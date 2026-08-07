"""
AEGIS - Kafka Stream Processor (Tier 3)
Stateful, low-latency event processing pipeline:
1. Event Normalization
2. Enrichment (TI lookups, asset metadata)
3. Deduplication & Aggregation
4. Window Operations (5min, 1hr for baselines)
"""
import asyncio
import json
import logging
import signal
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.services.dedup_service import dedup_service
from app.services.ueba_scorer import ueba_scorer

try:
    from app.services.kafka_messaging import kafka_service
    HAS_KAFKA = True
except ImportError:
    kafka_service = None
    HAS_KAFKA = False

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, "INFO"),
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}',
)
logger = logging.getLogger("stream-processor")


class WindowAggregator:
    """Sliding window aggregation for 5-minute and 1-hour baselines."""

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._windows: Dict[str, List[Dict]] = defaultdict(list)
        self._last_cleanup = datetime.now(timezone.utc)

    def add(self, key: str, event: Dict[str, Any]):
        self._windows[key].append(event)
        self._cleanup()

    def get_aggregates(self, key: str) -> Dict[str, Any]:
        events = self._windows.get(key, [])
        if not events:
            return {"count": 0}

        severities = defaultdict(int)
        event_types = defaultdict(int)
        source_ips: set = set()
        hostnames: set = set()
        usernames: set = set()
        total_confidence = 0.0

        for e in events:
            sev = e.get("severity", "info")
            severities[sev] += 1
            event_types[e.get("event_type", "unknown")] += 1
            if e.get("source_ip"):
                source_ips.add(e["source_ip"])
            if e.get("hostname"):
                hostnames.add(e["hostname"])
            if e.get("username"):
                usernames.add(e["username"])
            total_confidence += float(e.get("confidence", 0.5))

        count = len(events)
        return {
            "count": count,
            "window_seconds": self.window_seconds,
            "severity_distribution": dict(severities),
            "event_type_distribution": dict(event_types),
            "unique_source_ips": len(source_ips),
            "unique_hostnames": len(hostnames),
            "unique_usernames": len(usernames),
            "avg_confidence": round(total_confidence / count, 3) if count > 0 else 0,
            "first_event": events[0].get("timestamp"),
            "last_event": events[-1].get("timestamp"),
        }

    def _cleanup(self):
        now = datetime.now(timezone.utc)
        if (now - self._last_cleanup).total_seconds() < 60:
            return
        cutoff = now.timestamp() - (self.window_seconds * 2)
        for key in list(self._windows.keys()):
            self._windows[key] = [
                e for e in self._windows[key]
                if e.get("timestamp", 0) > cutoff
            ]
            if not self._windows[key]:
                del self._windows[key]
        self._last_cleanup = now


class EventNormalizer:
    """Normalize raw events into standardized ECS-like event types."""

    EVENT_TYPE_MAP = {
        "process_create": ["Sysmon 1", "EventID 4688", "process_creation", "execve"],
        "network_connect": ["Sysmon 3", "EventID 5156", "network_connection", "connect"],
        "file_create": ["Sysmon 11", "file_create", "FileCreateEvent"],
        "registry_event": ["Sysmon 12", "Sysmon 13", "registry_set", "RegSetValue"],
        "dns_query": ["Sysmon 22", "dns_query", "EventID 22"],
        "authentication": ["EventID 4624", "EventID 4625", "login", "logon"],
        "process_access": ["Sysmon 10", "process_access", "OpenProcess"],
        "wmi_event": ["Sysmon 19", "WmiEvent", "wmi"],
        "powershell": ["Sysmon 7", "EventID 4104", "PowerShell", "ScriptBlock"],
        "service_event": ["Sysmon 6", "EventID 7045", "service_install"],
    }

    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        raw_str = event.get("raw_data", "")
        raw_data = {}
        if isinstance(raw_str, str):
            try:
                raw_data = json.loads(raw_str)
            except (json.JSONDecodeError, TypeError):
                raw_data = {"message": raw_str}
        elif isinstance(raw_str, dict):
            raw_data = raw_str

        event_type = self._classify_event(raw_data)
        fields = self._extract_fields(raw_data)

        return {
            "event_id": str(uuid.uuid4()),
            "raw_event_id": event.get("event_id", ""),
            "tenant_id": event.get("tenant_id", "default"),
            "timestamp": event.get("timestamp", int(datetime.now(timezone.utc).timestamp() * 1000)),
            "event_type": event_type,
            "severity": self._map_severity(raw_data, event_type),
            "source_ip": fields.get("source_ip"),
            "destination_ip": fields.get("destination_ip"),
            "hostname": fields.get("hostname"),
            "username": fields.get("username"),
            "process_name": fields.get("process_name"),
            "source": event.get("source", "unknown"),
            "source_type": event.get("source_type", "generic"),
            "normalized_data": raw_data,
            "tags": self._generate_tags(raw_data, event_type),
        }

    def _classify_event(self, raw: Dict[str, Any]) -> str:
        data_str = json.dumps(raw).lower() if raw else ""
        for event_type, patterns in self.EVENT_TYPE_MAP.items():
            for pattern in patterns:
                if pattern.lower() in data_str:
                    return event_type
        if "login" in data_str or "logon" in data_str:
            return "authentication"
        if "process" in data_str:
            return "process_create"
        if "network" in data_str or "connect" in data_str:
            return "network_connect"
        return "generic"

    def _extract_fields(self, data: Dict[str, Any]) -> Dict[str, Optional[str]]:
        if not isinstance(data, dict):
            return {}

        fields = {}
        for f in ["source_ip", "src_ip", "SourceIp", "src", "client_ip"]:
            if data.get(f):
                fields["source_ip"] = str(data[f])
                break
        for f in ["destination_ip", "dest_ip", "dst_ip", "DestinationIp", "dst"]:
            if data.get(f):
                fields["destination_ip"] = str(data[f])
                break
        for f in ["host", "hostname", "Hostname", "ComputerName", "computer_name",
                   "agent.hostname", "beat.hostname"]:
            if data.get(f):
                fields["hostname"] = str(data[f])
                break
        for f in ["username", "user", "UserName", "user.name", "SubjectUserName",
                   "TargetUserName"]:
            if data.get(f):
                fields["username"] = str(data[f])
                break
        for f in ["process_name", "process.name", "Image", "NewProcessName"]:
            if data.get(f):
                fields["process_name"] = str(data[f])
                break
        return fields

    def _map_severity(self, data: Dict[str, Any], event_type: str) -> str:
        data_str = json.dumps(data).lower() if data else ""
        high_risk_types = ["process_create", "service_event", "powershell", "wmi_event"]
        critical_keywords = ["mimikatz", "ransomware", "meterpreter", "cobalt strike",
                             "empire", "sharp", "seatbelt", "kerberoast"]
        high_keywords = ["suspicious", "anomalous", "encodedcommand", "hidden"]

        if event_type in high_risk_types:
            if any(kw in data_str for kw in critical_keywords):
                return "critical"
            if any(kw in data_str for kw in high_keywords):
                return "high"
            return "medium"
        if event_type == "authentication":
            if "4625" in data_str:
                return "medium"
            if "anonymous" in data_str:
                return "high"
        return "low"

    def _generate_tags(self, data: Dict[str, Any], event_type: str) -> List[str]:
        tags = [event_type]
        data_str = json.dumps(data).lower() if data else ""
        if "powershell" in data_str:
            tags.extend(["windows", "scripting"])
        if any(kw in data_str for kw in ["mimikatz", "meterpreter", "cobalt"]):
            tags.append("credential_access")
        if any(kw in data_str for kw in ["schtasks", "at.exe", "wmi"]):
            tags.append("persistence")
        if any(kw in data_str for kw in ["192.168.", "10.", "172.16."]):
            tags.append("internal_ip")
        return tags


class Enricher:
    """Enrich events with threat intelligence, asset metadata, and context."""

    def __init__(self):
        self._asset_cache: Dict[str, Dict] = {}
        self._ti_cache: Dict[str, Dict] = {}

    async def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        source_ip = event.get("source_ip")
        if source_ip:
            ti_result = await self._lookup_threat_intel(source_ip)
            if ti_result:
                enrichment = event.get("enrichment", {})
                enrichment["threat_intel"] = ti_result
                event["enrichment"] = enrichment
                tags = event.get("tags", [])
                if ti_result.get("is_malicious"):
                    tags.append("threat_intel_match")
                    if ti_result.get("score", 0) > 80:
                        event["severity"] = "critical"
                    elif ti_result.get("score", 0) > 60:
                        event["severity"] = "high"
                event["tags"] = tags

        event["enriched_at"] = int(datetime.now(timezone.utc).timestamp() * 1000)
        return event

    async def _lookup_threat_intel(self, ip: str) -> Optional[Dict]:
        if ip in self._ti_cache:
            return self._ti_cache[ip]
        result = await self._check_known_malicious(ip)
        self._ti_cache[ip] = result
        return result

    async def _check_known_malicious(self, ip: str) -> Dict:
        private_ranges = ip.startswith(("10.", "172.16", "172.17", "172.18",
                                         "172.19", "172.20", "172.21", "172.22",
                                         "172.23", "172.24", "172.25", "172.26",
                                         "172.27", "172.28", "172.29", "172.30",
                                         "172.31", "192.168", "127.", "0."))
        if private_ranges:
            return {"is_malicious": False, "score": 0, "tags": ["private_ip"]}
        return {"is_malicious": False, "score": 0, "tags": []}


class StreamProcessor:
    """Main stream processing pipeline consuming from Kafka and producing alerts."""

    def __init__(self):
        self.normalizer = EventNormalizer()
        self.enricher = Enricher()
        self.window_5min = WindowAggregator(300)
        self.window_1hr = WindowAggregator(3600)
        self._running = False
        self._stats = {"processed": 0, "duplicates": 0, "alerts": 0, "errors": 0}

    async def start(self):
        logger.info("Starting stream processor...")
        await kafka_service.initialize()
        self._running = True

        consumers = [
            self._process_raw_events(),
            self._process_normalized_events(),
            self._stats_reporter(),
        ]
        tasks = [asyncio.create_task(c) for c in consumers]
        logger.info("Stream processor running â€” events.raw â†’ events.normalized â†’ alerts")
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Stream processor shutting down...")
            self._running = False

    async def _process_raw_events(self):
        async for msg in kafka_service.consume_events(
            ["events.raw"], group_id="AEGIS-stream-processor"
        ):
            try:
                value = msg["value"]
                is_dup, fp = await dedup_service.is_event_duplicate(
                    value.get("tenant_id", "default"), value
                )
                if is_dup:
                    self._stats["duplicates"] += 1
                    continue

                normalized = self.normalizer.normalize(value)
                enriched = await self.enricher.enrich(normalized)

                await kafka_service.produce_normalized_event(enriched)

                tenant_key = enriched.get("tenant_id", "")
                self.window_5min.add(tenant_key, enriched)
                self.window_1hr.add(tenant_key, enriched)

                await self._check_baselines(tenant_key, enriched)
                self._stats["processed"] += 1

            except Exception as e:
                self._stats["errors"] += 1
                logger.error("Raw event processing error: %s", e, exc_info=True)

    async def _process_normalized_events(self):
        async for msg in kafka_service.consume_events(
            ["events.normalized"], group_id="AEGIS-stream-enricher"
        ):
            try:
                value = msg["value"]
                event_type = value.get("event_type", "generic")
                severity = value.get("severity", "low")

                if severity in ("critical", "high") or event_type in (
                    "process_create", "powershell", "wmi_event", "service_event"
                ):
                    tenant_id = value.get("tenant_id", "default")
                    ueba_result = await ueba_scorer.score_event(tenant_id, value)
                    if ueba_result.get("anomaly_score", 0) > 0.7:
                        alert = {
                            "alert_id": str(uuid.uuid4()),
                            "tenant_id": tenant_id,
                            "rule_id": "ueba-anomaly",
                            "rule_name": f"UEBA Anomaly: {event_type}",
                            "severity": "high" if ueba_result["anomaly_score"] > 0.85 else severity,
                            "confidence": round(ueba_result["anomaly_score"], 2),
                            "title": f"UEBA Anomaly detected: {event_type} (deviation: {ueba_result.get('baseline_deviation', 0):.1f})",
                            "description": json.dumps(ueba_result.get("details", {})),
                            "source_ip": value.get("source_ip"),
                            "hostname": value.get("hostname"),
                            "mitre_techniques": ueba_result.get("mitre_techniques", []),
                            "correlation_score": ueba_result.get("anomaly_score"),
                            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
                        }
                        await kafka_service.produce_alert(alert)
                        self._stats["alerts"] += 1
                        logger.info("UEBA alert: %s (score=%.2f)", alert["title"],
                                    ueba_result["anomaly_score"])

            except Exception as e:
                self._stats["errors"] += 1
                logger.error("Normalized event error: %s", e, exc_info=True)

    async def _check_baselines(self, tenant_key: str, event: Dict[str, Any]):
        agg_5 = self.window_5min.get_aggregates(tenant_key)
        if agg_5["count"] > 50:
            event_type = event.get("event_type", "generic")
            spike_ratio = agg_5["event_type_distribution"].get(event_type, 0) / max(agg_5["count"], 1)
            if spike_ratio > 0.5 and agg_5["unique_source_ips"] > 10:
                logger.warning("Spike: %d %s events in 5min (%d sources)",
                               agg_5["count"], event_type, agg_5["unique_source_ips"])

    async def _stats_reporter(self):
        while self._running:
            await asyncio.sleep(30)
            total = self._stats["processed"]
            if total > 0:
                logger.info("Stats: %d processed, %d dupes, %d alerts, %d errors",
                            total, self._stats["duplicates"],
                            self._stats["alerts"], self._stats["errors"])

    def shutdown(self):
        self._running = False
        kafka_service.flush(5.0)


async def main():
    processor = StreamProcessor()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: processor.shutdown())
    await processor.start()


if __name__ == "__main__":
    asyncio.run(main())
