"""
AEGISX - MISP / OpenCTI Threat Intelligence Pipeline (Tier 4)
Auto-ingestion, IOC normalization, confidence scoring, and enrichment
from MISP, OpenCTI, OTX, VirusTotal, Shodan, and AbuseIPDB.
"""
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

IOC_TYPE_MAP = {
    "ip-dst": "ip", "ip-src": "ip", "ip": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "filename": "file", "file": "file",
    "email": "email", "email-src": "email", "email-dst": "email",
    "mutex": "mutex", "registry": "registry",
    "cve": "cve", "vulnerability": "cve",
}


class ThreatIntelPipeline:
    """Multi-source threat intelligence ingestion and normalization."""

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._ioc_cache: Dict[str, Dict] = {}

    async def _client(self):
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    # ── MISP ────────────────────────────────────────────────────

    async def sync_misp(self) -> Dict[str, Any]:
        if not settings.MISP_URL or not settings.MISP_API_KEY:
            return {"source": "misp", "success": False, "error": "MISP not configured",
                    "indicators": 0}

        try:
            client = await self._client()
            resp = await client.post(
                f"{settings.MISP_URL}/attributes/restSearch",
                headers={
                    "Authorization": settings.MISP_API_KEY,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "returnFormat": "json",
                    "to_ids": True,
                    "last": "24h",
                    "limit": 500,
                    "includeEventTags": True,
                    "includeContext": True,
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()

            indicators = []
            raw = data.get("response", {}).get("Attribute", [])
            for attr in raw:
                ioc = self._normalize_misp_attribute(attr)
                if ioc:
                    indicators.append(ioc)

            return {
                "source": "misp",
                "success": True,
                "indicators": len(indicators),
                "data": indicators,
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.error("MISP sync failed: %s", e)
            return {"source": "misp", "success": False, "error": str(e), "indicators": 0}

    def _normalize_misp_attribute(self, attr: Dict) -> Optional[Dict]:
        misp_type = attr.get("type", "")
        ioc_type = IOC_TYPE_MAP.get(misp_type, "unknown")
        if ioc_type == "unknown":
            return None

        value = attr.get("value", "")
        if not value:
            return None

        ioc_id = hashlib.sha256(f"misp:{value}".encode()).hexdigest()[:16]

        tags = [t.get("name", "") for t in attr.get("Tag", [])]
        event = attr.get("Event", {})

        return {
            "ioc_id": ioc_id,
            "type": ioc_type,
            "value": value,
            "source": "misp",
            "event_id": event.get("id"),
            "event_info": event.get("info", ""),
            "threat_level": event.get("threat_level_id"),
            "confidence": self._misp_confidence(attr),
            "tags": tags,
            "comment": attr.get("comment", ""),
            "category": attr.get("category", ""),
            "to_ids": attr.get("to_ids", False),
            "first_seen": attr.get("first_seen") or event.get("date"),
            "last_seen": attr.get("last_seen") or attr.get("timestamp"),
            "tlp": self._extract_tlp(tags),
        }

    def _misp_confidence(self, attr: Dict) -> float:
        score = 0.5
        if attr.get("to_ids"):
            score += 0.2
        event = attr.get("Event", {})
        threat = event.get("threat_level_id")
        if threat == "1":
            score += 0.3
        elif threat == "2":
            score += 0.15
        tags = [t.get("name", "").lower() for t in attr.get("Tag", [])]
        for t in tags:
            if "apt" in t or "tlp:red" in t:
                score += 0.1
        return min(score, 1.0)

    def _extract_tlp(self, tags: List[str]) -> str:
        for tag in tags:
            tl = tag.lower()
            if "tlp:red" in tl:
                return "red"
            if "tlp:amber" in tl:
                return "amber"
            if "tlp:green" in tl:
                return "green"
            if "tlp:white" in tl:
                return "white"
        return "amber"

    # ── OpenCTI ──────────────────────────────────────────────────

    async def sync_opencti(self) -> Dict[str, Any]:
        if not settings.OPENCTI_URL or not settings.OPENCTI_API_KEY:
            return {"source": "opencti", "success": False, "error": "OpenCTI not configured",
                    "indicators": 0}

        try:
            client = await self._client()
            query = """
            query IndicatorsQuery($first: Int!) {
              indicators(first: $first, orderBy: created_at, orderMode: desc) {
                edges {
                  node {
                    id
                    pattern_type
                    pattern
                    name
                    description
                    valid_from
                    valid_until
                    confidence
                    indicator_types
                    objectLabel { edges { node { value } } }
                  }
                }
              }
            }
            """
            resp = await client.post(
                f"{settings.OPENCTI_URL}/graphql",
                headers={
                    "Authorization": f"Bearer {settings.OPENCTI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={"query": query, "variables": {"first": 500}},
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()

            indicators = []
            edges = (data.get("data", {}).get("indicators", {}).get("edges", []))
            for edge in edges:
                node = edge.get("node", {})
                ioc = self._normalize_opencti_indicator(node)
                if ioc:
                    indicators.append(ioc)

            return {
                "source": "opencti",
                "success": True,
                "indicators": len(indicators),
                "data": indicators,
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.error("OpenCTI sync failed: %s", e)
            return {"source": "opencti", "success": False, "error": str(e), "indicators": 0}

    def _normalize_opencti_indicator(self, node: Dict) -> Optional[Dict]:
        pattern = node.get("pattern", "")
        ioc_type = "unknown"
        value = ""

        if "[ipv4-addr:value = '" in pattern:
            ioc_type = "ip"
            value = pattern.split("[ipv4-addr:value = '")[1].split("'")[0]
        elif "[domain-name:value = '" in pattern:
            ioc_type = "domain"
            value = pattern.split("[domain-name:value = '")[1].split("'")[0]
        elif "[url:value = '" in pattern:
            ioc_type = "url"
            value = pattern.split("[url:value = '")[1].split("'")[0]
        elif "[file:hashes.'SHA-256' = '" in pattern:
            ioc_type = "hash"
            value = pattern.split("[file:hashes.'SHA-256' = '")[1].split("'")[0]
        elif "[file:hashes.MD5 = '" in pattern:
            ioc_type = "hash"
            value = pattern.split("[file:hashes.MD5 = '")[1].split("'")[0]
        else:
            return None

        labels = [
            e.get("node", {}).get("value", "")
            for e in node.get("objectLabel", {}).get("edges", [])
        ]

        return {
            "ioc_id": hashlib.sha256(f"opencti:{value}".encode()).hexdigest()[:16],
            "type": ioc_type,
            "value": value,
            "source": "opencti",
            "name": node.get("name", ""),
            "description": node.get("description", ""),
            "confidence": node.get("confidence", 50) / 100.0,
            "valid_from": node.get("valid_from"),
            "valid_until": node.get("valid_until"),
            "tags": labels,
            "pattern_type": node.get("pattern_type"),
        }

    # ── VirusTotal ───────────────────────────────────────────────

    async def lookup_virustotal(self, ioc_type: str, value: str) -> Optional[Dict]:
        if not settings.VIRUSTOTAL_API_KEY:
            return None

        endpoints = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
            "hash": f"https://www.virustotal.com/api/v3/files/{value}",
            "url": f"https://www.virustotal.com/api/v3/urls/{hashlib.sha256(value.encode()).hexdigest()}",
        }
        url = endpoints.get(ioc_type)
        if not url:
            return None

        try:
            client = await self._client()
            resp = await client.get(
                url, headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=15.0,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            malicious = stats.get("malicious", 0)

            return {
                "source": "virustotal",
                "malicious_votes": malicious,
                "total_votes": total,
                "score": malicious / total,
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "tags": attrs.get("tags", []),
            }
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", value, e)
            return None

    # ── AbuseIPDB ────────────────────────────────────────────────

    async def lookup_abuseipdb(self, ip: str) -> Optional[Dict]:
        if not settings.ABUSEIPDB_API_KEY:
            return None

        try:
            client = await self._client()
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15.0,
            )
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            return {
                "source": "abuseipdb",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
            }
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            return None

    # ── Shodan ───────────────────────────────────────────────────

    async def lookup_shodan(self, ip: str) -> Optional[Dict]:
        if not settings.SHODAN_API_KEY:
            return None

        try:
            client = await self._client()
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.SHODAN_API_KEY},
                timeout=15.0,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            return {
                "source": "shodan",
                "ports": data.get("ports", []),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "os": data.get("os"),
                "vulns": list(data.get("vulns", []))[:10],
                "last_update": data.get("last_update"),
            }
        except Exception as e:
            logger.warning("Shodan lookup failed for %s: %s", ip, e)
            return None

    # ── Full Enrichment ──────────────────────────────────────────

    async def enrich_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        cache_key = f"{ioc_type}:{value}"
        if cache_key in self._ioc_cache:
            return self._ioc_cache[cache_key]

        enrichments = {}

        if ioc_type in ("ip",):
            results = await asyncio.gather(
                self.lookup_virustotal("ip", value),
                self.lookup_abuseipdb(value),
                self.lookup_shodan(value),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, dict):
                    enrichments[r["source"]] = r

        elif ioc_type in ("domain",):
            vt = await self.lookup_virustotal("domain", value)
            if vt:
                enrichments["virustotal"] = vt

        elif ioc_type in ("hash",):
            vt = await self.lookup_virustotal("hash", value)
            if vt:
                enrichments["virustotal"] = vt

        elif ioc_type == "url":
            vt = await self.lookup_virustotal("url", value)
            if vt:
                enrichments["virustotal"] = vt

        scores = [e.get("score", e.get("abuse_confidence_score", 0) / 100) for e in enrichments.values()]
        composite_score = (sum(scores) / len(scores)) if scores else 0.0

        result = {
            "type": ioc_type,
            "value": value,
            "composite_score": round(composite_score, 4),
            "enrichments": enrichments,
            "is_malicious": composite_score > 0.3,
            "risk_level": "critical" if composite_score > 0.7 else
                          "high" if composite_score > 0.5 else
                          "medium" if composite_score > 0.3 else "low",
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }
        self._ioc_cache[cache_key] = result
        return result

    async def sync_all(self) -> List[Dict[str, Any]]:
        results = await asyncio.gather(
            self.sync_misp(),
            self.sync_opencti(),
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, dict)]

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


threat_intel_pipeline = ThreatIntelPipeline()
