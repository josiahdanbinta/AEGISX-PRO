"""
AEGISX - TimescaleDB Event Persistence Service
Writes raw events, alerts, and audit entries to TimescaleDB hypertables
alongside the existing PostgreSQL OLTP tables.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("aegisx.timescaledb.persistence")

_BATCH_SIZE = 100
_BATCH_TIMEOUT = 5.0
_MAX_QUEUE = 5000


class TimescaleEventWriter:
    """Writes events to TimescaleDB hypertables in batched transactions."""

    def __init__(self):
        self._events_batch: List[Dict[str, Any]] = []
        self._alerts_batch: List[Dict[str, Any]] = []
        self._audit_batch: List[Dict[str, Any]] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush())

    async def stop(self):
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._force_flush()

    async def write_event(self, event: Dict[str, Any]):
        if len(self._events_batch) >= _MAX_QUEUE:
            return
        self._events_batch.append(event)
        if len(self._events_batch) >= _BATCH_SIZE:
            await self._flush_events()

    async def write_alert(self, alert: Dict[str, Any]):
        if len(self._alerts_batch) >= _MAX_QUEUE:
            return
        self._alerts_batch.append(alert)
        if len(self._alerts_batch) >= _BATCH_SIZE:
            await self._flush_alerts()

    async def write_audit(self, audit: Dict[str, Any]):
        if len(self._audit_batch) >= _MAX_QUEUE:
            return
        self._audit_batch.append(audit)
        if len(self._audit_batch) >= _BATCH_SIZE:
            await self._flush_audit()

    async def _periodic_flush(self):
        while self._running:
            await asyncio.sleep(_BATCH_TIMEOUT)
            await self._flush_events()
            await self._flush_alerts()
            await self._flush_audit()

    async def _force_flush(self):
        await self._flush_events()
        await self._flush_alerts()
        await self._flush_audit()

    async def _flush_events(self):
        if not self._events_batch:
            return
        batch = self._events_batch[:]
        self._events_batch = []
        try:
            from sqlalchemy import text
            from app.core.database import async_session_factory

            async with async_session_factory() as session:
                values_sql = []
                params = {}
                for i, event in enumerate(batch):
                    prefix = f"e{i}_"
                    values_sql.append(
                        f"(:{prefix}id, :{prefix}tid, :{prefix}eid, :{prefix}src, "
                        f":{prefix}stype, :{prefix}etype, :{prefix}sev, :{prefix}ts, "
                        f":{prefix}sip, :{prefix}dip, :{prefix}host, :{prefix}user, "
                        f":{prefix}proc, :{prefix}raw, :{prefix}norm, :{prefix}tags, "
                        f":{prefix}aid, :{prefix}ing)"
                    )
                    params.update({
                        f"{prefix}id": str(uuid.uuid4()),
                        f"{prefix}tid": str(event.get("tenant_id", "default")),
                        f"{prefix}eid": str(event.get("event_id", uuid.uuid4())),
                        f"{prefix}src": event.get("source", "unknown"),
                        f"{prefix}stype": event.get("source_type", "generic"),
                        f"{prefix}etype": event.get("event_type", "generic"),
                        f"{prefix}sev": event.get("severity", "info"),
                        f"{prefix}ts": event.get("timestamp", datetime.now(timezone.utc)),
                        f"{prefix}sip": event.get("source_ip"),
                        f"{prefix}dip": event.get("destination_ip"),
                        f"{prefix}host": event.get("hostname"),
                        f"{prefix}user": event.get("username"),
                        f"{prefix}proc": event.get("process_name"),
                        f"{prefix}raw": json.dumps(event.get("data", event)),
                        f"{prefix}norm": "{}",
                        f"{prefix}tags": event.get("tags", []),
                        f"{prefix}aid": event.get("agent_id"),
                        f"{prefix}ing": datetime.now(timezone.utc),
                    })

                sql = (
                    "INSERT INTO events_raw (id, tenant_id, event_id, source, source_type, "
                    "event_type, severity, timestamp, source_ip, destination_ip, hostname, "
                    "username, process_name, raw_data, normalized, tags, agent_id, ingested_at) "
                    f"VALUES {','.join(values_sql)} "
                    "ON CONFLICT (event_id) DO NOTHING"
                )
                await session.execute(text(sql), params)
                await session.commit()
            logger.debug("Flushed %d events to TimescaleDB", len(batch))
        except Exception as e:
            logger.warning("TimescaleDB events flush failed (%d events): %s", len(batch), str(e)[:200])

    async def _flush_alerts(self):
        if not self._alerts_batch:
            return
        batch = self._alerts_batch[:]
        self._alerts_batch = []
        try:
            from sqlalchemy import text
            from app.core.database import async_session_factory

            async with async_session_factory() as session:
                values_sql = []
                params = {}
                for i, alert in enumerate(batch):
                    prefix = f"a{i}_"
                    values_sql.append(
                        f"(:{prefix}aid, :{prefix}tid, :{prefix}title, :{prefix}desc, "
                        f":{prefix}sev, :{prefix}status, :{prefix}conf, :{prefix}rid, "
                        f":{prefix}rname, :{prefix}mitre, :{prefix}ueba, :{prefix}corr, "
                        f":{prefix}sip, :{prefix}host, :{prefix}res, :{prefix}ack, "
                        f":{prefix}iid, :{prefix}enrich, :{prefix}ts)"
                    )
                    params.update({
                        f"{prefix}aid": str(alert.get("alert_id", uuid.uuid4())),
                        f"{prefix}tid": str(alert.get("tenant_id", "default")),
                        f"{prefix}title": alert.get("title", ""),
                        f"{prefix}desc": alert.get("description", ""),
                        f"{prefix}sev": alert.get("severity", "medium"),
                        f"{prefix}status": alert.get("status", "new"),
                        f"{prefix}conf": float(alert.get("confidence", 0.5)),
                        f"{prefix}rid": str(alert.get("rule_id", "")),
                        f"{prefix}rname": alert.get("rule_name", ""),
                        f"{prefix}mitre": alert.get("mitre_techniques", []),
                        f"{prefix}ueba": alert.get("ueba_score"),
                        f"{prefix}corr": alert.get("correlation_score"),
                        f"{prefix}sip": alert.get("source_ip"),
                        f"{prefix}host": alert.get("hostname"),
                        f"{prefix}res": alert.get("resolved_at"),
                        f"{prefix}ack": alert.get("acknowledged_by"),
                        f"{prefix}iid": alert.get("incident_id"),
                        f"{prefix}enrich": "{}",
                        f"{prefix}ts": alert.get("created_at", datetime.now(timezone.utc)),
                    })

                sql = (
                    "INSERT INTO alerts_created (alert_id, tenant_id, title, description, "
                    "severity, status, confidence, rule_id, rule_name, mitre_techniques, "
                    "ueba_score, correlation_score, source_ip, hostname, resolved_at, "
                    "acknowledged_by, incident_id, enrichment, created_at) "
                    f"VALUES {','.join(values_sql)} "
                    "ON CONFLICT (alert_id) DO UPDATE SET status=EXCLUDED.status, "
                    "confidence=EXCLUDED.confidence, resolved_at=COALESCE(EXCLUDED.resolved_at, alerts_created.resolved_at)"
                )
                await session.execute(text(sql), params)
                await session.commit()
            logger.debug("Flushed %d alerts to TimescaleDB", len(batch))
        except Exception as e:
            logger.warning("TimescaleDB alerts flush failed (%d alerts): %s", len(batch), str(e)[:200])

    async def _flush_audit(self):
        if not self._audit_batch:
            return
        batch = self._audit_batch[:]
        self._audit_batch = []
        try:
            from sqlalchemy import text
            from app.core.database import async_session_factory

            async with async_session_factory() as session:
                values_sql = []
                params = {}
                for i, entry in enumerate(batch):
                    prefix = f"u{i}_"
                    values_sql.append(
                        f"(:{prefix}tid, :{prefix}uid, :{prefix}act, :{prefix}rtype, "
                        f":{prefix}rid, :{prefix}det, :{prefix}ip, :{prefix}agent, "
                        f":{prefix}corr, :{prefix}success, :{prefix}ts)"
                    )
                    params.update({
                        f"{prefix}tid": str(entry.get("tenant_id", "default")),
                        f"{prefix}uid": entry.get("user_id"),
                        f"{prefix}act": entry.get("action", "unknown"),
                        f"{prefix}rtype": entry.get("resource_type", "unknown"),
                        f"{prefix}rid": str(entry.get("resource_id", "")),
                        f"{prefix}det": json.dumps(entry.get("details", {})),
                        f"{prefix}ip": entry.get("ip_address"),
                        f"{prefix}agent": entry.get("user_agent"),
                        f"{prefix}corr": entry.get("correlation_id"),
                        f"{prefix}success": entry.get("success", True),
                        f"{prefix}ts": entry.get("created_at", datetime.now(timezone.utc)),
                    })

                sql = (
                    "INSERT INTO audit_trail (tenant_id, user_id, action, resource_type, "
                    "resource_id, details, ip_address, user_agent, correlation_id, success, created_at) "
                    f"VALUES {','.join(values_sql)}"
                )
                await session.execute(text(sql), params)
                await session.commit()
            logger.debug("Flushed %d audit entries to TimescaleDB", len(batch))
        except Exception as e:
            logger.warning("TimescaleDB audit flush failed (%d entries): %s", len(batch), str(e)[:200])


import json  # noqa: E402

tsdb_writer = TimescaleEventWriter()
