"""
AEGISX - ClickHouse Analytics Service
Tier 5: Columnar analytics for pre-aggregated metrics, detection rule statistics,
and high-performance analytical queries.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

from app.core.config import settings

logger = logging.getLogger(__name__)

_RETRY_COUNT = 3
_RETRY_DELAY = 1.0


class ClickHouseService:
    """ClickHouse columnar analytics client for high-performance queries."""

    def __init__(self):
        self.host = getattr(settings, 'CLICKHOUSE_HOST', 'localhost')
        self.port = getattr(settings, 'CLICKHOUSE_PORT', 8123)
        self.user = getattr(settings, 'CLICKHOUSE_USER', 'aegisx')
        self.password = getattr(settings, 'CLICKHOUSE_PASSWORD', 'aegisx')
        self.database = getattr(settings, 'CLICKHOUSE_DB', 'aegisx')
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=5)
            self._session = aiohttp.ClientSession(
                auth=aiohttp.BasicAuth(self.user, self.password),
                timeout=timeout,
            )
        return self._session

    async def _query(self, sql: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        session = await self._get_session()
        payload = sql.encode() if not params else json.dumps({"query": sql, "params": params}).encode()
        url = f"{self.base_url}/?database={self.database}{'&param_' + '&param_'.join(f'{k}={v}' for k, v in (params or {}).items()) if params else ''}"

        last_exc = None
        for attempt in range(_RETRY_COUNT):
            try:
                async with session.post(url, data=sql.encode()) as resp:
                    text = await resp.text()
                    if resp.status != 200:
                        logger.error("ClickHouse query error (status %d): %s", resp.status, text[:200])
                        return []
                    if not text.strip():
                        return []
                    lines = text.strip().split('\n')
                    if len(lines) < 2:
                        return []
                    header = lines[0].split('\t')
                    results = []
                    for line in lines[1:]:
                        values = line.split('\t')
                        row = {}
                        for i, col in enumerate(header):
                            if i < len(values):
                                row[col] = values[i]
                            else:
                                row[col] = None
                        results.append(row)
                    return results
            except Exception as e:
                last_exc = e
                if attempt < _RETRY_COUNT - 1:
                    logger.warning("ClickHouse query retry %d/%d: %s", attempt + 1, _RETRY_COUNT, e)
                    await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
        logger.error("ClickHouse query failed after %d retries: %s", _RETRY_COUNT, last_exc)
        return []

    async def _execute(self, sql: str) -> bool:
        session = await self._get_session()
        url = f"{self.base_url}/?database={self.database}"

        last_exc = None
        for attempt in range(_RETRY_COUNT):
            try:
                async with session.post(url, data=sql.encode()) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        logger.error("ClickHouse execute error: %s", text[:200])
                        return False
                    return True
            except Exception as e:
                last_exc = e
                if attempt < _RETRY_COUNT - 1:
                    await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
        logger.error("ClickHouse execute failed after %d retries: %s", _RETRY_COUNT, last_exc)
        return False

    async def initialize(self):
        await self._execute("""
            CREATE TABLE IF NOT EXISTS event_metrics_hourly (
                tenant_id String,
                hour DateTime,
                event_type String,
                severity String,
                event_count UInt64,
                unique_hosts UInt64,
                unique_users UInt64,
                unique_sources UInt64,
                avg_confidence Float32
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(hour)
            ORDER BY (tenant_id, hour, event_type, severity)
            TTL hour + INTERVAL 90 DAY
            SETTINGS index_granularity = 8192
        """)
        await self._execute("""
            CREATE TABLE IF NOT EXISTS detection_metrics_hourly (
                tenant_id String,
                hour DateTime,
                rule_id String,
                rule_name String,
                alerts_triggered UInt64,
                true_positives UInt64,
                false_positives UInt64,
                avg_confidence Float32,
                avg_processing_time_ms Float32
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(hour)
            ORDER BY (tenant_id, hour, rule_id)
            TTL hour + INTERVAL 365 DAY
            SETTINGS index_granularity = 8192
        """)
        await self._execute("""
            CREATE TABLE IF NOT EXISTS alert_metrics_hourly (
                tenant_id String,
                hour DateTime,
                severity String,
                alert_count UInt64,
                acknowledged_count UInt64,
                resolved_count UInt64,
                avg_resolution_time_seconds Float32,
                unique_rules UInt64
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(hour)
            ORDER BY (tenant_id, hour, severity)
            TTL hour + INTERVAL 365 DAY
            SETTINGS index_granularity = 8192
        """)
        await self._execute("""
            CREATE TABLE IF NOT EXISTS analyst_query_log (
                tenant_id String,
                query_time DateTime,
                user_id String,
                query_type String,
                query_text String,
                execution_time_ms UInt32,
                result_count UInt32
            )
            ENGINE = MergeTree()
            PARTITION BY toYYYYMM(query_time)
            ORDER BY (tenant_id, query_time, user_id)
            TTL query_time + INTERVAL 30 DAY
            SETTINGS index_granularity = 8192
        """)
        logger.info("ClickHouse schema initialized")

    async def insert_event_metrics(self, metrics: List[Dict[str, Any]]) -> bool:
        if not metrics:
            return True
        values = []
        for m in metrics:
            tid = _escape_str(str(m.get('tenant_id', 'default')))
            hour = _escape_str(str(m.get('hour', '1970-01-01 00:00:00')))
            etype = _escape_str(str(m.get('event_type', 'generic')))
            sev = _escape_str(str(m.get('severity', 'info')))
            cnt = int(m.get('event_count', 0))
            hosts = int(m.get('unique_hosts', 0))
            users = int(m.get('unique_users', 0))
            sources = int(m.get('unique_sources', 0))
            conf = float(m.get('avg_confidence', 0.0))
            values.append(
                f"('{tid}','{hour}','{etype}','{sev}',{cnt},{hosts},{users},{sources},{conf})"
            )
        sql = f"INSERT INTO event_metrics_hourly VALUES {','.join(values)}"
        return await self._execute(sql)

    async def query_detection_stats(self, tenant_id: str, hours: int = 24) -> List[Dict]:
        tid = _escape_str(tenant_id)
        sql = f"""
            SELECT rule_id, rule_name,
                   sum(alerts_triggered) as total_alerts,
                   sum(true_positives) as tps,
                   sum(false_positives) as fps,
                   avg(avg_confidence) as avg_conf
            FROM detection_metrics_hourly
            WHERE tenant_id = '{tid}'
              AND hour >= now() - INTERVAL {hours} HOUR
            GROUP BY rule_id, rule_name
            ORDER BY total_alerts DESC
            LIMIT 100
        """
        return await self._query(sql)

    async def query_alert_volume(self, tenant_id: str, hours: int = 24) -> List[Dict]:
        tid = _escape_str(tenant_id)
        sql = f"""
            SELECT hour, severity, sum(alert_count) as count
            FROM alert_metrics_hourly
            WHERE tenant_id = '{tid}'
              AND hour >= now() - INTERVAL {hours} HOUR
            GROUP BY hour, severity
            ORDER BY hour
        """
        return await self._query(sql)

    async def query_platform_health(self) -> Dict[str, Any]:
        results = await self._query("""
            SELECT
                (SELECT count() FROM event_metrics_hourly
                 WHERE hour >= now() - INTERVAL 1 HOUR) as events_last_hour,
                (SELECT count() FROM detection_metrics_hourly
                 WHERE hour >= now() - INTERVAL 1 HOUR) as detections_last_hour,
                (SELECT count() FROM alert_metrics_hourly
                 WHERE hour >= now() - INTERVAL 24 HOUR) as alerts_last_24h,
                (SELECT avg(event_count) FROM event_metrics_hourly
                 WHERE hour >= now() - INTERVAL 24 HOUR) as avg_hourly_events
        """)
        return results[0] if results else {}

    async def log_analyst_query(self, tenant_id: str, user_id: str,
                                  query_type: str, query_text: str,
                                  execution_time_ms: int, result_count: int):
        tid = _escape_str(tenant_id)
        uid = _escape_str(user_id)
        qtype = _escape_str(query_type)
        qtext = _escape_str(query_text[:2000])
        sql = (
            f"INSERT INTO analyst_query_log VALUES "
            f"('{tid}',now(),'{uid}','{qtype}','{qtext}',{execution_time_ms},{result_count})"
        )
        await self._execute(sql)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


def _escape_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


clickhouse_service = ClickHouseService()
