"""
AEGIS - TimescaleDB Service
Hypertable management, retention policies, continuous aggregates for time-series events.
"""
import logging

from app.core.config import settings

logger = logging.getLogger("AEGIS.timescaledb")

TIMESCALE_SQL = """
-- Convert tables to hypertables
SELECT create_hypertable('events_raw', 'ingested_at', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');
SELECT create_hypertable('alerts_created', 'created_at', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');
SELECT create_hypertable('audit_trail', 'created_at', if_not_exists => TRUE, chunk_time_interval => INTERVAL '1 day');

-- Enable compression
ALTER TABLE events_raw SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id',
    timescaledb.compress_orderby = 'ingested_at DESC, event_id'
);
ALTER TABLE alerts_created SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id',
    timescaledb.compress_orderby = 'created_at DESC, alert_id'
);
ALTER TABLE audit_trail SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'tenant_id',
    timescaledb.compress_orderby = 'created_at DESC'
);

-- Compression policies (compress chunks older than 7 days)
SELECT add_compression_policy('events_raw', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('alerts_created', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('audit_trail', INTERVAL '7 days', if_not_exists => TRUE);

-- Retention policies
SELECT add_retention_policy('events_raw', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('alerts_created', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('audit_trail', INTERVAL '2555 days', if_not_exists => TRUE);

-- Continuous aggregates for dashboards
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', ingested_at) AS bucket,
    tenant_id,
    severity,
    event_type,
    source_type,
    COUNT(*) AS event_count,
    COUNT(DISTINCT source_ip) AS unique_sources,
    COUNT(DISTINCT hostname) AS unique_hosts
FROM events_raw
GROUP BY bucket, tenant_id, severity, event_type, source_type
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_hourly_summary',
    start_offset => INTERVAL '2 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE
);

CREATE MATERIALIZED VIEW IF NOT EXISTS alerts_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', created_at) AS bucket,
    tenant_id,
    severity,
    status,
    COUNT(*) AS alert_count,
    AVG(confidence) AS avg_confidence,
    COUNT(DISTINCT rule_id) AS unique_rules_triggered
FROM alerts_created
GROUP BY bucket, tenant_id, severity, status
WITH NO DATA;

SELECT add_continuous_aggregate_policy('alerts_hourly_summary',
    start_offset => INTERVAL '2 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_events_raw_tenant_ingested ON events_raw (tenant_id, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_severity ON events_raw (tenant_id, severity, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_hostname ON events_raw (tenant_id, hostname, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_source_ip ON events_raw (tenant_id, source_ip, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_tenant ON alerts_created (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_severity ON alerts_created (tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_rule ON alerts_created (tenant_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_audit_trail_tenant ON audit_trail (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_user ON audit_trail (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_audit_trail_action ON audit_trail (tenant_id, action, created_at DESC);
"""


async def initialize_timescaledb():
    """Create hypertables and policies on startup."""
    try:
        from app.core.database import async_session_factory
    except Exception:
        return

    if not async_session_factory:
        return

    try:
        async with async_session_factory() as session:
            for statement in TIMESCALE_SQL.split(";"):
                stmt = statement.strip()
                if not stmt or stmt.startswith("--"):
                    continue
                try:
                    await session.execute(statement)
                except Exception as e:
                    msg = str(e)
                    if any(kw in msg.lower() for kw in ("already", "exists", "duplicate", "extension")):
                        pass
                    else:
                        logger.warning(f"TimescaleDB SQL statement failed: {msg[:120]}")
            await session.commit()
        logger.info("TimescaleDB hypertables and policies configured")
    except Exception as e:
        logger.warning(f"TimescaleDB initialization skipped: {e}")
