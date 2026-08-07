-- AEGISX TimescaleDB Initialization
-- Executed on first container startup via /docker-entrypoint-initdb.d/

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

SELECT create_hypertable('events_raw', 'timestamp',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

SELECT create_hypertable('alerts_created', 'created_at',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

SELECT create_hypertable('audit_trail', 'created_at',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

SELECT add_compression_policy('events_raw', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('alerts_created', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('audit_trail', INTERVAL '7 days', if_not_exists => TRUE);

SELECT add_retention_policy('events_raw', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('alerts_created', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('audit_trail', INTERVAL '2555 days', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_events_raw_tenant_time ON events_raw (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_severity ON events_raw (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_tenant_time ON alerts_created (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_status ON alerts_created (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_severity ON alerts_created (tenant_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_tenant_action ON audit_trail (tenant_id, action, created_at DESC);

CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    tenant_id,
    time_bucket('1 hour', timestamp) AS bucket,
    event_type,
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT hostname) AS unique_hosts,
    COUNT(DISTINCT source_ip) AS unique_sources
FROM events_raw
GROUP BY tenant_id, bucket, event_type, severity;

CREATE MATERIALIZED VIEW IF NOT EXISTS alerts_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    tenant_id,
    time_bucket('1 hour', created_at) AS bucket,
    severity,
    COUNT(*) AS alert_count,
    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) AS resolved_count,
    AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))) AS avg_resolution_seconds
FROM alerts_created
GROUP BY tenant_id, bucket, severity;
