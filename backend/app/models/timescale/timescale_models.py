"""
AEGIS - TimescaleDB Hypertable Models
Tier 5: Raw events, parsed alerts, audit trail as hypertables with retention policies.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Float, Integer, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, ARRAY, INET

from app.core.database import Base


class EventRaw(Base):
    __tablename__ = "events_raw"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    event_id = Column(String(64), unique=True, nullable=False)
    source = Column(String(128))
    source_type = Column(String(64))
    event_type = Column(String(64))
    severity = Column(String(16), default="info", index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source_ip = Column(INET)
    destination_ip = Column(INET)
    hostname = Column(String(256))
    username = Column(String(256))
    process_name = Column(String(512))
    raw_data = Column(JSON)
    normalized = Column(JSON)
    tags = Column(ARRAY(String))
    agent_id = Column(String(64))
    ingested_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    def __repr__(self):
        return f"<EventRaw {self.event_id} [{self.severity}]>"


class AlertCreated(Base):
    __tablename__ = "alerts_created"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    alert_id = Column(String(64), unique=True, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(16), nullable=False, index=True)
    status = Column(String(32), default="new", index=True)
    confidence = Column(Float, default=0.5)
    rule_id = Column(String(64))
    rule_name = Column(String(256))
    source_ip = Column(INET)
    destination_ip = Column(INET)
    hostname = Column(String(256))
    username = Column(String(256))
    mitre_techniques = Column(ARRAY(String))
    correlation_score = Column(Float)
    ueba_score = Column(Float)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True))
    resolution_time_seconds = Column(Integer)
    acknowledged_by = Column(UUID(as_uuid=True))
    incident_id = Column(UUID(as_uuid=True))
    raw_event_id = Column(String(64))
    enrichment = Column(JSON)

    def __repr__(self):
        return f"<AlertCreated {self.alert_id} [{self.severity}] {self.status}>"


class AuditTrail(Base):
    __tablename__ = "audit_trail"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True))
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64))
    resource_id = Column(String(64))
    details = Column(JSON)
    ip_address = Column(INET)
    user_agent = Column(String(512))
    correlation_id = Column(String(64))
    success = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<AuditTrail {self.action} by {self.user_id}>"


# Hypertable creation SQL (executed via setup script)
TIMESCALE_SQL = """
-- Enable TimescaleDB extension (if not already)
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Convert events_raw to hypertable
SELECT create_hypertable('events_raw', 'timestamp',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

-- Convert alerts_created to hypertable
SELECT create_hypertable('alerts_created', 'created_at',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

-- Convert audit_trail to hypertable
SELECT create_hypertable('audit_trail', 'created_at',
    if_not_exists => TRUE,
    chunk_time_interval => INTERVAL '1 day'
);

-- Compression policies (after 7 days)
SELECT add_compression_policy('events_raw', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('alerts_created', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_compression_policy('audit_trail', INTERVAL '7 days', if_not_exists => TRUE);

-- Retention policies: raw events 90 days hot, alerts 365 days, audit 7 years
SELECT add_retention_policy('events_raw', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('alerts_created', INTERVAL '365 days', if_not_exists => TRUE);
SELECT add_retention_policy('audit_trail', INTERVAL '2555 days', if_not_exists => TRUE);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_events_raw_tenant_time ON events_raw (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_severity ON events_raw (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_hostname ON events_raw (hostname, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_source_ip ON events_raw (source_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_tenant_time ON alerts_created (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_status ON alerts_created (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_severity ON alerts_created (tenant_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_tenant_action ON audit_trail (tenant_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_user ON audit_trail (tenant_id, user_id, created_at DESC);

-- Continuous aggregates for dashboard queries
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    tenant_id,
    time_bucket('1 hour', timestamp) AS bucket,
    event_type,
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT hostname) AS unique_hosts,
    COUNT(DISTINCT username) AS unique_users,
    COUNT(DISTINCT source_ip) AS unique_sources
FROM events_raw
GROUP BY tenant_id, bucket, event_type, severity
WITH NO DATA;

SELECT add_continuous_aggregate_policy('events_hourly_summary',
    start_offset => INTERVAL '2 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE
);

CREATE MATERIALIZED VIEW IF NOT EXISTS alerts_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    tenant_id,
    time_bucket('1 hour', created_at) AS bucket,
    severity,
    COUNT(*) AS alert_count,
    COUNT(*) FILTER (WHERE status = 'acknowledged') AS acknowledged_count,
    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) AS resolved_count,
    AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))) AS avg_resolution_seconds
FROM alerts_created
GROUP BY tenant_id, bucket, severity
WITH NO DATA;

SELECT add_continuous_aggregate_policy('alerts_hourly_summary',
    start_offset => INTERVAL '2 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE
);
"""
