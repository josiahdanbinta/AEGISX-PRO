"""
AEGIS - Metrics Instrumentation
Wires Prometheus counters/histograms into actual code paths.
Keep this module self-contained â€” no circular imports.
"""
import time
import functools
from contextlib import contextmanager
from typing import Optional

from app.services.metrics import (
    events_ingested_total,
    events_duplicated_total,
    alerts_created_total,
    alert_generation_duration_seconds,
    alerts_open,
    alerts_assigned_total,
    alert_resolution_time_seconds,
    detection_rule_executions_total,
    detection_rule_duration_seconds,
    stream_events_processed_total,
    stream_duplicates_total,
    stream_alerts_generated_total,
    stream_errors_total,
    ueba_score,
    storage_bytes_used,
    storage_bytes_quota,
    db_connections_active,
)


# â”€â”€ Database connections polling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async def poll_db_connections():
    try:
        from app.core.database import engine
        pool = engine.pool
        if hasattr(pool, 'size'):
            db_connections_active.set(pool.checkedin() + pool.checkedout())
    except Exception:
        pass


# â”€â”€ Event ingestion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def record_event_ingested(tenant_id: str = "default", source_type: str = "generic",
                           duplicated: bool = False):
    events_ingested_total.labels(tenant_id=tenant_id, source_type=source_type).inc()
    if duplicated:
        events_duplicated_total.labels(tenant_id=tenant_id).inc()


# â”€â”€ Alert creation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def record_alert_created(tenant_id: str, severity: str, rule_name: str,
                          duration_s: float = 0):
    alerts_created_total.labels(tenant_id=tenant_id, severity=severity,
                                 rule_name=rule_name).inc()
    if duration_s:
        alert_generation_duration_seconds.labels(rule_name=rule_name).observe(duration_s)


def record_alert_resolved(tenant_id: str, severity: str, resolution_time_s: float):
    alert_resolution_time_seconds.labels(tenant_id=tenant_id,
                                          severity=severity).observe(resolution_time_s)


def record_alert_assigned(tenant_id: str, user_id: str):
    alerts_assigned_total.labels(tenant_id=tenant_id, user_id=user_id).inc()


def set_open_alerts(tenant_id: str, severity: str, count: int):
    alerts_open.labels(tenant_id=tenant_id, severity=severity).set(count)


# â”€â”€ Detection rules â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@contextmanager
def track_detection_rule(tenant_id: str, rule_name: str):
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        detection_rule_executions_total.labels(tenant_id=tenant_id,
                                                rule_name=rule_name).inc()
        detection_rule_duration_seconds.labels(rule_name=rule_name).observe(elapsed)


# â”€â”€ Stream processing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def record_stream_event_processed(tenant_id: str):
    stream_events_processed_total.labels(tenant_id=tenant_id).inc()


def record_stream_duplicate(tenant_id: str):
    stream_duplicates_total.labels(tenant_id=tenant_id).inc()


def record_stream_alert_generated(tenant_id: str):
    stream_alerts_generated_total.labels(tenant_id=tenant_id).inc()


def record_stream_error(error_type: str):
    stream_errors_total.labels(error_type=error_type).inc()


# â”€â”€ UEBA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def record_ueba_score(tenant_id: str, entity_type: str, score: float):
    ueba_score.labels(tenant_id=tenant_id, entity_type=entity_type).observe(score)


# â”€â”€ Storage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def set_storage_metrics(tenant_id: str, storage_type: str, bytes_used: int,
                         quota_bytes: int = 0):
    storage_bytes_used.labels(tenant_id=tenant_id, storage_type=storage_type).set(bytes_used)
    if quota_bytes:
        storage_bytes_quota.labels(tenant_id=tenant_id).set(quota_bytes)
