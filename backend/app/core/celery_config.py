"""
AEGISX - Celery Task Queue Configuration
"""
from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "aegisx",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.agent_tasks",
        "app.tasks.detection_tasks",
        "app.tasks.notification_tasks",
        "app.tasks.report_tasks",
        "app.tasks.compliance_tasks",
        "app.tasks.vulnerability_tasks",
        "app.tasks.threat_intel_tasks",
        "app.tasks.cleanup_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3000,
    worker_max_tasks_per_child=1000,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    result_expires=86400,
    broker_connection_retry_on_startup=True,
)

celery_app.conf.task_routes = {
    "app.tasks.agent_tasks.*": {"queue": "agent"},
    "app.tasks.detection_tasks.*": {"queue": "detection"},
    "app.tasks.notification_tasks.*": {"queue": "notification"},
    "app.tasks.report_tasks.*": {"queue": "report"},
    "app.tasks.compliance_tasks.*": {"queue": "compliance"},
    "app.tasks.vulnerability_tasks.*": {"queue": "vulnerability"},
    "app.tasks.threat_intel_tasks.*": {"queue": "threat_intel"},
    "app.tasks.cleanup_tasks.*": {"queue": "cleanup"},
}

celery_app.conf.beat_schedule = {
    "agent-heartbeat-check": {
        "task": "app.tasks.agent_tasks.check_agent_heartbeats",
        "schedule": 60.0,
    },
    "sigma-rule-evaluation": {
        "task": "app.tasks.detection_tasks.evaluate_all_rules",
        "schedule": 300.0,
    },
    "event-correlation": {
        "task": "app.tasks.detection_tasks.run_correlation",
        "schedule": 600.0,
    },
    "vulnerability-scan-schedule": {
        "task": "app.tasks.vulnerability_tasks.schedule_scans",
        "schedule": 3600.0,
    },
    "threat-intel-refresh": {
        "task": "app.tasks.threat_intel_tasks.refresh_feeds",
        "schedule": 1800.0,
    },
    "report-schedule": {
        "task": "app.tasks.report_tasks.process_scheduled_reports",
        "schedule": 300.0,
    },
    "log-cleanup": {
        "task": "app.tasks.cleanup_tasks.cleanup_old_logs",
        "schedule": 86400.0,
    },
    "token-cleanup": {
        "task": "app.tasks.cleanup_tasks.cleanup_expired_tokens",
        "schedule": 3600.0,
    },
    "cold-archive-events": {
        "task": "app.tasks.cleanup_tasks.cold_archive_events",
        "schedule": 86400.0,
    },
    "flush-tsdb-buffers": {
        "task": "app.tasks.cleanup_tasks.flush_tsdb_buffers",
        "schedule": 30.0,
    },
}
