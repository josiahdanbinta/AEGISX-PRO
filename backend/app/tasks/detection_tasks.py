"""
AEGISX - Detection-related Celery tasks
Sigma rule evaluation, IOC matching, event correlation.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.celery_config import celery_app
from app.core.database import async_session_factory
from app.models import DetectionRule, Alert, IOCRule

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.tasks.detection_tasks.evaluate_all_rules",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def evaluate_all_rules(self):
    """Periodic task: evaluate all active Sigma rules across all tenants."""
    import asyncio

    async def _evaluate():
        from app.services.sigma_engine import SigmaEngine

        async with async_session_factory() as db:
            from sqlalchemy import distinct
            result = await db.execute(
                select(distinct(DetectionRule.tenant_id)).where(
                    DetectionRule.status == "active",
                    DetectionRule.rule_type == "sigma",
                )
            )
            tenant_ids = [str(row[0]) for row in result.all()]

            total_rules = 0
            total_alerts = 0

            for tid in tenant_ids:
                try:
                    engine = SigmaEngine(tenant_id=str(tid))
                    summary = await engine.run_all_rules()
                    total_rules += summary.get("rules_evaluated", 0)
                    total_alerts += summary.get("alerts_created", 0)
                except Exception as e:
                    logger.error("Failed to evaluate rules for tenant %s: %s", tid, e)

            await db.commit()
            logger.info(
                "evaluate_all_rules complete: %d tenants, %d rules, %d alerts",
                len(tenant_ids), total_rules, total_alerts,
            )
            return {
                "tenants_processed": len(tenant_ids),
                "rules_evaluated": total_rules,
                "alerts_created": total_alerts,
            }

    try:
        return asyncio.run(_evaluate())
    except Exception as exc:
        logger.error("evaluate_all_rules failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(
    name="app.tasks.detection_tasks.run_correlation",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
)
def run_correlation(self):
    """Periodic task: run event correlation to group alerts into incidents."""
    import asyncio

    async def _correlate():
        from app.services.correlation_engine import CorrelationEngine
        from sqlalchemy import distinct

        async with async_session_factory() as db:
            result = await db.execute(
                select(distinct(Alert.tenant_id)).where(
                    Alert.status.in_(["new", "acknowledged"]),
                    Alert.promoted_to_incident_id.is_(None),
                )
            )
            tenant_ids = [str(row[0]) for row in result.all()]

            total_processed = 0
            total_incidents = 0

            for tid in tenant_ids:
                try:
                    correlator = CorrelationEngine(tenant_id=str(tid), db=db)
                    summary = await correlator.run_correlation_job()
                    total_processed += summary.get("alerts_processed", 0)
                    total_incidents += summary.get("incidents_created", 0)
                except Exception as e:
                    logger.error("Correlation failed for tenant %s: %s", tid, e)

            await db.commit()
            logger.info(
                "run_correlation complete: %d tenants, %d alerts, %d incidents",
                len(tenant_ids), total_processed, total_incidents,
            )
            return {
                "tenants_processed": len(tenant_ids),
                "alerts_processed": total_processed,
                "incidents_created": total_incidents,
            }

    try:
        return asyncio.run(_correlate())
    except Exception as exc:
        logger.error("run_correlation failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)


@celery_app.task(name="app.tasks.detection_tasks.evaluate_rules")
def evaluate_rules(tenant_id: str):
    """Evaluate active detection rules for a specific tenant."""
    import asyncio

    async def _evaluate():
        from app.services.sigma_engine import SigmaEngine

        async with async_session_factory() as db:
            engine = SigmaEngine(tenant_id=tenant_id)
            summary = await engine.run_all_rules()
            await db.commit()
            return summary

    return asyncio.run(_evaluate())


@celery_app.task(name="app.tasks.detection_tasks.match_iocs")
def match_iocs(tenant_id: str, event_data: dict):
    """Match IOC rules against event data and create alerts if matched."""
    import asyncio
    import uuid

    async def _match():
        async with async_session_factory() as db:
            result = await db.execute(
                select(IOCRule).where(
                    IOCRule.tenant_id == uuid.UUID(tenant_id),
                    IOCRule.is_active == True,
                )
            )
            iocs = result.scalars().all()

            event_str = str(event_data).lower()
            matched_alerts = 0

            for ioc in iocs:
                if not ioc.value:
                    continue
                if ioc.value.lower() in event_str:
                    alert = Alert(
                        tenant_id=uuid.UUID(tenant_id),
                        title=f"IOC Match: {ioc.ioc_type}/{ioc.value}",
                        description=f"IOC {ioc.ioc_type}:{ioc.value} matched in event data. "
                                    f"Source: {ioc.source or 'unknown'}. {ioc.description or ''}",
                        severity=ioc.severity or "high",
                        status="new",
                        indicator_type=ioc.ioc_type,
                        indicator_value=ioc.value,
                        confidence=ioc.confidence or 1.0,
                        raw_event=event_data,
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                    )
                    db.add(alert)
                    matched_alerts += 1

            await db.commit()
            logger.info(
                "match_iocs: %d IOCs checked, %d alerts created for tenant %s",
                len(iocs), matched_alerts, tenant_id,
            )
            return {"iocs_checked": len(iocs), "alerts_created": matched_alerts}

    return asyncio.run(_match())
