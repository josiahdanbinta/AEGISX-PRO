"""
AEGISX - Detection-related Celery tasks
"""
from sqlalchemy import select

from app.core.celery_config import celery_app
from app.core.database import async_session_factory
from app.models import DetectionRule, Alert, IOCRule, Asset


@celery_app.task(name="app.tasks.detection_tasks.evaluate_rules")
def evaluate_rules(tenant_id: str):
    """Evaluate active detection rules against incoming events."""
    import asyncio

    async def _evaluate():
        async with async_session_factory() as db:
            rules = (await db.execute(
                select(DetectionRule).where(
                    DetectionRule.tenant_id == tenant_id,
                    DetectionRule.status == "active",
                )
            )).scalars().all()

            for rule in rules:
                # TODO: Execute rule logic (Sigma/YARA matching, IOC matching, etc.)
                # For now, just increment alert_count
                pass

            await db.commit()

    asyncio.run(_evaluate())


@celery_app.task(name="app.tasks.detection_tasks.match_iocs")
def match_iocs(tenant_id: str, event_data: dict):
    """Match IOC rules against event data."""
    import asyncio

    async def _match():
        async with async_session_factory() as db:
            iocs = (await db.execute(
                select(IOCRule).where(
                    IOCRule.tenant_id == tenant_id,
                    IOCRule.is_active == True,
                )
            )).scalars().all()

            for ioc in iocs:
                # TODO: Match ioc.value against event_data
                # If match, create Alert
                pass

    asyncio.run(_match())
