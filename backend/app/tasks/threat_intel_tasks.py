"""
AEGIS - Threat Intelligence Celery Tasks
Sync MISP/OpenCTI feeds, enrich IOCs, and refresh indicators.
"""
import asyncio
import logging
from typing import Any, Dict

from app.core.celery_config import celery_app
from app.core.database import async_session_factory
from app.models import ThreatIndicator, ThreatFeed
from sqlalchemy import select, update

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.threat_intel_tasks.refresh_feeds", queue="threat_intel")
def refresh_feeds():
    """Sync all configured threat intelligence feeds (MISP, OpenCTI, etc.)."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    loop.run_until_complete(_refresh_feeds_async())
    return {"status": "completed"}


async def _refresh_feeds_async():
    from app.services.threat_intel_pipeline import threat_intel_pipeline

    results = await threat_intel_pipeline.sync_all()

    async with async_session_factory() as db:
        for result in results:
            if not result.get("success"):
                continue

            source = result["source"]
            data = result.get("data", [])

            for ioc in data:
                try:
                    existing = await db.execute(
                        select(ThreatIndicator).where(
                            ThreatIndicator.type == ioc["type"],
                            ThreatIndicator.value == ioc["value"],
                        )
                    )
                    existing_ioc = existing.scalar_one_or_none()

                    if existing_ioc:
                        existing_ioc.last_seen = ioc.get("last_seen")
                        existing_ioc.confidence = ioc.get("confidence", 0.5)
                        if ioc.get("tags"):
                            existing_ioc.tags = list(set(
                                (existing_ioc.tags or []) + ioc["tags"]
                            ))
                    else:
                        ti = ThreatIndicator(
                            type=ioc["type"],
                            value=ioc["value"],
                            confidence=ioc.get("confidence", 0.5),
                            source=source,
                            description=ioc.get("event_info") or ioc.get("description", ""),
                            tags=ioc.get("tags", []) + [f"source:{source}"],
                            tlp=ioc.get("tlp", "amber"),
                            first_seen=ioc.get("first_seen"),
                            last_seen=ioc.get("last_seen"),
                            is_active=True,
                        )
                        db.add(ti)

                except Exception as e:
                    logger.warning("Failed to process IOC from %s: %s", source, e)
                    continue

        feeds = await db.execute(
            select(ThreatFeed).where(ThreatFeed.source_type == result["source"])
        )
        for feed in feeds.scalars().all():
            feed.indicator_count = result.get("indicators", 0)

        await db.commit()

    logger.info("Threat intel refresh: %s", {r["source"]: r["indicators"] for r in results})
    return {"sources": {r["source"]: r["indicators"] for r in results}}


@celery_app.task(name="app.tasks.threat_intel_tasks.enrich_ioc", queue="threat_intel")
def enrich_ioc(ioc_type: str, value: str):
    """Enrich a single IOC via MISP, OpenCTI, VirusTotal, AbuseIPDB, Shodan."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return loop.run_until_complete(_enrich_ioc_async(ioc_type, value))


async def _enrich_ioc_async(ioc_type: str, value: str) -> Dict[str, Any]:
    from app.services.threat_intel_pipeline import threat_intel_pipeline
    return await threat_intel_pipeline.enrich_ioc(ioc_type, value)
