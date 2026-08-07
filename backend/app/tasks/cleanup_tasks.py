"""
AEGIS - Cleanup & Retention Tasks
TimescaleDB cold archive management, token cleanup, log rotation.
"""
import logging
from datetime import datetime, timedelta, timezone

from app.core.celery_config import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.cleanup_tasks.cleanup_expired_tokens")
def cleanup_expired_tokens():
    """Remove expired refresh tokens and blacklisted JWTs."""
    import asyncio

    async def _run():
        from app.core.database import async_session_factory
        from sqlalchemy import delete
        from app.models.token import RefreshToken, BlacklistedToken

        async with async_session_factory() as session:
            now = datetime.now(timezone.utc)
            r1 = await session.execute(
                delete(RefreshToken).where(RefreshToken.expires_at < now)
            )
            r2 = await session.execute(
                delete(BlacklistedToken).where(BlacklistedToken.expires_at < now)
            )
            await session.commit()
            total = r1.rowcount + r2.rowcount
            if total:
                logger.info("Cleaned up %d expired tokens", total)

    try:
        asyncio.get_event_loop().run_until_complete(_run())
    except RuntimeError:
        asyncio.run(_run())


@celery_app.task(name="app.tasks.cleanup_tasks.cleanup_old_logs")
def cleanup_old_logs():
    """Apply retention policies to audit trails older than 90 days."""
    import asyncio

    async def _run():
        from app.core.database import async_session_factory
        from sqlalchemy import text

        try:
            async with async_session_factory() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                result = await session.execute(
                    text("DELETE FROM audit_trail WHERE created_at < :cutoff"),
                    {"cutoff": cutoff},
                )
                await session.commit()
                if result.rowcount:
                    logger.info("Archived %d audit entries older than 90 days", result.rowcount)
        except Exception:
            pass

    try:
        asyncio.get_event_loop().run_until_complete(_run())
    except RuntimeError:
        asyncio.run(_run())


@celery_app.task(name="app.tasks.cleanup_tasks.cold_archive_events")
def cold_archive_events():
    """
    Move events older than 90 days to cold archive table.
    Events table: compress chunks older than 7 days (handled by TimescaleDB policy).
    """
    import asyncio

    async def _run():
        from app.core.database import async_session_factory
        from sqlalchemy import text

        try:
            async with async_session_factory() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                await session.execute(
                    text(
                        "CREATE TABLE IF NOT EXISTS events_raw_archive ("
                        "  LIKE events_raw INCLUDING ALL"
                        ") IF NOT EXISTS;"
                    )
                )
                await session.execute(
                    text(
                        "INSERT INTO events_raw_archive "
                        "SELECT * FROM events_raw WHERE ingested_at < :cutoff"
                    ),
                    {"cutoff": cutoff},
                )
                result = await session.execute(
                    text("DELETE FROM events_raw WHERE ingested_at < :cutoff"),
                    {"cutoff": cutoff},
                )
                await session.commit()
                if result.rowcount:
                    logger.info("Cold-archived %d events older than 90 days", result.rowcount)
        except Exception as e:
            logger.warning("Cold archive skipped: %s", str(e)[:120])

    try:
        asyncio.get_event_loop().run_until_complete(_run())
    except RuntimeError:
        asyncio.run(_run())


@celery_app.task(name="app.tasks.cleanup_tasks.flush_tsdb_buffers")
def flush_tsdb_buffers():
    """Flush any pending TimescaleDB event batches. Runs every 30 seconds."""
    import asyncio

    async def _run():
        try:
            from app.services.timescale_persistence import tsdb_writer
            await tsdb_writer._force_flush()
        except Exception:
            pass

    try:
        asyncio.get_event_loop().run_until_complete(_run())
    except RuntimeError:
        asyncio.run(_run())
