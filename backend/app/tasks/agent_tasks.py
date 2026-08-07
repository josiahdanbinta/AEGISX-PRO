"""
AEGIS - Agent-related Celery tasks
"""
from datetime import datetime, timezone

from app.core.celery_config import celery_app
from app.core.database import async_session_factory
from app.models import Agent, Asset
from sqlalchemy import select, update


@celery_app.task(name="app.tasks.agent_tasks.check_agent_heartbeats")
def check_agent_heartbeats():
    """Mark agents as offline if they haven't sent a heartbeat within the timeout."""
    import asyncio

    async def _check():
        async with async_session_factory() as db:
            from app.core.config import settings
            threshold = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            threshold = threshold.replace(minute=threshold.minute - (settings.AGENT_STALE_TIMEOUT // 60))

            stmt = (
                update(Agent)
                .where(
                    Agent.status == "online",
                    Agent.last_heartbeat < threshold,
                )
                .values(status="offline")
            )
            await db.execute(stmt)
            await db.commit()

    asyncio.run(_check())


@celery_app.task(name="app.tasks.agent_tasks.send_agent_command")
def send_agent_command(agent_id: str, command: dict):
    """Send a command to a specific agent (delivered via WebSocket stub)."""
    import asyncio

    async def _send():
        async with async_session_factory() as db:
            agent = await db.scalar(select(Agent).where(Agent.id == agent_id))
            if agent:
                # Actual command delivery would happen via WebSocket
                pass

    asyncio.run(_send())
    return {"status": "queued", "agent_id": agent_id, "command": command.get("action")}
