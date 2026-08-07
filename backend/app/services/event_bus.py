"""
AEGISX - Redis PubSub Event Bus
Backbone for real-time push notifications. Producers publish events,
WebSocket subscribers receive them via Redis channels.

Channels:
    aegisx:dashboard:updates      — aggregate dashboard stats (emitted every 10s)
    aegisx:alerts:{tenant_id}     — new alerts for tenant
    aegisx:incident:{id}          — incident status/note/timeline changes
    aegisx:anomaly:{tenant_id}    — UEBA anomaly alerts
    aegisx:agent:{agent_id}       — agent status/heartbeat updates
"""
import asyncio
import json
import logging
from typing import Any, AsyncIterator, Callable, Dict, Optional

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger("aegisx.eventbus")


class EventBus:
    """Centralized event bus backed by Redis PubSub."""

    def __init__(self):
        self._pub: Optional[aioredis.Redis] = None
        self._sub: Optional[aioredis.Redis] = None

    async def _get_pub(self) -> aioredis.Redis:
        if self._pub is None:
            self._pub = aioredis.from_url(
                settings.REDIS_URL, encoding="utf-8", decode_responses=False,
            )
        return self._pub

    async def _get_sub(self) -> aioredis.Redis:
        if self._sub is None:
            self._sub = aioredis.from_url(
                settings.REDIS_URL, encoding="utf-8", decode_responses=False,
            )
        return self._sub

    # ── Publish ────────────────────────────────────────────────

    async def publish(self, channel: str, payload: dict):
        """Publish a JSON event to a channel."""
        try:
            pub = await self._get_pub()
            await pub.publish(channel, json.dumps(payload, default=str).encode())
        except Exception as e:
            logger.debug("EventBus publish failed [%s]: %s", channel, e)

    async def dashboard_update(self, stats: dict):
        await self.publish("aegisx:dashboard:updates", {
            "type": "dashboard_update", "data": stats,
        })

    async def alert_created(self, tenant_id: str, alert: dict):
        await self.publish(f"aegisx:alerts:{tenant_id}", {
            "type": "alert", "data": alert,
        })

    async def anomaly_detected(self, tenant_id: str, anomaly: dict):
        await self.publish(f"aegisx:anomaly:{tenant_id}", {
            "type": "anomaly", "data": anomaly,
        })

    async def incident_update(self, incident_id: str, tenant_id: str, update: dict):
        await self.publish(f"aegisx:incident:{incident_id}", {
            "type": "incident_update", "incident_id": incident_id,
            "tenant_id": tenant_id, "data": update,
        })

    async def agent_heartbeat(self, agent_id: str, tenant_id: str, status: dict):
        await self.publish(f"aegisx:agent:{agent_id}", {
            "type": "agent_heartbeat", "agent_id": agent_id,
            "tenant_id": tenant_id, "data": status,
        })

    # ── Subscribe ─────────────────────────────────────────────

    async def subscribe(self, *channels: str) -> AsyncIterator[Dict[str, Any]]:
        """Subscribe to channels and yield deserialized messages."""
        sub = await self._get_sub()
        pubsub = sub.pubsub()
        await pubsub.subscribe(*channels)
        logger.debug("Subscribed to channels: %s", channels)
        try:
            async for msg in pubsub.listen():
                if msg["type"] != "message":
                    continue
                try:
                    yield json.loads(msg["data"].decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.debug("EventBus parse error: %s", e)
        finally:
            await pubsub.unsubscribe(*channels)
            await pubsub.close()

    async def close(self):
        for client in (self._pub, self._sub):
            if client:
                try:
                    await client.close()
                except Exception:
                    pass


event_bus = EventBus()
