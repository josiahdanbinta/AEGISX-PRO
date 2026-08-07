"""
AEGIS - Deduplication Service
Tier 2: Redis bloom filters for event dedup with 1hr window.
Tier 4: Alert dedup using bloom filters.
"""
import hashlib
import logging
import time
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

DEDUP_WINDOW_SECONDS = 3600  # 1 hour
BLOOM_CAPACITY = 100000
BLOOM_ERROR_RATE = 0.001


class DedupService:
    """Event and alert deduplication using Redis bloom filters."""

    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=50,
            )
        return self._redis

    # â”€â”€ Event Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def is_event_duplicate(self, tenant_id: str, event_data: dict) -> tuple[bool, str]:
        """Check if an event is a duplicate within the 1-hour window.
        Returns (is_duplicate, fingerprint_hash).
        """
        fingerprint = self._compute_event_fingerprint(event_data)
        window_ts = int(time.time() // DEDUP_WINDOW_SECONDS)

        bloom_key = f"dedup:events:{tenant_id}:{window_ts}"

        redis = await self._get_redis()
        try:
            exists = await redis.execute_command("BF.EXISTS", bloom_key, fingerprint)
            if exists:
                logger.debug("Duplicate event detected: %s", fingerprint[:16])
                return True, fingerprint

            await redis.execute_command("BF.ADD", bloom_key, fingerprint)
            await redis.expire(bloom_key, DEDUP_WINDOW_SECONDS * 2)
            return False, fingerprint
        except Exception as e:
            if "unknown command" in str(e).lower():
                logger.warning("Redis Bloom module not loaded; fallback to SET-based dedup")
                return await self._fallback_dedup(bloom_key, fingerprint)
            logger.error("Dedup error: %s", e)
            return False, fingerprint

    async def _fallback_dedup(self, key: str, fingerprint: str) -> tuple[bool, str]:
        redis = await self._get_redis()
        added = await redis.sadd(key, fingerprint)
        if added:
            await redis.expire(key, DEDUP_WINDOW_SECONDS * 2)
        return not bool(added), fingerprint

    def _compute_event_fingerprint(self, event: dict) -> str:
        fields = [
            str(event.get("source")),
            str(event.get("source_type")),
            str(event.get("event_type")),
            str(event.get("source_ip", "")),
            str(event.get("hostname", "")),
            str(event.get("username", "")),
            str(event.get("process_name", "")),
            str(event.get("raw_data", "") or event.get("data", ""))[:512],
            str(event.get("agent_id", "")),
        ]
        return hashlib.sha256("|".join(fields).encode()).hexdigest()

    # â”€â”€ Alert Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def is_alert_duplicate(self, tenant_id: str, rule_id: str,
                                  source_ip: Optional[str],
                                  hostname: Optional[str]) -> bool:
        """Check if an alert for the same rule+entity exists."""
        composite = f"{rule_id}:{source_ip or ''}:{hostname or ''}"
        fp = hashlib.sha256(composite.encode()).hexdigest()

        window_ts = int(time.time() // 3600)
        bloom_key = f"dedup:alerts:{tenant_id}:{window_ts}"

        redis = await self._get_redis()
        try:
            exists = await redis.execute_command("BF.EXISTS", bloom_key, fp)
            if exists:
                return True
            await redis.execute_command("BF.ADD", bloom_key, fp)
            await redis.expire(bloom_key, 7200)
            return False
        except Exception:
            return False

    # â”€â”€ Rate-limiting token bucket â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def check_rate_limit(self, key: str, max_tokens: int,
                                window_seconds: int = 60) -> tuple[bool, int]:
        """Token bucket rate limiter. Returns (allowed, remaining)."""
        redis = await self._get_redis()
        current = await redis.get(key)
        count = int(current) if current else 0

        if count >= max_tokens:
            ttl = await redis.ttl(key)
            return False, 0

        new_count = await redis.incr(key)
        if new_count == 1:
            await redis.expire(key, window_seconds)

        remaining = max_tokens - new_count
        return True, remaining


dedup_service = DedupService()
