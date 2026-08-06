"""
AEGISX - Redis Cache Module
"""
import json
from typing import Any, AsyncGenerator, Optional

import redis.asyncio as aioredis
from app.core.config import settings


redis_client: Optional[aioredis.Redis] = None


async def init_cache() -> None:
    global redis_client
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=50,
    )
    await redis_client.ping()


async def close_cache() -> None:
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None


async def get_cache() -> AsyncGenerator[aioredis.Redis, None]:
    if redis_client is None:
        await init_cache()
    try:
        yield redis_client
    finally:
        pass


class CacheService:
    @staticmethod
    async def get(key: str) -> Optional[Any]:
        if redis_client is None:
            return None
        value = await redis_client.get(key)
        if value:
            return json.loads(value)
        return None

    @staticmethod
    async def set(key: str, value: Any, ttl: int = 300) -> None:
        if redis_client is None:
            return
        await redis_client.set(key, json.dumps(value), ex=ttl)

    @staticmethod
    async def delete(key: str) -> None:
        if redis_client is None:
            return
        await redis_client.delete(key)

    @staticmethod
    async def delete_pattern(pattern: str) -> None:
        if redis_client is None:
            return
        keys = await redis_client.keys(pattern)
        if keys:
            await redis_client.delete(*keys)

    @staticmethod
    async def exists(key: str) -> bool:
        if redis_client is None:
            return False
        return await redis_client.exists(key) > 0

    @staticmethod
    async def increment(key: str, amount: int = 1) -> int:
        if redis_client is None:
            return 0
        return await redis_client.incr(key, amount)

    @staticmethod
    async def expire(key: str, ttl: int) -> None:
        if redis_client is None:
            return
        await redis_client.expire(key, ttl)

    @staticmethod
    async def ttl(key: str) -> int:
        if redis_client is None:
            return -2
        return await redis_client.ttl(key)

    @staticmethod
    async def hset(key: str, field: str, value: Any) -> None:
        if redis_client is None:
            return
        await redis_client.hset(key, field, json.dumps(value))

    @staticmethod
    async def hget(key: str, field: str) -> Optional[Any]:
        if redis_client is None:
            return None
        value = await redis_client.hget(key, field)
        if value:
            return json.loads(value)
        return None

    @staticmethod
    async def hgetall(key: str) -> dict:
        if redis_client is None:
            return {}
        data = await redis_client.hgetall(key)
        return {k: json.loads(v) for k, v in data.items()}

    @staticmethod
    async def sadd(key: str, *values: str) -> None:
        if redis_client is None:
            return
        await redis_client.sadd(key, *values)

    @staticmethod
    async def smembers(key: str) -> set:
        if redis_client is None:
            return set()
        return await redis_client.smembers(key)

    @staticmethod
    async def sismember(key: str, value: str) -> bool:
        if redis_client is None:
            return False
        return await redis_client.sismember(key, value)

    @staticmethod
    async def acquire_lock(lock_name: str, ttl: int = 30) -> bool:
        if redis_client is None:
            return False
        return await redis_client.set(
            f"lock:{lock_name}",
            "locked",
            ex=ttl,
            nx=True,
        )

    @staticmethod
    async def release_lock(lock_name: str) -> None:
        if redis_client is None:
            return
        await redis_client.delete(f"lock:{lock_name}")


async def rate_limit_check(
    key: str,
    max_requests: int,
    window_seconds: int,
) -> tuple[bool, int]:
    if redis_client is None:
        return True, 0
    current = await CacheService.increment(key)
    if current == 1:
        await CacheService.expire(key, window_seconds)
    remaining = max(0, max_requests - current)
    return current <= max_requests, remaining
