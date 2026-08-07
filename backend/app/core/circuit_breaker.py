"""
AEGIS - Circuit Breaker Pattern
Prevents cascading failures for external service calls.
Implements 3-state circuit: CLOSED â†’ OPEN â†’ HALF_OPEN.
"""
import asyncio
import functools
import logging
import time
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5,
                 recovery_timeout: float = 30.0, half_open_max: int = 3):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max = half_open_max

        self._failures = 0
        self._last_failure_time: float = 0
        self._state = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
        self._half_open_count = 0
        self._total_success = 0
        self._total_failures = 0

    @property
    def state(self) -> str:
        return self._state

    @property
    def stats(self) -> dict:
        return {
            "name": self.name, "state": self._state,
            "failures": self._failures, "total_success": self._total_success,
            "total_failures": self._total_failures,
        }

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        if self._state == "OPEN":
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = "HALF_OPEN"
                self._half_open_count = 0
                logger.info("Circuit %s â†’ HALF_OPEN", self.name)
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit {self.name} is OPEN. Retry in "
                    f"{self.recovery_timeout - (time.time() - self._last_failure_time):.1f}s"
                )

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _on_success(self):
        self._failures = 0
        self._total_success += 1
        if self._state == "HALF_OPEN":
            self._half_open_count += 1
            if self._half_open_count >= self.half_open_max:
                self._state = "CLOSED"
                logger.info("Circuit %s â†’ CLOSED (recovered)", self.name)

    def _on_failure(self):
        self._failures += 1
        self._total_failures += 1
        self._last_failure_time = time.time()
        if self._state == "HALF_OPEN" or (
            self._state == "CLOSED" and self._failures >= self.failure_threshold
        ):
            self._state = "OPEN"
            logger.warning("Circuit %s â†’ OPEN (%d failures)", self.name, self._failures)


class CircuitBreakerOpenError(Exception):
    pass


# Pre-configured breakers for external services
_circuits: dict = {}


def circuit_breaker(name: str, failures: int = 5, recovery: float = 30.0):
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if name not in _circuits:
                _circuits[name] = CircuitBreaker(name, failures, recovery)
            return await _circuits[name].call(func, *args, **kwargs)
        return wrapper
    return decorator


def get_circuit_stats() -> list:
    return [cb.stats for cb in _circuits.values()]
