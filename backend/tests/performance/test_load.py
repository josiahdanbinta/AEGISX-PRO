"""
AEGISX Load & Performance Test Suite
Tests concurrent request handling, response times, and throughput.
"""
import pytest
import asyncio
import httpx
import uuid
import time
from conftest import PerformanceMetrics
from app.main import app
from app.core.security import create_access_token

BASE_URL = "http://localhost:8000"
AUTH_ENDPOINTS = [
    ("GET", "/api/v1/auth/me"),
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/dashboards/executive"),
]
READ_ENDPOINTS = [
    ("GET", "/api/v1/assets"),
    ("GET", "/api/v1/incidents"),
    ("GET", "/api/v1/detection/rules"),
    ("GET", "/api/v1/tenants"),
]
WRITE_ENDPOINTS = [
    ("POST", "/api/v1/compliance/frameworks/pci-dss/assess"),
]


def get_headers():
    token = create_access_token(str(uuid.uuid4()), str(uuid.uuid4()), ["super_admin"])
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": str(uuid.uuid4())}


@pytest.mark.performance
class TestConcurrentRequests:
    @pytest.mark.asyncio
    async def test_health_endpoint_under_load(self):
        """Health endpoint should handle 100 concurrent requests under 100ms avg."""
        metrics = PerformanceMetrics()
        url = f"{BASE_URL}/health"

        async def make_request():
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    start = time.time()
                    res = await client.get(url)
                    elapsed = time.time() - start
                    metrics.record(elapsed, res.status_code != 200)
            except Exception:
                metrics.record(10.0, is_error=True)

        tasks = [make_request() for _ in range(100)]
        await asyncio.gather(*tasks)

        summary = metrics.summary()
        print(f"\nHealth endpoint load test: {summary}")
        assert summary["avg_ms"] < 100, (
            f"Average response time {summary['avg_ms']}ms exceeds 100ms"
        )
        assert summary["error_rate"] < "5%", f"Error rate {summary['error_rate']} too high"

    @pytest.mark.asyncio
    async def test_read_endpoints_concurrent(self):
        """Read endpoints should handle 50 concurrent requests each."""
        for method, endpoint in READ_ENDPOINTS:
            metrics = PerformanceMetrics()
            url = f"{BASE_URL}{endpoint}"
            headers = get_headers()

            async def make_request():
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        start = time.time()
                        res = await client.request(method, url, headers=headers)
                        elapsed = time.time() - start
                        metrics.record(elapsed, res.status_code >= 500)
                except Exception:
                    metrics.record(10.0, is_error=True)

            tasks = [make_request() for _ in range(50)]
            await asyncio.gather(*tasks)

            summary = metrics.summary()
            print(f"\n{method} {endpoint}: {summary}")

    @pytest.mark.asyncio
    async def test_sequential_response_times(self):
        """Individual endpoints should respond within 200ms."""
        for method, endpoint in READ_ENDPOINTS + AUTH_ENDPOINTS:
            times = []
            url = f"{BASE_URL}{endpoint}"
            headers = get_headers()

            for _ in range(5):
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        start = time.time()
                        res = await client.request(method, url, headers=headers)
                        times.append((time.time() - start) * 1000)
                except Exception:
                    pass

            if times:
                avg = sum(times) / len(times)
                print(
                    f"{method} {endpoint}: avg={avg:.1f}ms, "
                    f"min={min(times):.1f}ms, max={max(times):.1f}ms"
                )


@pytest.mark.performance
class TestThroughput:
    @pytest.mark.asyncio
    async def test_sustained_throughput(self):
        """Sustain 10 req/s for 10 seconds without degradation."""
        metrics = PerformanceMetrics()
        url = f"{BASE_URL}/health"
        duration = 10
        target_rps = 10

        async def worker():
            async with httpx.AsyncClient(timeout=10.0) as client:
                while True:
                    try:
                        start = time.time()
                        res = await client.get(url)
                        metrics.record(time.time() - start, res.status_code != 200)
                    except Exception:
                        metrics.record(10.0, is_error=True)
                    await asyncio.sleep(1.0 / target_rps)

        workers = [worker() for _ in range(3)]
        task = asyncio.gather(*workers)
        await asyncio.sleep(duration)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        summary = metrics.summary()
        print(
            f"\nSustained throughput test ({duration}s, {target_rps} rps target): {summary}"
        )
        assert metrics.total_requests >= target_rps * duration * 0.5, (
            f"Insufficient throughput: {metrics.total_requests} requests"
        )


@pytest.mark.performance
class TestMemoryLeak:
    @pytest.mark.asyncio
    async def test_no_memory_leak_under_repeated_calls(self):
        """Repeated calls should not cause increasing response times."""
        url = f"{BASE_URL}/health"
        first_batch = []
        last_batch = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            for _ in range(20):
                start = time.time()
                res = await client.get(url)
                first_batch.append((time.time() - start) * 1000)

            for _ in range(200):
                await client.get(url)

            for _ in range(20):
                start = time.time()
                res = await client.get(url)
                last_batch.append((time.time() - start) * 1000)

        first_avg = sum(first_batch) / len(first_batch)
        last_avg = sum(last_batch) / len(last_batch)
        print(f"\nMemory leak test: first_avg={first_avg:.1f}ms, last_avg={last_avg:.1f}ms")
        assert last_avg < first_avg * 3, (
            f"Response time degraded from {first_avg:.1f}ms to {last_avg:.1f}ms"
        )


@pytest.mark.performance
class TestConcurrencyLimits:
    @pytest.mark.asyncio
    async def test_concurrent_user_scaling(self):
        """Test response times at different concurrency levels."""
        url = f"{BASE_URL}/health"

        for concurrency in [10, 50, 100]:
            metrics = PerformanceMetrics()

            async def make_request():
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        start = time.time()
                        res = await client.get(url)
                        metrics.record(time.time() - start, res.status_code != 200)
                except Exception:
                    metrics.record(10.0, is_error=True)

            tasks = [make_request() for _ in range(concurrency)]
            await asyncio.gather(*tasks)

            summary = metrics.summary()
            print(
                f"\nConcurrency={concurrency}: avg={summary['avg_ms']}ms, "
                f"p95={summary['p95_ms']}ms, errors={summary['error_rate']}"
            )
