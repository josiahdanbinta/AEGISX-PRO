import pytest
import time
import statistics
from typing import List, Dict
import asyncio
import httpx


class PerformanceMetrics:
    def __init__(self):
        self.response_times: List[float] = []
        self.errors: int = 0
        self.total_requests: int = 0

    def record(self, response_time: float, is_error: bool = False):
        self.response_times.append(response_time)
        if is_error:
            self.errors += 1
        self.total_requests += 1

    def summary(self) -> Dict:
        if not self.response_times:
            return {"error": "No data"}
        sorted_times = sorted(self.response_times)
        return {
            "total_requests": self.total_requests,
            "errors": self.errors,
            "error_rate": f"{(self.errors / max(1, self.total_requests)) * 100:.2f}%",
            "min_ms": round(min(self.response_times) * 1000, 2),
            "max_ms": round(max(self.response_times) * 1000, 2),
            "avg_ms": round(statistics.mean(self.response_times) * 1000, 2),
            "median_ms": round(statistics.median(self.response_times) * 1000, 2),
            "p95_ms": (
                round(sorted_times[int(len(sorted_times) * 0.95)] * 1000, 2)
                if len(sorted_times) >= 20
                else None
            ),
            "p99_ms": (
                round(sorted_times[int(len(sorted_times) * 0.99)] * 1000, 2)
                if len(sorted_times) >= 100
                else None
            ),
            "std_dev_ms": (
                round(statistics.stdev(self.response_times) * 1000, 2)
                if len(self.response_times) > 1
                else 0
            ),
        }
