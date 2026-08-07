"""
AEGISX - Flink Stream Processor Entrypoint
Standalone process that runs the Kafka→Flink pipeline:
  events.raw → dedup → normalize → enrich → events.normalized → UEBA → alerts.triggered

Usage:
    python -m app.streaming.flink_runner

Environment variables:
    KAFKA_BOOTSTRAP_SERVERS   (default: localhost:9092)
    SCHEMA_REGISTRY_URL       (default: http://localhost:8081)
    FLINK_PARALLELISM         (default: 8)
    FLINK_WINDOW_MINUTES      (default: 5)
"""
import asyncio
import logging
import os
import signal
import sys

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegisx.flink-runner")


async def main():
    from app.core.config import settings
    from app.streaming.processor import StreamProcessor

    processor = StreamProcessor()
    shutdown_event = asyncio.Event()

    def _shutdown(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info(
        "Starting Flink stream processor — parallelism: %s, bootstrap: %s",
        settings.FEATURE_KAFKA and "enabled" or "disabled",
        settings.KAFKA_BOOTSTRAP_SERVERS,
    )

    try:
        consumer_task = asyncio.create_task(processor.main())
        await shutdown_event.wait()
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
    except Exception as e:
        logger.error("Stream processor crashed: %s", e)
        raise
    finally:
        await processor.shutdown()
        logger.info("Stream processor stopped")


if __name__ == "__main__":
    asyncio.run(main())
