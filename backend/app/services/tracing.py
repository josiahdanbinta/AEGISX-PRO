"""
AEGIS - OpenTelemetry / Jaeger Tracing
Tier 9: Distributed tracing for detection rule execution and event processing.
Samples 10% of events for performance monitoring.
"""
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)


def setup_tracing():
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider, sampling
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

    sampler = sampling.ParentBased(
        root=sampling.TraceIdRatioBased(settings.JAEGER_SAMPLING_RATE)
    )

    resource = Resource(attributes={
        SERVICE_NAME: settings.OTEL_SERVICE_NAME,
    })

    provider = TracerProvider(sampler=sampler, resource=resource)

    jaeger_exporter = JaegerExporter(
        agent_host_name=settings.JAEGER_HOST,
        agent_port=settings.JAEGER_PORT,
    )

    provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor().instrument(excluded_urls="/metrics,/health,/debug")
    HTTPXClientInstrumentor().instrument()

    logger.info(
        "Tracing initialized: Jaeger @ %s:%d (sampling rate: %.2f%%)",
        settings.JAEGER_HOST, settings.JAEGER_PORT,
        settings.JAEGER_SAMPLING_RATE * 100,
    )
