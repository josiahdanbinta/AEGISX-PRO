"""
AEGIS - Kafka Messaging Service
Tier 2 Data Ingestion: Producer/Consumer for events.raw, events.normalized,
alerts.triggered, telemetry.agent topics with Avro schema support.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

try:
    import confluent_kafka
    from confluent_kafka import Producer, Consumer, KafkaError, TopicPartition
    from confluent_kafka.admin import AdminClient, NewTopic, ConfigResource
    from confluent_kafka.schema_registry import SchemaRegistryClient
    from confluent_kafka.schema_registry.avro import AvroSerializer, AvroDeserializer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    Producer = None
    Consumer = None
    AdminClient = None
    NewTopic = None

from app.core.config import settings

logger = logging.getLogger(__name__)

TOPICS = {
    "events.raw": {
        "partitions": 8, "replication_factor": 3,
        "retention_ms": 604800000, "cleanup_policy": "delete", "compression_type": "lz4",
    },
    "events.normalized": {
        "partitions": 8, "replication_factor": 3,
        "retention_ms": 604800000, "cleanup_policy": "delete", "compression_type": "lz4",
    },
    "alerts.triggered": {
        "partitions": 4, "replication_factor": 3,
        "retention_ms": 2592000000, "cleanup_policy": "compact", "compression_type": "lz4",
    },
    "telemetry.agent": {
        "partitions": 6, "replication_factor": 3,
        "retention_ms": 259200000, "cleanup_policy": "delete", "compression_type": "lz4",
    },
}

EVENT_RAW_SCHEMA = {
    "type": "record", "name": "RawEvent",
    "fields": [
        {"name": "event_id", "type": "string"},
        {"name": "tenant_id", "type": "string"},
        {"name": "source", "type": "string"},
        {"name": "source_type", "type": "string"},
        {"name": "timestamp", "type": {"type": "long", "logicalType": "timestamp-millis"}},
        {"name": "raw_data", "type": "string"},
        {"name": "hash", "type": "string"},
        {"name": "agent_id", "type": ["null", "string"], "default": None},
    ],
}

EVENT_NORMALIZED_SCHEMA = {
    "type": "record", "name": "NormalizedEvent",
    "fields": [
        {"name": "event_id", "type": "string"},
        {"name": "tenant_id", "type": "string"},
        {"name": "raw_event_id", "type": "string"},
        {"name": "timestamp", "type": {"type": "long", "logicalType": "timestamp-millis"}},
        {"name": "event_type", "type": "string"},
        {"name": "severity", "type": "string"},
        {"name": "source_ip", "type": ["null", "string"], "default": None},
        {"name": "destination_ip", "type": ["null", "string"], "default": None},
        {"name": "hostname", "type": ["null", "string"], "default": None},
        {"name": "username", "type": ["null", "string"], "default": None},
        {"name": "process_name", "type": ["null", "string"], "default": None},
        {"name": "normalized_data", "type": "string"},
        {"name": "tags", "type": {"type": "array", "items": "string"}, "default": []},
    ],
}

ALERT_SCHEMA = {
    "type": "record", "name": "AlertTriggered",
    "fields": [
        {"name": "alert_id", "type": "string"},
        {"name": "tenant_id", "type": "string"},
        {"name": "rule_id", "type": "string"},
        {"name": "rule_name", "type": "string"},
        {"name": "severity", "type": "string"},
        {"name": "confidence", "type": "float"},
        {"name": "title", "type": "string"},
        {"name": "description", "type": "string"},
        {"name": "source_ip", "type": ["null", "string"], "default": None},
        {"name": "hostname", "type": ["null", "string"], "default": None},
        {"name": "mitre_techniques", "type": {"type": "array", "items": "string"}, "default": []},
        {"name": "correlation_score", "type": ["null", "float"], "default": None},
        {"name": "timestamp", "type": {"type": "long", "logicalType": "timestamp-millis"}},
    ],
}

TELEMETRY_SCHEMA = {
    "type": "record", "name": "AgentTelemetry",
    "fields": [
        {"name": "agent_id", "type": "string"},
        {"name": "tenant_id", "type": "string"},
        {"name": "timestamp", "type": {"type": "long", "logicalType": "timestamp-millis"}},
        {"name": "cpu_percent", "type": "float"},
        {"name": "memory_percent", "type": "float"},
        {"name": "disk_percent", "type": "float"},
        {"name": "network_bytes_sent", "type": "long"},
        {"name": "network_bytes_recv", "type": "long"},
        {"name": "process_count", "type": "int"},
        {"name": "uptime_seconds", "type": "long"},
    ],
}

SCHEMA_MAP = {
    "events.raw": ("events.raw-value", EVENT_RAW_SCHEMA),
    "events.normalized": ("events.normalized-value", EVENT_NORMALIZED_SCHEMA),
    "alerts.triggered": ("alerts.triggered-value", ALERT_SCHEMA),
    "telemetry.agent": ("telemetry.agent-value", TELEMETRY_SCHEMA),
}


class KafkaService:
    """Kafka producer/consumer with Avro serialization, JSON fallback."""

    def __init__(self):
        self.bootstrap_servers = getattr(settings, 'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
        self.schema_registry_url = getattr(settings, 'SCHEMA_REGISTRY_URL', 'http://localhost:8081')
        self._producer: Optional[Producer] = None
        self._admin: Optional[AdminClient] = None
        self._schema_client: Optional[SchemaRegistryClient] = None
        self._serializers: Dict[str, AvroSerializer] = {}
        self._avro_enabled = False
        self._initialized = False

    async def initialize(self):
        if self._initialized:
            return
        conf = {'bootstrap.servers': self.bootstrap_servers}
        self._producer = Producer(conf)
        self._admin = AdminClient(conf)

        try:
            self._schema_client = SchemaRegistryClient({'url': self.schema_registry_url})
            for topic, (subject_name, schema) in SCHEMA_MAP.items():
                serializer = AvroSerializer(
                    schema_registry_client=self._schema_client,
                    schema_str=json.dumps(schema),
                    to_dict=None,
                )
                self._serializers[topic] = serializer
            self._avro_enabled = True
            logger.info("Avro serializers registered for %d topics", len(self._serializers))
        except Exception as e:
            logger.warning("Schema Registry unavailable, using JSON fallback: %s", e)
            self._schema_client = None
            self._avro_enabled = False

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._ensure_topics)
        self._initialized = True
        logger.info("KafkaService initialized (bootstrap: %s, avro: %s)", self.bootstrap_servers, self._avro_enabled)

    def _ensure_topics(self):
        try:
            existing = set(self._admin.list_topics(timeout=10).topics.keys())
            new_topics = []
            for name, config in TOPICS.items():
                if name not in existing:
                    new_topics.append(NewTopic(
                        topic=name,
                        num_partitions=config["partitions"],
                        replication_factor=config["replication_factor"],
                        config={
                            "retention.ms": str(config["retention_ms"]),
                            "cleanup.policy": config["cleanup_policy"],
                            "compression.type": config["compression_type"],
                        },
                    ))
            if new_topics:
                self._admin.create_topics(new_topics)
                logger.info("Created %d Kafka topics: %s", len(new_topics), [t.topic for t in new_topics])
        except Exception as e:
            logger.warning("Topic creation skipped: %s", e)

    def _serialize(self, topic: str, record: dict) -> bytes:
        if self._avro_enabled and topic in self._serializers:
            try:
                return self._serializers[topic](record, None)
            except Exception as e:
                logger.debug("Avro serialize failed for %s, using JSON: %s", topic, e)
        return json.dumps(record).encode('utf-8')

    def _delivery_callback(self, err, msg, topic_name: str):
        if err:
            logger.error("Kafka delivery failed [%s]: %s", topic_name, err)

    async def produce_raw_event(self, event: Dict[str, Any]) -> str:
        event_id = event.get("event_id") or str(uuid.uuid4())
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        record = {
            "event_id": event_id,
            "tenant_id": event.get("tenant_id", "default"),
            "source": event.get("source", "unknown"),
            "source_type": event.get("source_type", "generic"),
            "timestamp": event.get("timestamp", now_ms),
            "raw_data": json.dumps(event.get("data", event)),
            "hash": event.get("hash", ""),
            "agent_id": event.get("agent_id"),
        }
        value = self._serialize("events.raw", record)
        key = record["tenant_id"].encode('utf-8')
        await self._produce("events.raw", key, value)
        return event_id

    async def produce_normalized_event(self, event: Dict[str, Any]) -> str:
        event_id = event.get("event_id") or str(uuid.uuid4())
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        record = {
            "event_id": event_id,
            "tenant_id": event.get("tenant_id", "default"),
            "raw_event_id": event.get("raw_event_id", ""),
            "timestamp": event.get("timestamp", now_ms),
            "event_type": event.get("event_type", "generic"),
            "severity": event.get("severity", "info"),
            "source_ip": event.get("source_ip"),
            "destination_ip": event.get("destination_ip"),
            "hostname": event.get("hostname"),
            "username": event.get("username"),
            "process_name": event.get("process_name"),
            "normalized_data": json.dumps(event.get("data", event)),
            "tags": event.get("tags", []),
        }
        value = self._serialize("events.normalized", record)
        key = record["tenant_id"].encode('utf-8')
        await self._produce("events.normalized", key, value)
        return event_id

    async def produce_alert(self, alert: Dict[str, Any]) -> str:
        alert_id = alert.get("alert_id") or str(uuid.uuid4())
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        record = {
            "alert_id": alert_id,
            "tenant_id": alert.get("tenant_id", "default"),
            "rule_id": str(alert.get("rule_id", "")),
            "rule_name": alert.get("rule_name", "unknown"),
            "severity": alert.get("severity", "medium"),
            "confidence": float(alert.get("confidence", 0.5)),
            "title": alert.get("title", ""),
            "description": alert.get("description", ""),
            "source_ip": alert.get("source_ip"),
            "hostname": alert.get("hostname"),
            "mitre_techniques": alert.get("mitre_techniques", []),
            "correlation_score": alert.get("correlation_score"),
            "timestamp": alert.get("timestamp", now_ms),
        }
        value = self._serialize("alerts.triggered", record)
        key = record["tenant_id"].encode('utf-8')
        await self._produce("alerts.triggered", key, value)
        return alert_id

    async def produce_telemetry(self, telemetry: Dict[str, Any]) -> str:
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        record = {
            "agent_id": telemetry["agent_id"],
            "tenant_id": telemetry.get("tenant_id", "default"),
            "timestamp": telemetry.get("timestamp", now_ms),
            "cpu_percent": float(telemetry.get("cpu_percent", 0)),
            "memory_percent": float(telemetry.get("memory_percent", 0)),
            "disk_percent": float(telemetry.get("disk_percent", 0)),
            "network_bytes_sent": int(telemetry.get("network_bytes_sent", 0)),
            "network_bytes_recv": int(telemetry.get("network_bytes_recv", 0)),
            "process_count": int(telemetry.get("process_count", 0)),
            "uptime_seconds": int(telemetry.get("uptime_seconds", 0)),
        }
        value = self._serialize("telemetry.agent", record)
        key = record["agent_id"].encode('utf-8')
        await self._produce("telemetry.agent", key, value)
        return record["agent_id"]

    async def _produce(self, topic: str, key: bytes, value: bytes):
        await self.initialize()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self._producer.produce(
                topic, key=key, value=value,
                callback=lambda err, msg: self._delivery_callback(err, msg, topic),
            ),
        )
        self._producer.poll(0)

    def flush(self, timeout: float = 10.0):
        if self._producer:
            remaining = self._producer.flush(timeout)
            if remaining:
                logger.warning("%d messages still pending after flush", remaining)

    async def consume_events(self, topics: List[str], group_id: str = "AEGIS-consumer",
                              auto_offset_reset: str = "earliest") -> AsyncIterator[Dict[str, Any]]:
        conf = {
            'bootstrap.servers': self.bootstrap_servers,
            'group.id': group_id,
            'auto.offset.reset': auto_offset_reset,
            'enable.auto.commit': True,
            'auto.commit.interval.ms': 5000,
            'max.poll.interval.ms': 300000,
            'session.timeout.ms': 30000,
        }
        loop = asyncio.get_running_loop()
        consumer = Consumer(conf)
        consumer.subscribe(topics)
        try:
            while True:
                msg = await loop.run_in_executor(None, lambda: consumer.poll(1.0))
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error("Kafka consumer error: %s", msg.error())
                    continue
                try:
                    value = json.loads(msg.value().decode('utf-8'))
                    yield {"topic": msg.topic(), "partition": msg.partition(),
                           "offset": msg.offset(), "key": msg.key(), "value": value}
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.warning("Failed to parse message from %s: %s", msg.topic(), e)
        finally:
            consumer.close()


kafka_service = KafkaService()
