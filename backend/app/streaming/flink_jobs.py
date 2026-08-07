"""
AEGISX - Apache Flink Stream Processing Jobs (Tier 3)
Python-based Flink job definitions for event normalization, enrichment,
deduplication, window operations, and alert triggering.
Uses PyFlink Table API for stateful stream processing.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Flink Job 1: Event Normalization
# ═══════════════════════════════════════════════════════════════

EVENT_NORMALIZATION_SQL = """
CREATE TABLE raw_events (
    event_id STRING,
    tenant_id STRING,
    source STRING,
    source_type STRING,
    `timestamp` BIGINT,
    raw_data STRING,
    event_hash STRING,
    agent_id STRING,
    proc_time AS PROCTIME(),
    event_time AS TO_TIMESTAMP(FROM_UNIXTIME(`timestamp` / 1000)),
    WATERMARK FOR event_time AS event_time - INTERVAL '30' SECOND
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.raw',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'properties.group.id' = 'flink-normalizer',
    'scan.startup.mode' = 'latest-offset',
    'format' = 'json',
    'json.fail-on-missing-field' = 'false'
);

CREATE TABLE normalized_events (
    event_id STRING,
    tenant_id STRING,
    raw_event_id STRING,
    `timestamp` BIGINT,
    event_type STRING,
    severity STRING,
    source_ip STRING,
    destination_ip STRING,
    hostname STRING,
    username STRING,
    process_name STRING,
    normalized_data STRING,
    tags ARRAY<STRING>,
    enrichment STRING
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.normalized',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'format' = 'json'
);

INSERT INTO normalized_events
SELECT
    UUID() AS event_id,
    tenant_id,
    event_id AS raw_event_id,
    `timestamp`,
    CASE
        WHEN LOWER(raw_data) LIKE '%process%create%' THEN 'process_create'
        WHEN LOWER(raw_data) LIKE '%powershell%' OR LOWER(raw_data) LIKE '%scriptblock%' THEN 'powershell'
        WHEN LOWER(raw_data) LIKE '%wmi%' THEN 'wmi_event'
        WHEN LOWER(raw_data) LIKE '%service%install%' THEN 'service_event'
        WHEN LOWER(raw_data) LIKE '%login%' OR LOWER(raw_data) LIKE '%logon%' THEN 'authentication'
        WHEN LOWER(raw_data) LIKE '%network%connect%' THEN 'network_connect'
        WHEN LOWER(raw_data) LIKE '%dns%' THEN 'dns_query'
        WHEN LOWER(raw_data) LIKE '%reg%' THEN 'registry_event'
        ELSE 'generic'
    END AS event_type,
    CASE
        WHEN LOWER(raw_data) LIKE '%mimikatz%' OR LOWER(raw_data) LIKE '%ransomware%' THEN 'critical'
        WHEN LOWER(raw_data) LIKE '%suspicious%' OR LOWER(raw_data) LIKE '%encodedcommand%' THEN 'high'
        WHEN LOWER(raw_data) LIKE '%error%' OR LOWER(raw_data) LIKE '%failed%' THEN 'medium'
        ELSE 'low'
    END AS severity,
    NULL AS source_ip,
    NULL AS destination_ip,
    NULL AS hostname,
    NULL AS username,
    NULL AS process_name,
    raw_data AS normalized_data,
    ARRAY[source_type] AS tags,
    '{}' AS enrichment
FROM raw_events;
"""


# ═══════════════════════════════════════════════════════════════
# Flink Job 2: Window Operations & Aggregation
# ═══════════════════════════════════════════════════════════════

WINDOW_AGGREGATION_SQL = """
CREATE TABLE normalized_source (
    event_id STRING,
    tenant_id STRING,
    raw_event_id STRING,
    `timestamp` BIGINT,
    event_type STRING,
    severity STRING,
    source_ip STRING,
    hostname STRING,
    username STRING,
    tags ARRAY<STRING>,
    proc_time AS PROCTIME(),
    event_time AS TO_TIMESTAMP(FROM_UNIXTIME(`timestamp` / 1000)),
    WATERMARK FOR event_time AS event_time - INTERVAL '10' SECOND
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.normalized',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'properties.group.id' = 'flink-window-agg',
    'scan.startup.mode' = 'latest-offset',
    'format' = 'json',
    'json.fail-on-missing-field' = 'false'
);

CREATE TABLE event_windows_5min (
    tenant_id STRING,
    window_start TIMESTAMP(3),
    window_end TIMESTAMP(3),
    event_type STRING,
    severity STRING,
    event_count BIGINT,
    unique_hosts BIGINT,
    unique_sources BIGINT,
    avg_confidence DOUBLE,
    PRIMARY KEY (tenant_id, window_start, event_type) NOT ENFORCED
) WITH (
    'connector' = 'jdbc',
    'url' = 'jdbc:clickhouse://clickhouse:8123/aegisx',
    'table-name' = 'event_metrics_hourly',
    'driver' = 'ru.yandex.clickhouse.ClickHouseDriver',
    'username' = 'aegisx',
    'password' = 'aegisx'
);

CREATE TABLE alert_triggers (
    alert_id STRING,
    tenant_id STRING,
    rule_id STRING,
    rule_name STRING,
    severity STRING,
    confidence DOUBLE,
    title STRING,
    description STRING,
    source_ip STRING,
    hostname STRING,
    mitre_techniques ARRAY<STRING>,
    `timestamp` BIGINT
) WITH (
    'connector' = 'kafka',
    'topic' = 'alerts.triggered',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'format' = 'json'
);

INSERT INTO event_windows_5min
SELECT
    tenant_id,
    TUMBLE_START(event_time, INTERVAL '5' MINUTE) AS window_start,
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    event_type,
    LAST_VALUE(severity) AS severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT hostname) AS unique_hosts,
    COUNT(DISTINCT source_ip) AS unique_sources,
    0.5 AS avg_confidence
FROM normalized_source
GROUP BY tenant_id, TUMBLE(event_time, INTERVAL '5' MINUTE), event_type;

INSERT INTO alert_triggers
SELECT
    UUID() AS alert_id,
    tenant_id,
    'flink-spike-detection' AS rule_id,
    'Volume Spike Detected' AS rule_name,
    'high' AS severity,
    0.7 AS confidence,
    CONCAT('Event spike: ', CAST(COUNT(*) AS STRING), ' ', event_type, ' events in 5 minutes') AS title,
    CONCAT('Detected abnormal spike of ', event_type, ' events. ', CAST(COUNT(DISTINCT hostname) AS STRING), ' unique hosts, ', CAST(COUNT(DISTINCT source_ip) AS STRING), ' unique sources.') AS description,
    NULL AS source_ip,
    NULL AS hostname,
    ARRAY['TA0043'] AS mitre_techniques,
    UNIX_TIMESTAMP() * 1000 AS `timestamp`
FROM normalized_source
GROUP BY tenant_id, TUMBLE(event_time, INTERVAL '5' MINUTE), event_type
HAVING COUNT(*) > 100;
"""


# ═══════════════════════════════════════════════════════════════
# Flink Job 3: Deduplication (Deduplicate within 1-hour window)
# ═══════════════════════════════════════════════════════════════

DEDUP_SQL = """
CREATE TABLE events_with_dedup (
    event_id STRING,
    tenant_id STRING,
    event_type STRING,
    severity STRING,
    source_ip STRING,
    hostname STRING,
    username STRING,
    `timestamp` BIGINT,
    dedup_key STRING,
    event_time AS TO_TIMESTAMP(FROM_UNIXTIME(`timestamp` / 1000)),
    WATERMARK FOR event_time AS event_time - INTERVAL '1' HOUR
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.normalized',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'properties.group.id' = 'flink-dedup',
    'scan.startup.mode' = 'latest-offset',
    'format' = 'json',
    'json.fail-on-missing-field' = 'false'
);

CREATE TABLE events_deduplicated (
    event_id STRING,
    tenant_id STRING,
    event_type STRING,
    severity STRING,
    source_ip STRING,
    hostname STRING,
    username STRING,
    `timestamp` BIGINT,
    is_duplicate BOOLEAN
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.normalized',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'format' = 'json'
);

INSERT INTO events_deduplicated
SELECT
    event_id,
    tenant_id,
    event_type,
    severity,
    source_ip,
    hostname,
    username,
    `timestamp`,
    CASE WHEN ROW_NUMBER() OVER (
        PARTITION BY MD5(CONCAT(tenant_id, COALESCE(source_ip, ''), COALESCE(hostname, ''), event_type))
        ORDER BY event_time ASC
    ) > 1 THEN TRUE ELSE FALSE END AS is_duplicate
FROM events_with_dedup;
"""


# ═══════════════════════════════════════════════════════════════
# Flink Job 4: UEBA Anomaly Detection Integration
# ═══════════════════════════════════════════════════════════════

UEBA_SQL = """
CREATE TABLE event_stream (
    event_id STRING,
    tenant_id STRING,
    event_type STRING,
    severity STRING,
    source_ip STRING,
    hostname STRING,
    username STRING,
    tags ARRAY<STRING>,
    enrichment STRING,
    `timestamp` BIGINT,
    proc_time AS PROCTIME(),
    event_time AS TO_TIMESTAMP(FROM_UNIXTIME(`timestamp` / 1000)),
    WATERMARK FOR event_time AS event_time - INTERVAL '30' SECOND
) WITH (
    'connector' = 'kafka',
    'topic' = 'events.normalized',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'properties.group.id' = 'flink-ueba',
    'scan.startup.mode' = 'latest-offset',
    'format' = 'json',
    'json.fail-on-missing-field' = 'false'
);

CREATE TABLE hourly_baselines (
    tenant_id STRING,
    hostname STRING,
    username STRING,
    window_start TIMESTAMP(3),
    window_end TIMESTAMP(3),
    event_count BIGINT,
    severity_critical BIGINT,
    severity_high BIGINT,
    severity_medium BIGINT,
    unique_event_types BIGINT,
    top_event_type STRING,
    anomaly_score DOUBLE,
    PRIMARY KEY (tenant_id, hostname, window_start) NOT ENFORCED
) WITH (
    'connector' = 'jdbc',
    'url' = 'jdbc:clickhouse://clickhouse:8123/aegisx',
    'table-name' = 'ueba_hourly_baselines',
    'driver' = 'ru.yandex.clickhouse.ClickHouseDriver',
    'username' = 'aegisx',
    'password' = 'aegisx'
);

INSERT INTO hourly_baselines
SELECT
    tenant_id,
    COALESCE(hostname, 'unknown') AS hostname,
    COALESCE(username, 'unknown') AS username,
    TUMBLE_START(event_time, INTERVAL '1' HOUR) AS window_start,
    TUMBLE_END(event_time, INTERVAL '1' HOUR) AS window_end,
    COUNT(*) AS event_count,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS severity_critical,
    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS severity_high,
    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS severity_medium,
    COUNT(DISTINCT event_type) AS unique_event_types,
    LAST_VALUE(event_type) AS top_event_type,
    (CAST(SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS DOUBLE) / CAST(COUNT(*) + 1 AS DOUBLE)) * 10.0 AS anomaly_score
FROM event_stream
GROUP BY
    tenant_id,
    COALESCE(hostname, 'unknown'),
    COALESCE(username, 'unknown'),
    TUMBLE(event_time, INTERVAL '1' HOUR);
"""


# ═══════════════════════════════════════════════════════════════
# Flink Job 5: Telemetry Aggregation
# ═══════════════════════════════════════════════════════════════

TELEMETRY_SQL = """
CREATE TABLE agent_telemetry (
    agent_id STRING,
    tenant_id STRING,
    `timestamp` BIGINT,
    cpu_percent DOUBLE,
    memory_percent DOUBLE,
    disk_percent DOUBLE,
    network_bytes_sent BIGINT,
    network_bytes_recv BIGINT,
    process_count INT,
    uptime_seconds BIGINT,
    event_time AS TO_TIMESTAMP(FROM_UNIXTIME(`timestamp` / 1000)),
    WATERMARK FOR event_time AS event_time - INTERVAL '1' MINUTE
) WITH (
    'connector' = 'kafka',
    'topic' = 'telemetry.agent',
    'properties.bootstrap.servers' = 'kafka-1:9092,kafka-2:9092,kafka-3:9092',
    'properties.group.id' = 'flink-telemetry',
    'scan.startup.mode' = 'latest-offset',
    'format' = 'json',
    'json.fail-on-missing-field' = 'false'
);

CREATE TABLE agent_health_metrics (
    agent_id STRING,
    tenant_id STRING,
    window_start TIMESTAMP(3),
    window_end TIMESTAMP(3),
    avg_cpu DOUBLE,
    avg_memory DOUBLE,
    max_cpu DOUBLE,
    max_memory DOUBLE,
    avg_disk DOUBLE,
    avg_process_count DOUBLE,
    bandwidth_bytes_sent BIGINT,
    bandwidth_bytes_recv BIGINT,
    sample_count BIGINT,
    PRIMARY KEY (agent_id, window_start) NOT ENFORCED
) WITH (
    'connector' = 'jdbc',
    'url' = 'jdbc:clickhouse://clickhouse:8123/aegisx',
    'table-name' = 'agent_health_metrics_hourly',
    'driver' = 'ru.yandex.clickhouse.ClickHouseDriver',
    'username' = 'aegisx',
    'password' = 'aegisx'
);

INSERT INTO agent_health_metrics
SELECT
    agent_id,
    tenant_id,
    TUMBLE_START(event_time, INTERVAL '5' MINUTE) AS window_start,
    TUMBLE_END(event_time, INTERVAL '5' MINUTE) AS window_end,
    AVG(cpu_percent) AS avg_cpu,
    AVG(memory_percent) AS avg_memory,
    MAX(cpu_percent) AS max_cpu,
    MAX(memory_percent) AS max_memory,
    AVG(disk_percent) AS avg_disk,
    AVG(CAST(process_count AS DOUBLE)) AS avg_process_count,
    SUM(network_bytes_sent) AS bandwidth_bytes_sent,
    SUM(network_bytes_recv) AS bandwidth_bytes_recv,
    COUNT(*) AS sample_count
FROM agent_telemetry
GROUP BY agent_id, tenant_id, TUMBLE(event_time, INTERVAL '5' MINUTE);

INSERT INTO alert_triggers
SELECT
    UUID() AS alert_id,
    tenant_id,
    'agent-health-anomaly' AS rule_id,
    'Agent Health Anomaly' AS rule_name,
    'medium' AS severity,
    0.5 AS confidence,
    CONCAT('High CPU usage on agent ', agent_id) AS title,
    CONCAT('Agent ', agent_id, ' CPU at ', CAST(ROUND(AVG(cpu_percent), 1) AS STRING), '% over 5 minutes') AS description,
    NULL AS source_ip,
    NULL AS hostname,
    ARRAY['TA0040'] AS mitre_techniques,
    UNIX_TIMESTAMP() * 1000 AS `timestamp`
FROM agent_telemetry
GROUP BY agent_id, tenant_id, TUMBLE(event_time, INTERVAL '5' MINUTE)
HAVING AVG(cpu_percent) > 90 OR AVG(memory_percent) > 95;
"""


# ═══════════════════════════════════════════════════════════════
# Job Factory
# ═══════════════════════════════════════════════════════════════

FLINK_JOBS = {
    "event-normalization": {
        "name": "Event Normalization",
        "description": "Normalize raw events into ECS-compatible format with severity classification",
        "sql": EVENT_NORMALIZATION_SQL,
        "parallelism": 8,
        "memory": "2g",
    },
    "window-aggregation": {
        "name": "Window Aggregation & Baseline Detection",
        "description": "5-minute tumbling windows with spike detection and ClickHouse writes",
        "sql": WINDOW_AGGREGATION_SQL,
        "parallelism": 4,
        "memory": "2g",
    },
    "deduplication": {
        "name": "Event Deduplication",
        "description": "Deduplicate events within a 1-hour window using ROW_NUMBER",
        "sql": DEDUP_SQL,
        "parallelism": 4,
        "memory": "1g",
    },
    "ueba-integration": {
        "name": "UEBA Baseline Computation",
        "description": "Per-entity hourly baselines with anomaly scoring",
        "sql": UEBA_SQL,
        "parallelism": 4,
        "memory": "2g",
    },
    "telemetry-aggregation": {
        "name": "Agent Telemetry Aggregation",
        "description": "5-minute window aggregation of agent health metrics with anomaly alerting",
        "sql": TELEMETRY_SQL,
        "parallelism": 2,
        "memory": "1g",
    },
}


def get_job_definition(job_name: str) -> Optional[Dict[str, Any]]:
    return FLINK_JOBS.get(job_name)


def list_jobs() -> List[Dict[str, Any]]:
    return [
        {"id": key, "name": job["name"], "description": job["description"],
         "parallelism": job["parallelism"], "memory": job["memory"]}
        for key, job in FLINK_JOBS.items()
    ]
