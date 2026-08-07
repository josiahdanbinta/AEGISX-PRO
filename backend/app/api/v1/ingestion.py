"""
AEGIS - Log Ingestion Pipeline
Syslog (RFC 5424/3164), JSON events, Elastic Beats-compatible ingestion
Stores parsed events in OpenSearch with proper indexing
"""
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.opensearch import get_search_service, SearchService

router = APIRouter()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Syslog Parsing (RFC 5424 & RFC 3164)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

SYSLOG_SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

SYSLOG_FACILITY_MAP = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert",
    15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

RFC5424_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>'                          # PRI
    r'(?P<version>\d{1,3})\s+'                   # VERSION
    r'(?P<timestamp>[^\s]+)\s+'                  # TIMESTAMP
    r'(?P<hostname>[^\s]+)\s+'                   # HOSTNAME
    r'(?P<app_name>[^\s]+)\s+'                   # APP-NAME
    r'(?P<procid>[^\s]+)\s+'                     # PROCID
    r'(?P<msgid>[^\s]+)\s+'                      # MSGID
    r'(?P<structured_data>\[[^\]]*\]|-)\s*'     # STRUCTURED-DATA
    r'(?P<message>.*)$'                          # MSG
)

RFC3164_PATTERN = re.compile(
    r'^<(?P<pri>\d+)>'                           # PRI
    r'(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>[\S]+)\s+'
    r'(?P<message>.*)$'
)


def _parse_priority(pri_value: str) -> dict:
    try:
        pri = int(pri_value)
        facility = pri >> 3
        severity_code = pri & 0x07
        return {
            "facility": facility,
            "facility_name": SYSLOG_FACILITY_MAP.get(facility, f"facility_{facility}"),
            "severity_code": severity_code,
            "severity": SYSLOG_SEVERITY_MAP.get(severity_code, "unknown"),
        }
    except (ValueError, TypeError):
        return {"facility": None, "severity_code": None, "severity": "unknown"}


def parse_syslog_message(raw: str) -> Dict[str, Any]:
    raw_stripped = raw.strip()

    match = RFC5424_PATTERN.match(raw_stripped)
    if match:
        parsed = match.groupdict()
        priority = _parse_priority(parsed.get("pri", "0"))
        return {
            "protocol": "rfc5424",
            "raw_message": raw_stripped,
            "priority": priority,
            "facility": priority.get("facility_name"),
            "severity": priority.get("severity"),
            "severity_code": priority.get("severity_code"),
            "version": int(parsed.get("version", 1)),
            "timestamp": parsed.get("timestamp", ""),
            "hostname": parsed.get("hostname", ""),
            "app_name": parsed.get("app_name", "").replace("-", "") if parsed.get("app_name") != "-" else "",
            "procid": parsed.get("procid", "").replace("-", "") if parsed.get("procid") != "-" else "",
            "msgid": parsed.get("msgid", "").replace("-", "") if parsed.get("msgid") != "-" else "",
            "structured_data": parsed.get("structured_data", ""),
            "message": parsed.get("message", ""),
        }

    match = RFC3164_PATTERN.match(raw_stripped)
    if match:
        parsed = match.groupdict()
        priority = _parse_priority(parsed.get("pri", "0"))
        message = parsed.get("message", "")

        tag = ""
        content = message
        if ":" in message or " " in message:
            parts = message.split(maxsplit=1)
            if len(parts) == 2:
                tag_part = parts[0]
                if ":" in tag_part:
                    tagpart = tag_part.split(":", 1)
                    tag = tagpart[0]
                    if len(tagpart) > 1:
                        content = tagpart[1] + " " + parts[1]
                else:
                    tag = tag_part
                    content = parts[1]
            else:
                tag = parts[0]
                content = ""

        app_name = tag.split("[")[0] if "[" in tag else tag

        return {
            "protocol": "rfc3164",
            "raw_message": raw_stripped,
            "priority": priority,
            "facility": priority.get("facility_name"),
            "severity": priority.get("severity"),
            "severity_code": priority.get("severity_code"),
            "timestamp": parsed.get("timestamp", ""),
            "hostname": parsed.get("hostname", ""),
            "app_name": app_name,
            "tag": tag,
            "message": content,
        }

    return {
        "protocol": "unknown",
        "raw_message": raw_stripped,
        "severity": "info",
        "message": raw_stripped,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SyslogIngestionRequest(BaseModel):
    messages: List[str] = Field(..., min_length=1, max_length=10000,
                                description="List of syslog-formatted messages")

class JSONIngestionRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=10000,
                                          description="List of JSON event objects")
    index_suffix: Optional[str] = Field(None, description="Optional index name suffix")

class BeatsIngestionRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=10000,
                                          description="List of Elastic Beats-compatible JSON documents")
    beat_type: Optional[str] = Field(None, description="Beat type: winlogbeat, filebeat, etc.")

class IngestionResponse(BaseModel):
    accepted: int
    indexed: int
    errors: int
    message: str


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Ingestion helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

SYSLOG_INDEX_MAPPING = {
    "properties": {
        "id": {"type": "keyword"},
        "protocol": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "severity_code": {"type": "integer"},
        "facility": {"type": "keyword"},
        "hostname": {"type": "keyword"},
        "app_name": {"type": "keyword"},
        "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
        "raw_message": {"type": "text"},
        "timestamp_received": {"type": "date"},
        "source_ip": {"type": "ip"},
        "tags": {"type": "keyword"},
        "metadata": {"type": "object", "enabled": True},
    }
}


async def _ensure_syslog_index(search: SearchService) -> str:
    index_name = f"{settings.OPENSEARCH_INDEX_PREFIX}-syslog".lower()
    try:
        if not search.client.index_exists(index_name):
            search.client.create_index(index_name, mappings=SYSLOG_INDEX_MAPPING)
    except Exception:
        pass
    return index_name


async def _bulk_index_syslog(search: SearchService, documents: List[Dict[str, Any]]) -> int:
    index_name = await _ensure_syslog_index(search)
    try:
        docs = [(d.get("id"), d) for d in documents]
        success, _ = search.client.bulk_index(index_name, docs)
        return success
    except Exception:
        return 0


async def _bulk_index_custom(search: SearchService, index_name: str, documents: List[Dict[str, Any]]) -> int:
    try:
        if not search.client.index_exists(index_name):
            search.client.create_index(index_name)
        docs = [(d.get("id"), d) for d in documents]
        success, _ = search.client.bulk_index(index_name, docs)
        return success
    except Exception:
        return 0


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Endpoints
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post(
    "/syslog",
    response_model=IngestionResponse,
    summary="Ingest Syslog Messages",
    description="Accept syslog-formatted messages (RFC 5424/3164), parse, and index them in OpenSearch.",
)
async def ingest_syslog(
    request: SyslogIngestionRequest,
    background_tasks: BackgroundTasks,
    req: Request,
):
    search = get_search_service()
    now = datetime.now(timezone.utc).isoformat()
    client_ip = req.client.host if req.client else "127.0.0.1"

    documents = []
    for raw in request.messages:
        if not raw or not raw.strip():
            continue
        parsed = parse_syslog_message(raw)
        parsed["id"] = str(uuid.uuid4())
        parsed["timestamp_received"] = now
        parsed["source_ip"] = client_ip
        documents.append(parsed)

    if not documents:
        return IngestionResponse(accepted=len(request.messages), indexed=0, errors=0,
                                 message="No valid messages to index")

    indexed = await _bulk_index_syslog(search, documents)
    errors = len(documents) - indexed

    for doc in documents:
        try:
            from app.services.kafka_messaging import kafka_service
            from app.services.dedup_service import dedup_service
            import asyncio

            fingerprint = await dedup_service._compute_event_fingerprint({
                "source": "syslog",
                "source_type": "rfc5424",
                "hostname": doc.get("hostname", ""),
                "raw_data": doc.get("raw_message", ""),
            })
            is_dup = await dedup_service.is_event_duplicate(fingerprint)
            if not is_dup:
                asyncio.create_task(kafka_service.produce_raw_event({
                    "event_id": doc.get("id", ""),
                    "tenant_id": getattr(req.state, "tenant_id", "default"),
                    "source": "syslog",
                    "source_type": "rfc5424",
                    "data": doc,
                }))
        except Exception:
            pass

    return IngestionResponse(
        accepted=len(request.messages),
        indexed=indexed,
        errors=errors,
        message=f"Ingested {indexed}/{len(documents)} parsed syslog events",
    )


@router.post(
    "/json",
    response_model=IngestionResponse,
    summary="Ingest JSON Events",
    description="Accept arbitrary JSON events for bulk ingestion into OpenSearch.",
)
async def ingest_json(
    request: JSONIngestionRequest,
    background_tasks: BackgroundTasks,
):
    search = get_search_service()
    now = datetime.now(timezone.utc).isoformat()
    suffix = request.index_suffix or "events"
    index_name = f"{settings.OPENSEARCH_INDEX_PREFIX}-{suffix}".lower()

    documents = []
    for event in request.events:
        if not isinstance(event, dict):
            continue
        if "id" not in event:
            event["id"] = str(uuid.uuid4())
        if "timestamp" not in event:
            event["timestamp"] = now
        event["ingested_at"] = now
        documents.append(event)

    if not documents:
        return IngestionResponse(accepted=len(request.events), indexed=0, errors=0,
                                 message="No valid events to index")

    indexed = await _bulk_index_custom(search, index_name, documents)
    errors = len(documents) - indexed

    return IngestionResponse(
        accepted=len(request.events),
        indexed=indexed,
        errors=errors,
        message=f"Indexed {indexed}/{len(documents)} JSON events into '{index_name}'",
    )


@router.post(
    "/beats",
    response_model=IngestionResponse,
    summary="Ingest Elastic Beats Events",
    description="Accept Elastic Beats-compatible JSON documents (Winlogbeat, Filebeat, etc.) and index them.",
)
async def ingest_beats(
    request: BeatsIngestionRequest,
    background_tasks: BackgroundTasks,
):
    search = get_search_service()
    now = datetime.now(timezone.utc).isoformat()
    beat_type = request.beat_type or "beats"
    index_name = f"{settings.OPENSEARCH_INDEX_PREFIX}-{beat_type}".lower()

    BEATS_INDEX_MAPPING = {
        "properties": {
            "@timestamp": {"type": "date"},
            "beat": {
                "properties": {
                    "hostname": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "version": {"type": "keyword"},
                }
            },
            "host": {
                "properties": {
                    "hostname": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "ip": {"type": "ip"},
                }
            },
            "message": {"type": "text"},
            "event": {
                "properties": {
                    "kind": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "code": {"type": "keyword"},
                    "provider": {"type": "keyword"},
                }
            },
            "log": {
                "properties": {
                    "level": {"type": "keyword"},
                    "source": {"type": "keyword"},
                }
            },
            "winlog": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "channel": {"type": "keyword"},
                    "provider_name": {"type": "keyword"},
                    "task": {"type": "keyword"},
                    "opcode": {"type": "keyword"},
                    "keywords": {"type": "keyword"},
                    "level": {"type": "keyword"},
                    "computer_name": {"type": "keyword"},
                    "record_id": {"type": "long"},
                    "event_data": {"type": "object", "enabled": True},
                }
            },
            "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
            "agent": {
                "properties": {
                    "id": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "version": {"type": "keyword"},
                }
            },
            "tags": {"type": "keyword"},
            "metadata": {"type": "object", "enabled": True},
        }
    }

    documents = []
    for event in request.events:
        if not isinstance(event, dict):
            continue
        if "id" not in event:
            event["id"] = str(uuid.uuid4())
        if "@timestamp" not in event:
            event["@timestamp"] = now
        event["ingested_at"] = now
        documents.append(event)

    if not documents:
        return IngestionResponse(accepted=len(request.events), indexed=0, errors=0,
                                 message="No valid beats events to index")

    try:
        if not search.client.index_exists(index_name):
            search.client.create_index(index_name, mappings=BEATS_INDEX_MAPPING)
    except Exception:
        pass

    indexed = await _bulk_index_custom(search, index_name, documents)
    errors = len(documents) - indexed

    return IngestionResponse(
        accepted=len(request.events),
        indexed=indexed,
        errors=errors,
        message=f"Indexed {indexed}/{len(documents)} beats events into '{index_name}'",
    )


class BatchEventRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=10000,
                                          description="List of event objects (any format)")
    source: str = Field("api", description="Event source identifier")
    source_type: str = Field("generic", description="Source type for classification")
    index_suffix: Optional[str] = Field("events", description="OpenSearch index suffix")


@router.post(
    "/batch",
    response_model=IngestionResponse,
    summary="Ingest Batch Events",
    description="Accept arbitrary events in batch, index in OpenSearch, and publish to Kafka for streaming.",
)
async def ingest_batch(
    request: BatchEventRequest,
    background_tasks: BackgroundTasks,
    req: Request,
):
    search = get_search_service()
    now = datetime.now(timezone.utc).isoformat()
    index_name = f"{settings.OPENSEARCH_INDEX_PREFIX}-{request.index_suffix or 'events'}".lower()

    documents = []
    for event in request.events:
        if not isinstance(event, dict):
            continue
        if "id" not in event:
            event["id"] = str(uuid.uuid4())
        if "timestamp" not in event:
            event["timestamp"] = now
        event["ingested_at"] = now
        event["source"] = request.source
        event["source_type"] = request.source_type
        documents.append(event)

    if not documents:
        return IngestionResponse(accepted=len(request.events), indexed=0, errors=0,
                                  message="No valid events to index")

    indexed = await _bulk_index_custom(search, index_name, documents)
    errors = len(documents) - indexed

    for doc in documents[:20]:
        try:
            import asyncio as _asyncio
            _asyncio.create_task(kafka_service.produce_raw_event({
                "event_id": doc.get("id", ""),
                "tenant_id": getattr(req.state, "tenant_id", "default"),
                "source": request.source,
                "source_type": request.source_type,
                "data": doc,
            }))
        except Exception:
            pass

    return IngestionResponse(
        accepted=len(request.events),
        indexed=indexed,
        errors=errors,
        message=f"Batch ingested {indexed}/{len(documents)} events into '{index_name}'",
    )


@router.post(
    "/syslog/single",
    response_model=dict,
    summary="Parse Single Syslog Message",
    description="Parse a single syslog message and return the structured result (debug/testing endpoint).",
)
async def parse_single_syslog(raw: str):
    return parse_syslog_message(raw)
