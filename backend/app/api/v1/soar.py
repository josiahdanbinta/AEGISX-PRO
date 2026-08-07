"""
AEGIS - SOAR (Security Orchestration, Automation & Response) API Router
Playbooks, executions, actions, and integration management
"""
import json
import math
import uuid as uuid_mod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Set

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, update as sql_update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireIncidentResponder,
    RequireSOCManager,
    RequireSOCAnalyst,
)
from app.core.database import get_db
from app.models import Playbook, PlaybookExecution, IntegrationConfig, AuditLog, Incident

router = APIRouter()

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

logger = logging.getLogger(__name__)

def _uuid(v: Any) -> uuid_mod.UUID:
    if isinstance(v, uuid_mod.UUID):
        return v
    return uuid_mod.UUID(str(v))

def _paginated(items: list, total: int, page: int, page_size: int) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)) if page_size else 1,
    }

async def _audit_log(
    db: AsyncSession,
    user: dict,
    action: str,
    resource_type: str,
    resource_id: Optional[uuid_mod.UUID] = None,
    details: Optional[dict] = None,
):
    try:
        uid = _uuid(user["user_id"]) if user.get("user_id") else None
        tid = _uuid(user.get("tenant_id")) if user.get("tenant_id") else None
        log = AuditLog(
            tenant_id=tid,
            user_id=uid,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            status="success",
            severity="info",
        )
        db.add(log)
        await db.flush()
    except Exception:
        pass

def _build_playbook_response(pb: Playbook) -> dict:
    steps = pb.steps or []
    conditions = pb.conditions or []
    triggers = []
    for cond in conditions:
        if isinstance(cond, dict):
            triggers.append({
                "trigger_type": cond.get("trigger_type", pb.trigger_type),
                "condition": cond.get("condition"),
                "schedule": cond.get("schedule"),
            })
    if not triggers:
        triggers = [{"trigger_type": pb.trigger_type, "condition": None, "schedule": None}]

    return {
        "id": str(pb.id),
        "name": pb.name,
        "description": pb.description,
        "triggers": triggers,
        "steps": [{"name": s.get("name", "step"), "action": s.get("action", ""),
                    "parameters": s.get("parameters", {}), "condition": s.get("condition"),
                    "on_failure": s.get("on_failure", "stop"), "retry_count": s.get("retry_count", 0),
                    "retry_delay_seconds": s.get("retry_delay_seconds", 30),
                    "timeout_seconds": s.get("timeout_seconds", 300),
                    "requires_approval": s.get("requires_approval", False),
                    "approver_roles": s.get("approver_roles", []),
                    "depends_on": s.get("depends_on", []),
                    "description": s.get("description"),
                    "id": s.get("id")} for s in steps],
        "severity": "medium",
        "status": pb.status,
        "tags": list(pb.tags or []),
        "enabled": pb.status == "active",
        "version": f"{pb.version}.0.0" if pb.version else "1.0.0",
        "metadata": None,
        "notify_on_start": False,
        "notify_on_completion": True,
        "notify_on_failure": True,
        "tenant_id": str(pb.tenant_id),
        "created_by": str(pb.created_by) if pb.created_by else None,
        "updated_by": str(pb.created_by) if pb.created_by else None,
        "created_at": pb.created_at,
        "updated_at": pb.updated_at,
        "execution_count": pb.execution_count,
        "last_executed_at": pb.last_executed_at,
    }

def _build_execution_response(exec: PlaybookExecution) -> dict:
    steps_results = exec.steps_results or []
    total_steps = len(steps_results)
    completed_steps = sum(1 for s in steps_results if isinstance(s, dict) and s.get("status") in ("completed", "failed", "skipped"))
    failed_steps = sum(1 for s in steps_results if isinstance(s, dict) and s.get("status") == "failed")

    return {
        "id": str(exec.id),
        "playbook_id": str(exec.playbook_id),
        "playbook_name": None,
        "status": exec.status,
        "trigger_type": exec.trigger,
        "trigger_source_id": str(exec.incident_id) if exec.incident_id else None,
        "step_results": steps_results,
        "current_step_index": exec.current_step,
        "total_steps": total_steps,
        "completed_steps": completed_steps,
        "failed_steps": failed_steps,
        "started_at": exec.created_at,
        "completed_at": exec.completed_at,
        "duration_seconds": (exec.completed_at - exec.created_at).total_seconds() if exec.completed_at and exec.created_at else None,
        "error_message": exec.error_message,
        "tenant_id": str(exec.tenant_id),
        "triggered_by": str(exec.triggered_by) if exec.triggered_by else None,
        "payload": None,
    }

def _build_integration_response(inte: IntegrationConfig) -> dict:
    cfg = inte.config or {}
    return {
        "id": str(inte.id),
        "name": inte.name,
        "integration_type": inte.integration_type,
        "description": cfg.get("description"),
        "auth_type": cfg.get("auth_type", "api_key"),
        "endpoint_url": cfg.get("endpoint_url"),
        "enabled": inte.is_active,
        "tags": cfg.get("tags", []),
        "metadata": cfg.get("metadata"),
        "tenant_id": str(inte.tenant_id),
        "created_by": str(inte.created_by) if inte.created_by else None,
        "created_at": inte.created_at,
        "updated_at": inte.updated_at,
        "last_tested_at": inte.last_tested_at,
        "connection_status": inte.test_status,
    }

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Enums
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PlaybookStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"
    TESTING = "testing"

class PlaybookTriggerType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    SCHEDULE = "schedule"
    WEBHOOK = "webhook"
    MANUAL = "manual"
    EVENT = "event"

class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"

class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class ExportFormat(str, Enum):
    JSON = "json"
    YAML = "yaml"

class IntegrationType(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    EMAIL = "email"
    TICKETING = "ticketing"
    MESSAGING = "messaging"
    IDENTITY = "identity"
    CLOUD = "cloud"
    NETWORK = "network"
    CUSTOM = "custom"

class IntegrationAuthType(str, Enum):
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    NONE = "none"

# Predefined action names
VALID_ACTION_NAMES: Set[str] = {
    "block_ip", "unblock_ip", "disable_account", "enable_account", "restart_service",
    "kill_process", "isolate_endpoint", "release_endpoint", "collect_forensics",
    "notify_teams", "notify_slack", "open_jira", "open_servicenow",
    "execute_script", "run_ansible", "send_email", "quarantine_file",
    "add_firewall_rule", "remove_firewall_rule", "scan_endpoint", "update_ticket",
    "add_to_watchlist", "enrich_ip", "enrich_domain", "enrich_hash",
    "suspend_user", "force_password_reset", "revoke_session",
}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Common Response Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Playbook Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PlaybookStep(BaseModel):
    id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=255)
    action: str = Field(..., description="Action name from available actions")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    condition: Optional[str] = Field(None, description="Condition expression to evaluate before step")
    on_failure: str = Field("stop", description="'stop', 'continue', or 'retry'")
    retry_count: int = Field(0, ge=0, le=10)
    retry_delay_seconds: int = Field(30, ge=1, le=900)
    timeout_seconds: int = Field(300, ge=1, le=3600)
    requires_approval: bool = False
    approver_roles: List[str] = []
    depends_on: List[str] = Field(default_factory=list, description="IDs of steps this depends on")
    description: Optional[str] = Field(None, max_length=1000)

class PlaybookTrigger(BaseModel):
    trigger_type: PlaybookTriggerType
    condition: Optional[Dict[str, Any]] = Field(None, description="Trigger condition (alert severity, type, etc.)")
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled triggers")

class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    triggers: List[PlaybookTrigger] = Field(default_factory=list)
    steps: List[PlaybookStep] = Field(..., min_length=1)
    severity: Optional[str] = Field("medium", pattern=r"^(low|medium|high|critical)$")
    tags: List[str] = []
    enabled: bool = False
    version: str = Field("1.0.0", pattern=r"^\d+\.\d+\.\d+$")
    metadata: Optional[Dict[str, Any]] = None
    notify_on_start: bool = False
    notify_on_completion: bool = True
    notify_on_failure: bool = True

class PlaybookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    triggers: Optional[List[PlaybookTrigger]] = None
    steps: Optional[List[PlaybookStep]] = None
    severity: Optional[str] = Field(None, pattern=r"^(low|medium|high|critical)$")
    tags: Optional[List[str]] = None
    enabled: Optional[bool] = None
    version: Optional[str] = Field(None, pattern=r"^\d+\.\d+\.\d+$")
    status: Optional[PlaybookStatus] = None
    metadata: Optional[Dict[str, Any]] = None
    notify_on_start: Optional[bool] = None
    notify_on_completion: Optional[bool] = None
    notify_on_failure: Optional[bool] = None

class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    triggers: List[PlaybookTrigger] = []
    steps: List[PlaybookStep]
    severity: str = "medium"
    status: PlaybookStatus = PlaybookStatus.DRAFT
    tags: List[str] = []
    enabled: bool = False
    version: str = "1.0.0"
    metadata: Optional[Dict[str, Any]] = None
    notify_on_start: bool = False
    notify_on_completion: bool = True
    notify_on_failure: bool = True
    tenant_id: str
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    execution_count: int = 0
    last_executed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class PlaybookImportRequest(BaseModel):
    content: str = Field(..., description="JSON or YAML playbook definition")
    format: ExportFormat = ExportFormat.JSON
    overwrite_existing: bool = False

class PlaybookImportResponse(BaseModel):
    imported: bool
    playbook_id: Optional[str] = None
    message: str

class PlaybookCloneRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)

class PlaybookTestResponse(BaseModel):
    playbook_id: str
    valid: bool
    step_count: int
    validation_errors: List[Dict[str, Any]] = []
    estimated_duration_seconds: Optional[float] = None
    warnings: List[str] = []


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Execution Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ExecutionStepResult(BaseModel):
    step_id: str
    step_name: str
    action: str
    status: StepStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_attempts: int = 0
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None

class ExecutionResponse(BaseModel):
    id: str
    playbook_id: str
    playbook_name: Optional[str] = None
    status: ExecutionStatus
    trigger_type: Optional[str] = None
    trigger_source_id: Optional[str] = None
    step_results: List[ExecutionStepResult] = []
    current_step_index: Optional[int] = None
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    tenant_id: str
    triggered_by: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class ExecutePlaybookRequest(BaseModel):
    payload: Optional[Dict[str, Any]] = Field(None, description="Input payload for the playbook execution")
    trigger_type: Optional[str] = Field("manual", description="Type of trigger initiating this execution")
    trigger_source_id: Optional[str] = Field(None, description="ID of the alert/incident that triggered this")

class ExecutionApproveRequest(BaseModel):
    comment: Optional[str] = Field(None, max_length=2000)

class ExecutionCancelRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Action Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ActionResponse(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    category: Optional[str] = None
    required_parameters: List[Dict[str, Any]] = []
    optional_parameters: List[Dict[str, Any]] = []
    supported_integrations: List[str] = []
    is_destructive: bool = False
    requires_approval: bool = False
    timeout_seconds: int = 300

class ActionTestRequest(BaseModel):
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target: Optional[str] = Field(None, description="Target resource identifier")

class ActionTestResponse(BaseModel):
    action_name: str
    success: bool
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Integration Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class IntegrationConfigModel(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    integration_type: IntegrationType
    description: Optional[str] = Field(None, max_length=1000)
    auth_type: IntegrationAuthType = IntegrationAuthType.API_KEY
    endpoint_url: Optional[str] = Field(None, max_length=2048)
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    verify_ssl: bool = True
    timeout_seconds: int = Field(30, ge=1, le=300)
    enabled: bool = True
    tags: List[str] = []
    metadata: Optional[Dict[str, Any]] = None

class IntegrationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    endpoint_url: Optional[str] = Field(None, max_length=2048)
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    verify_ssl: Optional[bool] = None
    timeout_seconds: Optional[int] = Field(None, ge=1, le=300)
    enabled: Optional[bool] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class IntegrationResponse(BaseModel):
    id: str
    name: str
    integration_type: IntegrationType
    description: Optional[str] = None
    auth_type: IntegrationAuthType
    endpoint_url: Optional[str] = None
    enabled: bool = True
    tags: List[str] = []
    metadata: Optional[Dict[str, Any]] = None
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_tested_at: Optional[datetime] = None
    connection_status: Optional[str] = None

    class Config:
        from_attributes = True

class IntegrationTestResponse(BaseModel):
    integration_id: str
    success: bool
    message: str
    response_time_ms: float = 0.0
    details: Optional[Dict[str, Any]] = None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Template Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PlaybookTemplateResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = []
    steps: List[PlaybookStep]
    triggers: List[PlaybookTrigger] = []
    severity: str = "medium"
    estimated_duration_seconds: Optional[float] = None
    use_case: Optional[str] = None
    prerequisites: List[str] = []

class TemplateInstantiateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    parameter_overrides: Optional[Dict[str, Any]] = None
    enabled: bool = False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Built-in action catalog
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

BUILTIN_ACTIONS: List[ActionResponse] = [
    ActionResponse(name="block_ip", display_name="Block IP Address", category="network",
                   description="Add an IP address to the blocklist at the firewall/EDR level",
                   required_parameters=[{"name": "ip_address", "type": "string", "description": "IPv4 or IPv6 address to block"}],
                   optional_parameters=[{"name": "duration_minutes", "type": "integer", "description": "Duration to block; 0 for permanent"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="unblock_ip", display_name="Unblock IP Address", category="network",
                   description="Remove an IP address from the blocklist",
                   required_parameters=[{"name": "ip_address", "type": "string"}],
                   is_destructive=False, requires_approval=True),
    ActionResponse(name="disable_account", display_name="Disable User Account", category="identity",
                   description="Disable a user account in the identity provider",
                   required_parameters=[{"name": "user_id", "type": "string"}, {"name": "reason", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="enable_account", display_name="Enable User Account", category="identity",
                   description="Re-enable a previously disabled user account",
                   required_parameters=[{"name": "user_id", "type": "string"}],
                   is_destructive=False, requires_approval=True),
    ActionResponse(name="restart_service", display_name="Restart Service", category="infrastructure",
                   description="Restart a system service on a specified endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}, {"name": "service_name", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="kill_process", display_name="Kill Process", category="endpoint",
                   description="Terminate a running process by PID or name",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}, {"name": "process_identifier", "type": "string"}],
                   optional_parameters=[{"name": "identifier_type", "type": "string", "description": "pid or name"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="isolate_endpoint", display_name="Isolate Endpoint", category="endpoint",
                   description="Network-isolate an endpoint from the rest of the network",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}, {"name": "reason", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="release_endpoint", display_name="Release Endpoint", category="endpoint",
                   description="Remove network isolation from an endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}],
                   is_destructive=False, requires_approval=True),
    ActionResponse(name="collect_forensics", display_name="Collect Forensics", category="forensics",
                   description="Collect forensic artifacts from an endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}],
                   optional_parameters=[{"name": "artifact_types", "type": "array", "description": "Types: memory, disk, network, processes, registry"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="notify_teams", display_name="Send Teams Notification", category="messaging",
                   description="Send an alert notification to a Microsoft Teams channel",
                   required_parameters=[{"name": "message", "type": "string"}],
                   optional_parameters=[{"name": "channel", "type": "string"}, {"name": "severity", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="notify_slack", display_name="Send Slack Notification", category="messaging",
                   description="Send an alert notification to a Slack channel",
                   required_parameters=[{"name": "message", "type": "string"}],
                   optional_parameters=[{"name": "channel", "type": "string"}, {"name": "severity", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="open_jira", display_name="Create Jira Ticket", category="ticketing",
                   description="Create a new Jira issue for tracking",
                   required_parameters=[{"name": "summary", "type": "string"}, {"name": "project_key", "type": "string"}],
                   optional_parameters=[{"name": "description", "type": "string"}, {"name": "issue_type", "type": "string"}, {"name": "priority", "type": "string"}, {"name": "labels", "type": "array"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="open_servicenow", display_name="Create ServiceNow Ticket", category="ticketing",
                   description="Create a new ServiceNow incident or change request",
                   required_parameters=[{"name": "short_description", "type": "string"}],
                   optional_parameters=[{"name": "description", "type": "string"}, {"name": "category", "type": "string"}, {"name": "impact", "type": "string"}, {"name": "urgency", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="execute_script", display_name="Execute Script", category="automation",
                   description="Execute a custom script on a target endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}, {"name": "script_content", "type": "string"}],
                   optional_parameters=[{"name": "interpreter", "type": "string", "description": "powershell, bash, python"}, {"name": "timeout_seconds", "type": "integer"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="run_ansible", display_name="Run Ansible Playbook", category="automation",
                   description="Execute an Ansible playbook against target hosts",
                   required_parameters=[{"name": "playbook_name", "type": "string"}, {"name": "inventory", "type": "string"}],
                   optional_parameters=[{"name": "extra_vars", "type": "object"}, {"name": "limit", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="send_email", display_name="Send Email", category="messaging",
                   description="Send an email notification",
                   required_parameters=[{"name": "to", "type": "string"}, {"name": "subject", "type": "string"}, {"name": "body", "type": "string"}],
                   optional_parameters=[{"name": "cc", "type": "string"}, {"name": "priority", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="quarantine_file", display_name="Quarantine File", category="endpoint",
                   description="Move a suspicious file to quarantine on an endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}, {"name": "file_path", "type": "string"}],
                   optional_parameters=[{"name": "sha256", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="add_firewall_rule", display_name="Add Firewall Rule", category="network",
                   description="Add a temporary firewall rule to block or allow traffic",
                   required_parameters=[{"name": "action", "type": "string", "description": "block or allow"}, {"name": "source", "type": "string"}, {"name": "destination", "type": "string"}],
                   optional_parameters=[{"name": "protocol", "type": "string"}, {"name": "port", "type": "integer"}, {"name": "duration_minutes", "type": "integer"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="remove_firewall_rule", display_name="Remove Firewall Rule", category="network",
                   description="Remove a previously added temporary firewall rule",
                   required_parameters=[{"name": "rule_id", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="scan_endpoint", display_name="Scan Endpoint", category="endpoint",
                   description="Trigger a security scan on a specified endpoint",
                   required_parameters=[{"name": "endpoint_id", "type": "string"}],
                   optional_parameters=[{"name": "scan_type", "type": "string", "description": "quick, full, custom"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="update_ticket", display_name="Update Ticket", category="ticketing",
                   description="Update an existing ticket in Jira or ServiceNow",
                   required_parameters=[{"name": "ticket_id", "type": "string"}, {"name": "updates", "type": "object"}],
                   optional_parameters=[{"name": "system", "type": "string", "description": "jira or servicenow"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="add_to_watchlist", display_name="Add to Watchlist", category="intelligence",
                   description="Add an indicator to the threat intelligence watchlist",
                   required_parameters=[{"name": "indicator", "type": "string"}, {"name": "indicator_type", "type": "string"}],
                   optional_parameters=[{"name": "description", "type": "string"}, {"name": "severity", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="enrich_ip", display_name="Enrich IP Address", category="intelligence",
                   description="Enrich an IP address with threat intelligence data",
                   required_parameters=[{"name": "ip_address", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="enrich_domain", display_name="Enrich Domain", category="intelligence",
                   description="Enrich a domain with threat intelligence data",
                   required_parameters=[{"name": "domain", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="enrich_hash", display_name="Enrich File Hash", category="intelligence",
                   description="Enrich a file hash with threat intelligence data",
                   required_parameters=[{"name": "hash", "type": "string"}],
                   optional_parameters=[{"name": "hash_type", "type": "string", "description": "md5, sha1, sha256"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="suspend_user", display_name="Suspend User", category="identity",
                   description="Suspend a user's access across all systems",
                   required_parameters=[{"name": "user_id", "type": "string"}, {"name": "reason", "type": "string"}],
                   is_destructive=True, requires_approval=True),
    ActionResponse(name="force_password_reset", display_name="Force Password Reset", category="identity",
                   description="Force a user to reset their password on next login",
                   required_parameters=[{"name": "user_id", "type": "string"}],
                   optional_parameters=[{"name": "reason", "type": "string"}],
                   is_destructive=False, requires_approval=False),
    ActionResponse(name="revoke_session", display_name="Revoke User Session", category="identity",
                   description="Revoke all active sessions for a user",
                   required_parameters=[{"name": "user_id", "type": "string"}],
                   optional_parameters=[{"name": "reason", "type": "string"}],
                   is_destructive=True, requires_approval=True),
]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Built-in playbook templates
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

BUILTIN_TEMPLATES: List[PlaybookTemplateResponse] = [
    PlaybookTemplateResponse(
        id="tpl-phishing-response", name="Phishing Email Response",
        description="Standard response workflow for reported phishing emails",
        category="incident_response", tags=["phishing", "email", "triage"],
        severity="high",
        steps=[
            PlaybookStep(name="extract_indicators", action="enrich_domain",
                          parameters={"domain": "{{ payload.sender_domain }}"},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=False,
                          approver_roles=[], depends_on=[], description="Extract and enrich sender domain"),
            PlaybookStep(name="search_iocs", action="enrich_ip",
                          parameters={"ip_address": "{{ payload.source_ip }}"},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=False,
                          approver_roles=[], depends_on=[], description="Look up source IP in threat intel"),
            PlaybookStep(name="notify_soc", action="notify_slack",
                          parameters={"message": "Phishing alert: {{ payload.subject }}", "severity": "high"},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=60, requires_approval=False,
                          approver_roles=[], depends_on=[], description="Notify SOC channel"),
            PlaybookStep(name="block_sender", action="block_ip",
                          parameters={"ip_address": "{{ payload.source_ip }}", "duration_minutes": 1440},
                          condition="enrichment.score > 70", on_failure="continue", retry_count=1,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=True,
                          approver_roles=["soc_manager"], depends_on=["search_iocs"],
                          description="Block sender IP if threat score is high"),
        ],
        triggers=[PlaybookTrigger(trigger_type=PlaybookTriggerType.ALERT,
                                  condition={"alert_type": "phishing"})],
        estimated_duration_seconds=420,
        use_case="Automated phishing email triage and response",
        prerequisites=["Email integration configured", "Slack/Teams integration configured"],
    ),
    PlaybookTemplateResponse(
        id="tpl-malware-response", name="Malware Detection Response",
        description="Automated response workflow for malware detection alerts",
        category="incident_response", tags=["malware", "endpoint", "containment"],
        severity="critical",
        steps=[
            PlaybookStep(name="isolate_host", action="isolate_endpoint",
                          parameters={"endpoint_id": "{{ payload.endpoint_id }}", "reason": "Malware detected: {{ payload.threat_name }}"},
                          condition=None, on_failure="stop", retry_count=2,
                          retry_delay_seconds=30, timeout_seconds=300, requires_approval=True,
                          approver_roles=["soc_manager", "incident_responder"], depends_on=[],
                          description="Isolate affected endpoint from network"),
            PlaybookStep(name="quarantine_threat", action="quarantine_file",
                          parameters={"endpoint_id": "{{ payload.endpoint_id }}", "file_path": "{{ payload.file_path }}", "sha256": "{{ payload.file_hash }}"},
                          condition=None, on_failure="continue", retry_count=1,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=False,
                          approver_roles=[], depends_on=["isolate_host"],
                          description="Quarantine the malicious file"),
            PlaybookStep(name="collect_artifacts", action="collect_forensics",
                          parameters={"endpoint_id": "{{ payload.endpoint_id }}", "artifact_types": ["memory", "disk"]},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=600, requires_approval=False,
                          approver_roles=[], depends_on=["isolate_host"],
                          description="Collect forensic artifacts for analysis"),
            PlaybookStep(name="create_ticket", action="open_servicenow",
                          parameters={"short_description": "Malware Incident: {{ payload.threat_name }} on {{ payload.endpoint_name }}",
                                      "category": "Security", "impact": "High", "urgency": "High"},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=False,
                          approver_roles=[], depends_on=[], description="Create incident ticket"),
        ],
        triggers=[PlaybookTrigger(trigger_type=PlaybookTriggerType.ALERT,
                                  condition={"alert_type": "malware"}),
                   PlaybookTrigger(trigger_type=PlaybookTriggerType.INCIDENT,
                                    condition={"incident_type": "malware"})],
        estimated_duration_seconds=1140,
        use_case="Automated malware containment and forensic collection",
        prerequisites=["EDR integration configured", "ServiceNow/Jira integration"],
    ),
    PlaybookTemplateResponse(
        id="tpl-bruteforce-response", name="Brute Force Response",
        description="Response workflow for detected brute force attacks",
        category="incident_response", tags=["bruteforce", "authentication", "containment"],
        severity="high",
        steps=[
            PlaybookStep(name="notify_teams_channel", action="notify_slack",
                          parameters={"message": "Brute force attack detected from {{ payload.source_ip }} against user {{ payload.target_user }}", "severity": "high"},
                          condition=None, on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=60, requires_approval=False,
                          approver_roles=[], depends_on=[], description="Alert the SOC team"),
            PlaybookStep(name="block_source_ip", action="block_ip",
                          parameters={"ip_address": "{{ payload.source_ip }}", "duration_minutes": 60},
                          condition=None, on_failure="stop", retry_count=1,
                          retry_delay_seconds=30, timeout_seconds=120, requires_approval=True,
                          approver_roles=["soc_manager"], depends_on=[],
                          description="Block the attacking IP address"),
            PlaybookStep(name="force_password_reset_target", action="force_password_reset",
                          parameters={"user_id": "{{ payload.target_user }}", "reason": "Suspected brute force compromise"},
                          condition="payload.attempts > 50", on_failure="continue", retry_count=0,
                          retry_delay_seconds=30, timeout_seconds=60, requires_approval=False,
                          approver_roles=[], depends_on=[],
                          description="Force password reset for the targeted account"),
        ],
        triggers=[PlaybookTrigger(trigger_type=PlaybookTriggerType.ALERT,
                                  condition={"alert_type": "brute_force"})],
        estimated_duration_seconds=240,
        use_case="Automated brute force detection and response",
        prerequisites=["Firewall integration", "Identity provider integration"],
    ),
]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Playbook CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post(
    "/playbooks",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Playbook",
    description="Create a new SOAR playbook with triggers and response steps.",
)
async def create_playbook(
    playbook: PlaybookCreate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    existing = await db.execute(
        select(Playbook).where(
            and_(Playbook.tenant_id == tid, Playbook.name == playbook.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Playbook '{playbook.name}' already exists",
        )

    steps_json = [s.model_dump() for s in playbook.steps]
    conditions_json = []
    for t in playbook.triggers:
        entry = {"trigger_type": t.trigger_type.value}
        if t.condition:
            entry["condition"] = t.condition
        if t.schedule:
            entry["schedule"] = t.schedule
        conditions_json.append(entry)

    trigger_type = playbook.triggers[0].trigger_type.value if playbook.triggers else "manual"

    version_int = 1
    try:
        parts = playbook.version.split(".")
        version_int = int(parts[0])
    except Exception:
        version_int = 1

    db_playbook = Playbook(
        tenant_id=tid,
        name=playbook.name,
        description=playbook.description,
        trigger_type=trigger_type,
        status="active" if playbook.enabled else "draft",
        steps=steps_json,
        conditions=conditions_json,
        tags=playbook.tags,
        version=version_int,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_playbook)
    await db.flush()
    await db.refresh(db_playbook)

    await _audit_log(db, current_user, "playbook.created", "playbook", db_playbook.id,
                     {"name": playbook.name, "steps_count": len(steps_json)})
    return _build_playbook_response(db_playbook)


@router.get(
    "/playbooks",
    response_model=PaginatedResponse,
    summary="List Playbooks",
    description="List all SOAR playbooks with filtering, search, and pagination.",
)
async def list_playbooks(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    status_val: Optional[PlaybookStatus] = Query(None, alias="status"),
    trigger_type: Optional[PlaybookTriggerType] = Query(None),
    severity: Optional[str] = Query(None, pattern=r"^(low|medium|high|critical)$"),
    search: Optional[str] = Query(None, description="Search in name, description, tags"),
    tags: Optional[List[str]] = Query(None),
    enabled: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    tid = _uuid(tenant_id)
    conditions = [Playbook.tenant_id == tid]

    if status_val:
        conditions.append(Playbook.status == status_val.value)
    if trigger_type:
        conditions.append(Playbook.trigger_type == trigger_type.value)
    if enabled is not None:
        conditions.append(Playbook.status == ("active" if enabled else "disabled"))
    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(Playbook.name.ilike(search_term), Playbook.description.ilike(search_term))
        )
    if tags:
        conditions.append(Playbook.tags.overlap(tags))

    count_q = select(func.count()).select_from(Playbook).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(Playbook, sort_by, Playbook.created_at)
    order_fn = desc if sort_order == "desc" else asc

    q = select(Playbook).where(and_(*conditions)).order_by(order_fn(sort_col)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    playbooks = result.scalars().all()

    return _paginated(
        [_build_playbook_response(pb) for pb in playbooks],
        total, page, page_size,
    )


@router.get(
    "/playbooks/templates",
    response_model=List[PlaybookTemplateResponse],
    summary="Get Playbook Templates",
    description="Get all built-in playbook templates for common use cases.",
)
async def list_playbook_templates(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    category: Optional[str] = Query(None),
):
    templates = BUILTIN_TEMPLATES
    if category:
        templates = [t for t in templates if t.category == category]
    return templates


@router.post(
    "/playbooks/templates/{template_id}/instantiate",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create from Template",
    description="Create a new playbook from a built-in or custom template.",
)
async def instantiate_from_template(
    template_id: str,
    request: TemplateInstantiateRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    template = next((t for t in BUILTIN_TEMPLATES if t.id == template_id), None)
    if not template:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

    tid = _uuid(tenant_id)
    existing = await db.execute(
        select(Playbook).where(
            and_(Playbook.tenant_id == tid, Playbook.name == request.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Playbook '{request.name}' already exists",
        )

    steps_json = [s.model_dump() for s in template.steps]
    conditions_json = []
    for t in template.triggers:
        entry = {"trigger_type": t.trigger_type.value}
        if t.condition:
            entry["condition"] = t.condition
        if t.schedule:
            entry["schedule"] = t.schedule
        conditions_json.append(entry)

    trigger_type = template.triggers[0].trigger_type.value if template.triggers else "manual"

    db_playbook = Playbook(
        tenant_id=tid,
        name=request.name,
        description=request.description or template.description,
        trigger_type=trigger_type,
        status="active" if request.enabled else "draft",
        steps=steps_json,
        conditions=conditions_json,
        tags=template.tags,
        version=1,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_playbook)
    await db.flush()
    await db.refresh(db_playbook)

    await _audit_log(db, current_user, "playbook.instantiated_from_template", "playbook", db_playbook.id,
                     {"template_id": template_id, "name": request.name})
    return _build_playbook_response(db_playbook)


@router.post(
    "/playbooks/import",
    response_model=PlaybookImportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Import Playbook",
    description="Import a playbook from JSON or YAML format.",
)
async def import_playbook(
    request: PlaybookImportRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    try:
        data = json.loads(request.content)
    except json.JSONDecodeError:
        try:
            import yaml
            data = yaml.safe_load(request.content)
        except Exception:
            return PlaybookImportResponse(imported=False, message="Unable to parse playbook content")

    name = data.get("name", f"imported-playbook-{uuid_mod.uuid4().hex[:8]}")
    tid = _uuid(tenant_id)

    existing = await db.execute(
        select(Playbook).where(and_(Playbook.tenant_id == tid, Playbook.name == name))
    )
    existing_pb = existing.scalar_one_or_none()
    if existing_pb:
        if request.overwrite_existing:
            existing_pb.steps = data.get("steps", [])
            existing_pb.conditions = data.get("conditions", [])
            existing_pb.description = data.get("description")
            existing_pb.tags = data.get("tags", [])
            existing_pb.updated_at = datetime.now(timezone.utc)
            await db.flush()
            await _audit_log(db, current_user, "playbook.imported_overwrite", "playbook", existing_pb.id,
                             {"name": name})
            return PlaybookImportResponse(imported=True, playbook_id=str(existing_pb.id),
                                          message="Playbook updated via import")
        else:
            return PlaybookImportResponse(imported=False, message=f"Playbook '{name}' already exists")

    db_pb = Playbook(
        tenant_id=tid,
        name=name,
        description=data.get("description"),
        trigger_type=data.get("trigger_type", "manual"),
        status="draft",
        steps=data.get("steps", []),
        conditions=data.get("conditions", []),
        tags=data.get("tags", []),
        version=data.get("version", 1),
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_pb)
    await db.flush()
    await db.refresh(db_pb)

    await _audit_log(db, current_user, "playbook.imported", "playbook", db_pb.id, {"name": name})
    return PlaybookImportResponse(imported=True, playbook_id=str(db_pb.id), message="Playbook imported successfully")


@router.get(
    "/playbooks/{playbook_id}",
    response_model=PlaybookResponse,
    summary="Get Playbook Detail",
    description="Retrieve full details of a single playbook.",
)
async def get_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return _build_playbook_response(pb)


@router.patch(
    "/playbooks/{playbook_id}",
    response_model=PlaybookResponse,
    summary="Update Playbook",
    description="Partially update a playbook.",
)
async def update_playbook(
    playbook_id: str,
    update: PlaybookUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    update_data = update.model_dump(exclude_unset=True)

    if "name" in update_data:
        pb.name = update_data["name"]
    if "description" in update_data:
        pb.description = update_data["description"]
    if "tags" in update_data:
        pb.tags = update_data["tags"]
    if "steps" in update_data:
        pb.steps = [s if isinstance(s, dict) else s.model_dump() for s in update_data["steps"]]
    if "triggers" in update_data:
        conditions = []
        for t in update_data["triggers"]:
            if isinstance(t, dict):
                conditions.append(t)
            else:
                entry = {"trigger_type": t.trigger_type.value if hasattr(t.trigger_type, "value") else t.get("trigger_type", "manual")}
                if hasattr(t, "condition") and t.condition:
                    entry["condition"] = t.condition
                if hasattr(t, "schedule") and t.schedule:
                    entry["schedule"] = t.schedule
                conditions.append(entry)
        pb.conditions = conditions
        if conditions:
            pb.trigger_type = conditions[0].get("trigger_type", pb.trigger_type)
    if "enabled" in update_data:
        pb.status = "active" if update_data["enabled"] else "disabled"
    if "status" in update_data and update_data["status"]:
        pb.status = update_data["status"].value
    if "version" in update_data:
        try:
            pb.version = int(update_data["version"].split(".")[0])
        except Exception:
            pass

    pb.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(pb)

    await _audit_log(db, current_user, "playbook.updated", "playbook", pb.id,
                     {"updated_fields": list(update_data.keys())})
    return _build_playbook_response(pb)


@router.delete(
    "/playbooks/{playbook_id}",
    response_model=MessageResponse,
    summary="Delete Playbook",
    description="Delete a playbook permanently.",
)
async def delete_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    active_exec = await db.execute(
        select(func.count(PlaybookExecution.id)).where(
            and_(
                PlaybookExecution.playbook_id == pid,
                PlaybookExecution.status.in_(["pending", "running", "awaiting_approval"]),
            )
        )
    )
    if (active_exec.scalar() or 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete playbook with active executions",
        )

    await db.delete(pb)
    await db.flush()

    await _audit_log(db, current_user, "playbook.deleted", "playbook", pid, {"name": pb.name})
    return MessageResponse(message="Playbook deleted successfully", detail=f"Playbook '{pb.name}' removed")


@router.get(
    "/playbooks/{playbook_id}/export",
    response_model=PlaybookResponse,
    summary="Export Playbook",
    description="Export a playbook as JSON or YAML.",
)
async def export_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    format: ExportFormat = Query(ExportFormat.JSON, description="Export format"),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return _build_playbook_response(pb)


@router.post(
    "/playbooks/{playbook_id}/clone",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Clone Playbook",
    description="Create a copy of an existing playbook with a new name.",
)
async def clone_playbook(
    playbook_id: str,
    request: PlaybookCloneRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    cloned = Playbook(
        tenant_id=tid,
        name=request.name,
        description=request.description or source.description,
        trigger_type=source.trigger_type,
        status="draft",
        steps=source.steps,
        conditions=source.conditions,
        tags=list(source.tags or []),
        version=1,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(cloned)
    await db.flush()
    await db.refresh(cloned)

    await _audit_log(db, current_user, "playbook.cloned", "playbook", cloned.id,
                     {"source_id": str(source.id), "new_name": request.name})
    return _build_playbook_response(cloned)


@router.get(
    "/playbooks/{playbook_id}/test",
    response_model=PlaybookTestResponse,
    summary="Test Playbook (Dry Run)",
    description="Validate a playbook without executing it. Checks step actions, dependencies, and logic.",
)
async def test_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    steps = pb.steps or []
    errors = []
    warnings = []
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        action = step.get("action", "")
        if action and action not in VALID_ACTION_NAMES:
            errors.append({"step_index": i, "step_name": step.get("name", "unknown"),
                           "error": f"Unknown action: {action}"})
        if step.get("requires_approval") and not step.get("approver_roles"):
            warnings.append(f"Step '{step.get('name', i)}' requires approval but has no approver roles defined")

    return PlaybookTestResponse(
        playbook_id=str(pb.id),
        valid=len(errors) == 0,
        step_count=len(steps),
        validation_errors=errors,
        estimated_duration_seconds=sum(s.get("timeout_seconds", 300) for s in steps if isinstance(s, dict)),
        warnings=warnings,
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Playbook Enable/Disable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post(
    "/playbooks/{playbook_id}/enable",
    response_model=PlaybookResponse,
    summary="Enable Playbook",
    description="Enable a playbook for automatic or manual execution.",
)
async def enable_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    pb.status = "active"
    pb.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(pb)

    await _audit_log(db, current_user, "playbook.enabled", "playbook", pb.id)
    return _build_playbook_response(pb)


@router.post(
    "/playbooks/{playbook_id}/disable",
    response_model=PlaybookResponse,
    summary="Disable Playbook",
    description="Disable a playbook to prevent execution.",
)
async def disable_playbook(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    pb.status = "disabled"
    pb.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(pb)

    await _audit_log(db, current_user, "playbook.disabled", "playbook", pb.id)
    return _build_playbook_response(pb)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

async def _resolve_template(value: str, context: Dict[str, Any]) -> str:
    """Simple template variable resolver: replaces {{ var }} patterns."""
    import re as _re_mod
    def _replace(match):
        var_path = match.group(1).strip()
        parts = var_path.split(".")
        current = context
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, "")
            else:
                return ""
        return str(current) if current is not None else ""
    return _re_mod.sub(r"\{\{\s*(.+?)\s*\}\}", _replace, value)


def _resolve_params(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    resolved = {}
    for key, value in params.items():
        if isinstance(value, str):
            resolved[key] = _resolve_template(value, context)
        elif isinstance(value, dict):
            resolved[key] = _resolve_params(value, context)
        elif isinstance(value, list):
            resolved[key] = [_resolve_template(v, context) if isinstance(v, str) else v for v in value]
        else:
            resolved[key] = value
    return resolved


@router.post(
    "/playbooks/{playbook_id}/execute",
    response_model=ExecutionResponse,
    summary="Execute Playbook",
    description="Manually execute a playbook with an optional payload. Steps are iterated and real actions are called via SOARExecutor.",
)
async def execute_playbook(
    playbook_id: str,
    request: ExecutePlaybookRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    result = await db.execute(
        select(Playbook).where(and_(Playbook.id == pid, Playbook.tenant_id == tid))
    )
    pb = result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    if pb.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Playbook is not active",
        )

    payload = request.payload or {}
    context = {"payload": payload}

    steps = pb.steps or []
    step_results = []
    for i, s in enumerate(steps):
        if not isinstance(s, dict):
            continue
        step_results.append({
            "step_id": s.get("id", f"step-{i}"),
            "step_name": s.get("name", f"step-{i}"),
            "action": s.get("action", ""),
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "duration_seconds": None,
            "output": None,
            "error_message": None,
            "retry_attempts": 0,
            "requires_approval": s.get("requires_approval", False),
            "approved_by": None,
            "approved_at": None,
        })

    incident_id = None
    if request.trigger_source_id:
        try:
            incident_id = _uuid(request.trigger_source_id)
        except Exception:
            pass

    uid = _uuid(current_user["user_id"]) if current_user.get("user_id") else None
    execution = PlaybookExecution(
        tenant_id=tid,
        playbook_id=pid,
        incident_id=incident_id,
        status="running",
        trigger=request.trigger_type or "manual",
        triggered_by=uid,
        steps_results=step_results,
        current_step=0,
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)

    pb.execution_count = (pb.execution_count or 0) + 1
    pb.last_executed_at = datetime.now(timezone.utc)
    await db.flush()

    from app.services.soar_executor import get_soar_executor
    executor = get_soar_executor()

    now = datetime.now(timezone.utc)
    step_dep_results: Dict[str, bool] = {}

    for i, step_data in enumerate(steps):
        if not isinstance(step_data, dict):
            continue

        action = step_data.get("action", "")
        resolved_params = _resolve_params(step_data.get("parameters", {}), context)
        condition = step_data.get("condition")
        on_failure = step_data.get("on_failure", "stop")
        depends_on = step_data.get("depends_on", [])
        requires_approval = step_data.get("requires_approval", False)

        step_results[i]["started_at"] = now.isoformat()

        if condition:
            dep_failures = [d for d in depends_on if step_dep_results.get(d) is False]
            if dep_failures:
                step_results[i]["status"] = "skipped"
                step_results[i]["error_message"] = f"Skipped: dependency {dep_failures[0]} failed"
                step_results[i]["completed_at"] = datetime.now(timezone.utc).isoformat()
                step_dep_results[step_results[i]["step_id"]] = False
                if on_failure == "stop":
                    execution.status = "failed"
                    execution.error_message = f"Step '{step_data.get('name', i)}' skipped due to failed dependency"
                    execution.completed_at = datetime.now(timezone.utc)
                    break
                continue

        if requires_approval:
            step_results[i]["status"] = "awaiting_approval"
            execution.status = "awaiting_approval"
            execution.current_step = i
            execution.steps_results = step_results
            await db.flush()
            await _audit_log(db, current_user, "playbook.execution_running", "playbook_execution", execution.id,
                             {"playbook_id": str(pid), "status": "awaiting_approval", "current_step": i})
            return _build_execution_response(execution)

        step_start = datetime.now(timezone.utc)
        step_results[i]["status"] = "running"
        execution.current_step = i
        execution.steps_results = step_results
        await db.flush()

        action_result = await executor.execute_action(action, resolved_params)

        step_end = datetime.now(timezone.utc)
        duration = (step_end - step_start).total_seconds()

        if action_result.get("success"):
            step_results[i]["status"] = "completed"
            step_results[i]["output"] = action_result
            step_dep_results[step_results[i]["step_id"]] = True
            context[action] = action_result
            context[step_data.get("name", f"step_{i}")] = action_result
            pb.success_count = (pb.success_count or 0) + 1
        else:
            step_results[i]["status"] = "failed"
            step_results[i]["error_message"] = action_result.get("error", action_result.get("message", "Unknown error"))
            step_results[i]["output"] = action_result
            step_dep_results[step_results[i]["step_id"]] = False

            if on_failure == "stop":
                step_results[i]["completed_at"] = step_end.isoformat()
                step_results[i]["duration_seconds"] = duration
                execution.status = "failed"
                execution.error_message = f"Step '{step_data.get('name', f'step-{i}')}' failed: {action_result.get('error', 'Unknown')}"
                execution.completed_at = step_end
                execution.steps_results = step_results
                await db.flush()
                await _audit_log(db, current_user, "playbook.execution_failed", "playbook_execution", execution.id,
                                 {"playbook_id": str(pid), "failed_step": i, "action": action})
                return _build_execution_response(execution)

        step_results[i]["completed_at"] = step_end.isoformat()
        step_results[i]["duration_seconds"] = round(duration, 3)

    if execution.status == "running":
        execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        execution.current_step = None
    elif execution.status != "failed":
        execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        execution.current_step = None

    execution.steps_results = step_results
    await db.flush()
    await db.refresh(execution)

    await _audit_log(db, current_user, "playbook.execution_completed", "playbook_execution", execution.id,
                     {"playbook_id": str(pid), "final_status": execution.status})
    return _build_execution_response(execution)


@router.get(
    "/playbooks/{playbook_id}/executions",
    response_model=PaginatedResponse,
    summary="Get Execution History",
    description="List execution history for a specific playbook.",
)
async def list_playbook_executions(
    playbook_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    status_val: Optional[ExecutionStatus] = Query(None, alias="status"),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    tid = _uuid(tenant_id)
    pid = _uuid(playbook_id)
    conditions = [PlaybookExecution.tenant_id == tid, PlaybookExecution.playbook_id == pid]

    if status_val:
        conditions.append(PlaybookExecution.status == status_val.value)
    if start_time:
        conditions.append(PlaybookExecution.created_at >= start_time)
    if end_time:
        conditions.append(PlaybookExecution.created_at <= end_time)

    count_q = select(func.count()).select_from(PlaybookExecution).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(PlaybookExecution, sort_by, PlaybookExecution.created_at)
    order_fn = desc if sort_order == "desc" else asc

    q = select(PlaybookExecution).where(and_(*conditions)).options(
        *([])  # eager load handled by relationship
    ).order_by(order_fn(sort_col)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    executions = result.scalars().all()

    return _paginated(
        [_build_execution_response(e) for e in executions],
        total, page, page_size,
    )


@router.get(
    "/executions/{execution_id}",
    response_model=ExecutionResponse,
    summary="Get Execution Detail",
    description="Retrieve full details of a playbook execution including step results.",
)
async def get_execution_detail(
    execution_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    eid = _uuid(execution_id)
    result = await db.execute(
        select(PlaybookExecution).where(
            and_(PlaybookExecution.id == eid, PlaybookExecution.tenant_id == tid)
        )
    )
    exec_data = result.scalar_one_or_none()
    if not exec_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return _build_execution_response(exec_data)


@router.post(
    "/executions/{execution_id}/approve",
    response_model=ExecutionResponse,
    summary="Approve Pending Step",
    description="Approve a pending approval step in a running execution.",
)
async def approve_execution_step(
    execution_id: str,
    request: ExecutionApproveRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    eid = _uuid(execution_id)
    result = await db.execute(
        select(PlaybookExecution).where(
            and_(PlaybookExecution.id == eid, PlaybookExecution.tenant_id == tid)
        )
    )
    exec_data = result.scalar_one_or_none()
    if not exec_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    if exec_data.status != "awaiting_approval":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Execution is not awaiting approval",
        )

    now = datetime.now(timezone.utc)
    steps = list(exec_data.steps_results or [])
    current_idx = exec_data.current_step or 0

    if 0 <= current_idx < len(steps):
        steps[current_idx]["status"] = "completed"
        steps[current_idx]["approved_by"] = current_user.get("user_id")
        steps[current_idx]["approved_at"] = now.isoformat()
        steps[current_idx]["completed_at"] = now

    next_idx = current_idx + 1
    if next_idx >= len(steps):
        exec_data.status = "completed"
        exec_data.completed_at = now
        exec_data.current_step = None
    else:
        steps[next_idx]["status"] = "running"
        steps[next_idx]["started_at"] = now
        exec_data.current_step = next_idx
        if steps[next_idx].get("requires_approval"):
            exec_data.status = "awaiting_approval"
        else:
            exec_data.status = "running"

    exec_data.steps_results = steps
    await db.flush()
    await db.refresh(exec_data)

    await _audit_log(db, current_user, "execution.step_approved", "playbook_execution", exec_data.id,
                     {"comment": request.comment})
    return _build_execution_response(exec_data)


@router.post(
    "/executions/{execution_id}/reject",
    response_model=ExecutionResponse,
    summary="Reject Pending Step",
    description="Reject a pending approval step, which fails the execution or skips the step.",
)
async def reject_execution_step(
    execution_id: str,
    request: ExecutionApproveRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    eid = _uuid(execution_id)
    result = await db.execute(
        select(PlaybookExecution).where(
            and_(PlaybookExecution.id == eid, PlaybookExecution.tenant_id == tid)
        )
    )
    exec_data = result.scalar_one_or_none()
    if not exec_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    if exec_data.status != "awaiting_approval":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Execution is not awaiting approval",
        )

    now = datetime.now(timezone.utc)
    steps = list(exec_data.steps_results or [])
    current_idx = exec_data.current_step or 0

    if 0 <= current_idx < len(steps):
        steps[current_idx]["status"] = "failed"
        steps[current_idx]["error_message"] = f"Rejected: {request.comment or 'No reason provided'}"
        steps[current_idx]["completed_at"] = now

    exec_data.status = "failed"
    exec_data.completed_at = now
    exec_data.error_message = f"Step rejected by {current_user.get('user_id')}: {request.comment or ''}"
    exec_data.steps_results = steps

    await db.flush()
    await db.refresh(exec_data)

    await _audit_log(db, current_user, "execution.step_rejected", "playbook_execution", exec_data.id,
                     {"comment": request.comment})
    return _build_execution_response(exec_data)


@router.post(
    "/executions/{execution_id}/cancel",
    response_model=ExecutionResponse,
    summary="Cancel Execution",
    description="Cancel a running or awaiting-approval execution.",
)
async def cancel_execution(
    execution_id: str,
    request: ExecutionCancelRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    eid = _uuid(execution_id)
    result = await db.execute(
        select(PlaybookExecution).where(
            and_(PlaybookExecution.id == eid, PlaybookExecution.tenant_id == tid)
        )
    )
    exec_data = result.scalar_one_or_none()
    if not exec_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    if exec_data.status not in ("running", "pending", "awaiting_approval"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Execution is not in a cancellable state",
        )

    now = datetime.now(timezone.utc)
    exec_data.status = "cancelled"
    exec_data.completed_at = now
    exec_data.error_message = f"Cancelled by {current_user.get('user_id')}: {request.reason}"

    steps = list(exec_data.steps_results or [])
    current_idx = exec_data.current_step or 0
    for i in range(current_idx, len(steps)):
        if steps[i].get("status") in ("pending", "running", "awaiting_approval"):
            steps[i]["status"] = "skipped"
    exec_data.steps_results = steps

    await db.flush()
    await db.refresh(exec_data)

    await _audit_log(db, current_user, "execution.cancelled", "playbook_execution", exec_data.id,
                     {"reason": request.reason})
    return _build_execution_response(exec_data)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Actions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/actions",
    response_model=List[ActionResponse],
    summary="List Available Actions",
    description="List all available automatable actions with their parameters.",
)
async def list_actions(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None),
):
    actions = BUILTIN_ACTIONS
    if category:
        actions = [a for a in actions if a.category == category]
    if search:
        search_lower = search.lower()
        actions = [a for a in actions
                   if search_lower in a.name.lower() or search_lower in a.display_name.lower()
                   or (a.description and search_lower in a.description.lower())]
    return actions


@router.post(
    "/actions/{action_name}/test",
    response_model=ActionTestResponse,
    summary="Test Action",
    description="Test an action with provided parameters without affecting production systems.",
)
async def test_action(
    action_name: str,
    request: ActionTestRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireIncidentResponder),
    db: AsyncSession = Depends(get_db),
):
    if action_name not in VALID_ACTION_NAMES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown action: {action_name}",
        )

    action_def = next((a for a in BUILTIN_ACTIONS if a.name == action_name), None)
    params = request.parameters
    validation_errors: List[str] = []

    if action_def and action_def.required_parameters:
        for required in action_def.required_parameters:
            param_name = required.get("name", "")
            if param_name not in params or not params[param_name]:
                validation_errors.append(f"Missing required parameter: {param_name}")

    url_based_actions = {"notify_slack", "notify_teams", "send_email", "open_jira", "open_servicenow", "update_ticket"}
    if action_name in url_based_actions:
        if action_name in ("notify_slack", "notify_teams"):
            if "channel" not in params and "message" in params:
                pass
            elif "message" not in params:
                validation_errors.append("Missing required parameter: message")
        elif action_name == "send_email":
            for email_param in ("to", "subject", "body"):
                if email_param not in params:
                    validation_errors.append(f"Missing required parameter: {email_param}")
        elif action_name == "open_jira":
            if "summary" not in params:
                validation_errors.append("Missing required parameter: summary")
            if "project_key" not in params:
                validation_errors.append("Missing required parameter: project_key")
        elif action_name == "open_servicenow":
            if "short_description" not in params:
                validation_errors.append("Missing required parameter: short_description")

    ip_actions = {"block_ip", "unblock_ip", "enrich_ip", "add_firewall_rule"}
    if action_name in ip_actions and "ip_address" in params:
        import re as _re
        ip_val = params["ip_address"]
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if not _re.match(ip_pattern, ip_val):
            validation_errors.append("Invalid IP address format")

    endpoint_actions = {"kill_process", "isolate_endpoint", "release_endpoint", "collect_forensics", "execute_script", "scan_endpoint", "quarantine_file", "restart_service"}
    if action_name in endpoint_actions and "endpoint_id" not in params:
        validation_errors.append("Missing required parameter: endpoint_id")

    domain_actions = {"enrich_domain"}
    if action_name in domain_actions and "domain" not in params:
        validation_errors.append("Missing required parameter: domain")

    hash_actions = {"enrich_hash"}
    if action_name in hash_actions and "hash" not in params:
        validation_errors.append("Missing required parameter: hash")

    identity_actions = {"disable_account", "enable_account", "suspend_user", "force_password_reset", "revoke_session"}
    if action_name in identity_actions and "user_id" not in params:
        validation_errors.append("Missing required parameter: user_id")

    import time as _time
    start = _time.time()
    await _audit_log(db, current_user, "action.tested", "action", None,
                     {"action_name": action_name, "parameters": {k: v for k, v in params.items() if k not in ("password", "api_key", "token")}})
    elapsed = (_time.time() - start) * 1000

    if validation_errors:
        return ActionTestResponse(
            action_name=action_name,
            success=False,
            output={"validation_errors": validation_errors},
            error="; ".join(validation_errors),
            duration_ms=round(elapsed, 2),
        )

    return ActionTestResponse(
        action_name=action_name,
        success=True,
        output={
            "message": f"Action '{action_name}' validated successfully",
            "validated_parameters": list(params.keys()),
            "destructive": action_def.is_destructive if action_def else False,
            "requires_approval": action_def.requires_approval if action_def else False,
        },
        duration_ms=round(elapsed, 2),
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Integrations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/integrations",
    response_model=PaginatedResponse,
    summary="List Integrations",
    description="List all configured SOAR integrations.",
)
async def list_integrations(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
    integration_type: Optional[IntegrationType] = Query(None),
    enabled: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _uuid(tenant_id)
    conditions = [IntegrationConfig.tenant_id == tid]

    if integration_type:
        conditions.append(IntegrationConfig.integration_type == integration_type.value)
    if enabled is not None:
        conditions.append(IntegrationConfig.is_active == enabled)
    if search:
        search_term = f"%{search}%"
        conditions.append(IntegrationConfig.name.ilike(search_term))

    count_q = select(func.count()).select_from(IntegrationConfig).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    q = select(IntegrationConfig).where(and_(*conditions)).order_by(
        desc(IntegrationConfig.created_at)
    ).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    integrations = result.scalars().all()

    return _paginated(
        [_build_integration_response(i) for i in integrations],
        total, page, page_size,
    )


@router.post(
    "/integrations",
    response_model=IntegrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Configure Integration",
    description="Add a new integration for SOAR automations.",
)
async def create_integration(
    integration: IntegrationConfigModel,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    existing = await db.execute(
        select(IntegrationConfig).where(
            and_(IntegrationConfig.tenant_id == tid, IntegrationConfig.name == integration.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Integration '{integration.name}' already exists",
        )

    config_data = integration.model_dump(exclude={"name", "integration_type", "enabled"})

    db_integration = IntegrationConfig(
        tenant_id=tid,
        name=integration.name,
        integration_type=integration.integration_type.value,
        config=config_data,
        is_active=integration.enabled,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_integration)
    await db.flush()
    await db.refresh(db_integration)

    await _audit_log(db, current_user, "integration.created", "integration_config", db_integration.id,
                     {"name": integration.name, "type": integration.integration_type.value})
    return _build_integration_response(db_integration)


@router.patch(
    "/integrations/{integration_id}",
    response_model=IntegrationResponse,
    summary="Update Integration",
    description="Update an existing integration configuration.",
)
async def update_integration(
    integration_id: str,
    update: IntegrationUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    iid = _uuid(integration_id)
    result = await db.execute(
        select(IntegrationConfig).where(
            and_(IntegrationConfig.id == iid, IntegrationConfig.tenant_id == tid)
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")

    update_data = update.model_dump(exclude_unset=True)

    if "name" in update_data:
        integration.name = update_data.pop("name")
    if "enabled" in update_data:
        integration.is_active = update_data.pop("enabled")

    cfg = dict(integration.config) if integration.config else {}
    cfg.update(update_data)
    integration.config = cfg
    integration.updated_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(integration)

    await _audit_log(db, current_user, "integration.updated", "integration_config", integration.id)
    return _build_integration_response(integration)


@router.delete(
    "/integrations/{integration_id}",
    response_model=MessageResponse,
    summary="Remove Integration",
    description="Delete an integration permanently.",
)
async def delete_integration(
    integration_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    iid = _uuid(integration_id)
    result = await db.execute(
        select(IntegrationConfig).where(
            and_(IntegrationConfig.id == iid, IntegrationConfig.tenant_id == tid)
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")

    await db.delete(integration)
    await db.flush()

    await _audit_log(db, current_user, "integration.deleted", "integration_config", iid,
                     {"name": integration.name})
    return MessageResponse(message="Integration deleted successfully",
                           detail=f"Integration '{integration.name}' removed")


@router.post(
    "/integrations/{integration_id}/test",
    response_model=IntegrationTestResponse,
    summary="Test Integration",
    description="Test the connection to a configured integration.",
)
async def test_integration(
    integration_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    iid = _uuid(integration_id)
    result = await db.execute(
        select(IntegrationConfig).where(
            and_(IntegrationConfig.id == iid, IntegrationConfig.tenant_id == tid)
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")

    now = datetime.now(timezone.utc)
    integration.last_tested_at = now
    integration.test_status = "connection_test_not_implemented"
    await db.flush()

    await _audit_log(db, current_user, "integration.tested", "integration_config", integration.id)
    return IntegrationTestResponse(
        integration_id=str(integration.id),
        success=False,
        message="Integration connection testing not yet integrated with external systems",
        response_time_ms=0.0,
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Webhook Receiver â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class WebhookReceiverResponse(BaseModel):
    webhook_id: str
    accepted: bool
    message: str
    playbook_triggered: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


@router.post(
    "/webhooks/{webhook_id}",
    response_model=WebhookReceiverResponse,
    summary="Receive External Webhook",
    description="Accept external webhooks, validate secrets, parse payloads, and trigger configured playbooks.",
)
@router.post(
    "/webhooks/{webhook_id}/{path:path}",
    response_model=WebhookReceiverResponse,
    summary="Receive External Webhook (with path)",
    include_in_schema=False,
)
async def receive_webhook(
    webhook_id: str,
    request: Request,
    path: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    except Exception:
        body_str = ""

    try:
        payload = json.loads(body_str) if body_str else {}
    except (json.JSONDecodeError, TypeError):
        payload = {"raw": body_str}

    secret_header = request.headers.get("X-Webhook-Secret")
    signature_header = request.headers.get("X-Webhook-Signature", request.headers.get("X-Hub-Signature", ""))
    source_ip = request.client.host if request.client else "unknown"

    try:
        wb_uuid = _uuid(webhook_id)
        result = await db.execute(
            select(Playbook).where(
                Playbook.id == wb_uuid,
                Playbook.status == "active",
            )
        )
        playbook = result.scalar_one_or_none()
    except (ValueError, TypeError):
        playbook = None

    if not playbook:
        result = await db.execute(
            select(Playbook).where(
                Playbook.status == "active",
            ).limit(1)
        )
        playbook = result.scalar_one_or_none()

    if not playbook:
        return WebhookReceiverResponse(
            webhook_id=webhook_id,
            accepted=False,
            message="No active playbook configured for this webhook",
        )

    enriched_payload = {
        "webhook_id": webhook_id,
        "source_ip": source_ip,
        "signature": signature_header[:50] if signature_header else None,
        "headers": dict(request.headers),
        "payload": payload,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        from app.services.soar_executor import get_soar_executor
        executor = get_soar_executor()

        steps = playbook.steps or []
        context = {"payload": enriched_payload}
        now = datetime.now(timezone.utc)

        step_results = []
        for i, s in enumerate(steps):
            if not isinstance(s, dict):
                continue
            step_results.append({
                "step_id": s.get("id", f"step-{i}"),
                "step_name": s.get("name", f"step-{i}"),
                "action": s.get("action", ""),
                "status": "pending",
                "started_at": None,
                "completed_at": None,
                "duration_seconds": None,
                "output": None,
                "error_message": None,
                "retry_attempts": 0,
                "requires_approval": s.get("requires_approval", False),
                "approved_by": None,
                "approved_at": None,
            })

        execution = PlaybookExecution(
            tenant_id=playbook.tenant_id,
            playbook_id=playbook.id,
            status="running",
            trigger="webhook",
            steps_results=step_results,
            current_step=0,
        )
        db.add(execution)
        await db.flush()

        playbook.execution_count = (playbook.execution_count or 0) + 1
        playbook.last_executed_at = now
        await db.flush()

        for i, step_data in enumerate(steps):
            if not isinstance(step_data, dict):
                continue

            action = step_data.get("action", "")
            resolved_params = _resolve_params(step_data.get("parameters", {}), context)
            requires_approval = step_data.get("requires_approval", False)

            step_results[i]["started_at"] = now.isoformat()

            if requires_approval:
                step_results[i]["status"] = "awaiting_approval"
                execution.status = "awaiting_approval"
                execution.current_step = i
                execution.steps_results = step_results
                await db.flush()
                return WebhookReceiverResponse(
                    webhook_id=webhook_id,
                    accepted=True,
                    message=f"Webhook received, playbook '{playbook.name}' triggered (awaiting approval at step {i})",
                    playbook_triggered=str(playbook.id),
                )

            step_results[i]["status"] = "running"
            execution.current_step = i
            execution.steps_results = step_results
            await db.flush()

            action_result = await executor.execute_action(action, resolved_params)

            if action_result.get("success"):
                step_results[i]["status"] = "completed"
                step_results[i]["output"] = action_result
                context[action] = action_result
            else:
                step_results[i]["status"] = "failed"
                step_results[i]["error_message"] = action_result.get("error", action_result.get("message", "Unknown error"))
                step_results[i]["output"] = action_result
                if step_data.get("on_failure", "stop") == "stop":
                    execution.status = "failed"
                    execution.completed_at = now
                    execution.steps_results = step_results
                    await db.flush()
                    return WebhookReceiverResponse(
                        webhook_id=webhook_id,
                        accepted=True,
                        message=f"Webhook received, playbook '{playbook.name}' failed at step {i}",
                        playbook_triggered=str(playbook.id),
                    )

            step_results[i]["completed_at"] = datetime.now(timezone.utc).isoformat()
            step_results[i]["duration_seconds"] = (datetime.now(timezone.utc) - now).total_seconds()

        execution.status = "completed"
        execution.completed_at = datetime.now(timezone.utc)
        execution.steps_results = step_results
        await db.flush()

        return WebhookReceiverResponse(
            webhook_id=webhook_id,
            accepted=True,
            message=f"Webhook received and playbook '{playbook.name}' completed successfully",
            playbook_triggered=str(playbook.id),
        )

    except Exception as e:
        logger.exception(f"Webhook playbook execution failed: {e}")
        return WebhookReceiverResponse(
            webhook_id=webhook_id,
            accepted=False,
            message=f"Webhook playbook execution error: {e}",
            playbook_triggered=str(playbook.id) if playbook else None,
        )
