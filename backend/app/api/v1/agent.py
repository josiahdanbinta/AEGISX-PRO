"""
AEGISX - Agent Enrollment & Management API Router
Register, download, heartbeat, data push, command relay
"""
import uuid
import hashlib
import tarfile
import io
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, RequireSOCAnalyst, RequireTenantAdmin
from app.core.config import settings
from app.core.database import get_db
from app.models import Agent, Asset, AuditLog
from app.core.security import generate_secure_token

router = APIRouter()


# ── Pydantic Models ───────────────────────────────────────────────

class AgentRegisterRequest(BaseModel):
    hostname: str = Field(..., description="Agent hostname")
    platform: str = Field(..., description="OS platform (windows/linux/macos)")
    platform_version: Optional[str] = Field(None, description="OS version details")
    ip_address: Optional[str] = Field(None, description="Agent IP address")
    mac_address: Optional[str] = Field(None, description="Agent MAC address")
    agent_version: str = Field("1.1.0", description="Agent version")
    registration_key: str = Field(..., description="Tenant registration key")
    tenant_id: str = Field(..., description="Tenant UUID")
    capabilities: Optional[list] = Field(default=[], description="Agent capabilities")
    # Accept agent's payload format too
    agent_key: Optional[str] = Field(None, alias="agent_key")
    os_info: Optional[dict] = Field(None)
    architecture: Optional[str] = Field(None)
    python_version: Optional[str] = Field(None)
    collectors: Optional[list] = Field(None)


class AgentRegisterResponse(BaseModel):
    agent_id: str
    agent_key: str
    server_url: str
    heartbeat_interval: int
    status: str = "registered"
    message: str = "Agent registered successfully"


class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    agent_key: str
    status: str = "online"
    system_info: Optional[dict] = None
    metrics: Optional[dict] = None


class AgentHeartbeatResponse(BaseModel):
    status: str
    pending_commands: list = []
    next_heartbeat: int


class AgentDataPush(BaseModel):
    agent_id: str
    agent_key: str
    data_type: str = Field(..., description="Type of data: inventory, logs, alerts, metrics, ransomware")
    payload: dict = Field(..., description="Collected data payload")


class AgentCommandRequest(BaseModel):
    command: str = Field(..., description="Command to send: collect, status, reconfigure, restart, shutdown, update, get_full_inventory, scan_ransomware, get_services, get_apps")
    params: Optional[dict] = None


class AgentCommandResponse(BaseModel):
    command_id: str
    status: str = "queued"
    message: str


# ── In-memory command queue (Redis-backed in production) ───────────

_agent_command_queues: dict = {}
_pending_commands: dict = {}


# ── Agent Registration ─────────────────────────────────────────────

@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    summary="Register a new agent",
    description="Enroll a new agent endpoint. Returns agent credentials and configuration.",
)
async def register_agent(request: AgentRegisterRequest, db: AsyncSession = Depends(get_db)):
    # Accept both registration_key and agent_key
    reg_key = request.registration_key or request.agent_key
    if not reg_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="registration_key or agent_key required")

    if reg_key != settings.AGENT_REGISTRATION_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid registration key")

    tid = uuid.UUID(request.tenant_id)

    # Extract platform version from os_info if not provided directly
    platform_ver = request.platform_version
    if not platform_ver and request.os_info:
        platform_ver = request.os_info.get("version", request.os_info.get("name", ""))
    if not request.capabilities and request.collectors:
        request.capabilities = request.collectors

    # Check if agent already exists for this hostname + tenant
    existing = await db.execute(
        select(Agent).where(Agent.hostname == request.hostname, Agent.tenant_id == tid)
    )
    existing_agent = existing.scalar_one_or_none()

    if existing_agent:
        # Re-register existing agent — update it
        existing_agent.ip_address = request.ip_address
        existing_agent.platform = request.platform
        existing_agent.version = request.agent_version
        existing_agent.status = "online"
        existing_agent.last_heartbeat = datetime.now(timezone.utc)
        existing_agent.capabilities = request.capabilities or []
        await db.flush()

        return AgentRegisterResponse(
            agent_id=str(existing_agent.id),
            agent_key=existing_agent.agent_key,
            server_url=f"http://{request.ip_address or 'localhost'}:8000",
            heartbeat_interval=settings.AGENT_HEARTBEAT_INTERVAL,
            status="reconnected",
            message=f"Agent {request.hostname} reconnected successfully",
        )

    # Create new agent
    agent_id = uuid.uuid4()
    agent_key = generate_secure_token(32)

    agent = Agent(
        id=agent_id,
        tenant_id=tid,
        name=request.hostname,
        hostname=request.hostname,
        ip_address=request.ip_address,
        agent_key=hashlib.sha256(agent_key.encode()).hexdigest(),
        version=request.agent_version,
        platform=request.platform,
        status="online",
        last_heartbeat=datetime.now(timezone.utc),
        capabilities=request.capabilities or [],
    )
    db.add(agent)

    # Auto-create an Asset record for this agent
    asset = Asset(
        id=uuid.uuid4(),
        tenant_id=tid,
        name=request.hostname,
        hostname=request.hostname,
        ip_address=request.ip_address,
        mac_address=request.mac_address,
        type="endpoint",
        os=request.platform,
        os_version=request.platform_version,
        status="online",
        agent_id=str(agent_id),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(asset)

    # Audit the registration
    audit = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tid,
        action="agent_register",
        resource_type="Agent",
        resource_id=agent_id,
        details={
            "hostname": request.hostname,
            "platform": request.platform,
            "version": request.agent_version,
            "ip": request.ip_address,
        },
        status="success",
        severity="info",
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    await db.flush()

    return AgentRegisterResponse(
        agent_id=str(agent_id),
        agent_key=agent_key,
        server_url=f"http://{request.ip_address or 'localhost'}:8000",
        heartbeat_interval=settings.AGENT_HEARTBEAT_INTERVAL,
    )


# ── Agent Heartbeat ────────────────────────────────────────────────

@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    summary="Agent heartbeat",
    description="Send periodic heartbeat to update agent status and receive pending commands.",
)
async def agent_heartbeat(request: AgentHeartbeatRequest, db: AsyncSession = Depends(get_db)):
    agent = await db.scalar(select(Agent).where(Agent.id == uuid.UUID(request.agent_id)))
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    # Verify agent key
    key_hash = hashlib.sha256(request.agent_key.encode()).hexdigest()
    if agent.agent_key != key_hash:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid agent key")

    # Update agent status
    agent.status = request.status
    agent.last_heartbeat = datetime.now(timezone.utc)

    # Update linked asset
    if agent.asset_id:
        await db.execute(
            sql_update(Asset)
            .where(Asset.id == agent.asset_id)
            .values(last_seen=datetime.now(timezone.utc), status="online")
        )
    else:
        # Find asset by agent_id
        asset = await db.scalar(
            select(Asset).where(Asset.agent_id == str(agent.id), Asset.tenant_id == agent.tenant_id)
        )
        if asset:
            asset.last_seen = datetime.now(timezone.utc)
            asset.status = "online"

    await db.flush()

    # Check for pending commands
    pending = _agent_command_queues.get(request.agent_id, [])
    commands = []
    while pending:
        commands.append(pending.pop(0))

    return AgentHeartbeatResponse(
        status="ok",
        pending_commands=commands,
        next_heartbeat=settings.AGENT_HEARTBEAT_INTERVAL,
    )


# ── Agent Data Push ────────────────────────────────────────────────

@router.post(
    "/data",
    summary="Push collected data from agent",
    description="Agent pushes collected data (inventory, logs, alerts, metrics, ransomware detections) to the platform.",
)
async def agent_data_push(request: AgentDataPush, db: AsyncSession = Depends(get_db)):
    agent = await db.scalar(select(Agent).where(Agent.id == uuid.UUID(request.agent_id)))
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    key_hash = hashlib.sha256(request.agent_key.encode()).hexdigest()
    if agent.agent_key != key_hash:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid agent key")

    # Update agent last seen
    agent.last_heartbeat = datetime.now(timezone.utc)

    # Process data based on type
    if request.data_type == "inventory":
        # Update asset with inventory data
        asset = await db.scalar(
            select(Asset).where(Asset.agent_id == str(agent.id), Asset.tenant_id == agent.tenant_id)
        )
        if asset:
            payload = request.payload
            if payload.get("hardware"):
                asset.hardware_info = payload["hardware"]
            if payload.get("software"):
                asset.software_info = payload["software"]
            if payload.get("network"):
                asset.network_info = payload["network"]
            asset.last_seen = datetime.now(timezone.utc)

    elif request.data_type == "ransomware":
        # Log ransomware detection events
        audit = AuditLog(
            id=uuid.uuid4(),
            tenant_id=agent.tenant_id,
            action="ransomware_detection",
            resource_type="Agent",
            resource_id=agent.id,
            details=request.payload,
            status="success",
            severity="critical",
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit)

    await db.flush()

    return {"status": "received", "data_type": request.data_type}


# ── Agent Download ─────────────────────────────────────────────────

@router.get(
    "/download",
    summary="Download agent package",
    description="Download the AEGISX agent package for manual or scripted deployment.",
)
async def download_agent():
    """Package and stream the agent code as a tar.gz file."""
    agent_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "agent")

    # Create an in-memory tar.gz of the agent directory
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        for root, dirs, files in os.walk(agent_dir):
            # Exclude __pycache__, tests, .pyc files
            dirs[:] = [d for d in dirs if d != "__pycache__" and d != "tests"]
            files = [f for f in files if not f.endswith(".pyc")]

            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, agent_dir)
                tar.add(file_path, arcname=arcname)

    tar_buffer.seek(0)
    return StreamingResponse(
        tar_buffer,
        media_type="application/gzip",
        headers={
            "Content-Disposition": "attachment; filename=aegisx-agent.tar.gz",
            "X-Agent-Version": "1.1.0",
        },
    )


# ── Agent Command ──────────────────────────────────────────────────

@router.post(
    "/{agent_id}/command",
    response_model=AgentCommandResponse,
    summary="Send command to agent",
    description="Queue a command for a specific agent. Agent retrieves commands during heartbeat.",
)
async def send_agent_command(
    agent_id: str,
    request: AgentCommandRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    agent = await db.scalar(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    cmd_id = str(uuid.uuid4())
    command = {
        "command_id": cmd_id,
        "command": request.command,
        "params": request.params or {},
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    if agent_id not in _agent_command_queues:
        _agent_command_queues[agent_id] = []
    _agent_command_queues[agent_id].append(command)

    # Audit
    audit = AuditLog(
        id=uuid.uuid4(),
        tenant_id=agent.tenant_id,
        user_id=uuid.UUID(current_user["user_id"]),
        action="agent_command",
        resource_type="Agent",
        resource_id=agent.id,
        details={"command": request.command, "command_id": cmd_id},
        status="success",
        severity="info",
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    await db.flush()

    return AgentCommandResponse(command_id=cmd_id, message=f"Command '{request.command}' queued for agent {agent.name}")


# ── Agent Listing (for dashboard) ──────────────────────────────────

@router.get(
    "/list",
    summary="List registered agents",
    description="List all agents for the current tenant with status.",
)
async def list_agents(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = uuid.UUID(current_user["tenant_id"])
    agents = (await db.execute(
        select(Agent).where(Agent.tenant_id == tid).order_by(Agent.last_heartbeat.desc())
    )).scalars().all()

    return {
        "agents": [
            {
                "id": str(a.id),
                "name": a.name,
                "hostname": a.hostname,
                "platform": a.platform,
                "version": a.version,
                "status": a.status,
                "ip_address": a.ip_address,
                "last_heartbeat": a.last_heartbeat.isoformat() if a.last_heartbeat else None,
                "capabilities": a.capabilities,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in agents
        ],
        "total": len(agents),
    }


@router.get(
    "/registration-key",
    summary="Get agent registration key",
    description="Return the registration key needed for agent enrollment (admin only).",
)
async def get_registration_key(
    current_user: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return {
        "registration_key": settings.AGENT_REGISTRATION_KEY,
        "tenant_id": current_user["tenant_id"],
        "server_url": "http://localhost:8000",
        "enrollment_commands": {
            "linux_macos": f"curl -sSL http://SERVER_IP:8000/api/v1/agent/download -o aegisx-agent.tar.gz && tar -xzf aegisx-agent.tar.gz && cd agent && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python agent.py --server http://SERVER_IP:8000 --key {settings.AGENT_REGISTRATION_KEY} --tenant {current_user['tenant_id']}",
            "windows_cmd": f"curl -o aegisx-agent.zip http://SERVER_IP:8000/api/v1/agent/download && tar -xf aegisx-agent.zip && cd agent && python -m venv venv && venv\\Scripts\\activate && pip install -r requirements.txt && python agent.py --server http://SERVER_IP:8000 --key {settings.AGENT_REGISTRATION_KEY} --tenant {current_user['tenant_id']}",
        },
    }


# ── EDR Response Endpoints ───────────────────────────────────────

@router.get("/commands", summary="Get pending commands for authenticated agent")
async def get_pending_commands(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    agent_id = current_user.get("user_id")
    commander = AgentCommander(db)
    commands = await commander.get_pending_commands(agent_id)
    return {"commands": commands, "count": len(commands)}


@router.post("/command-result", summary="Agent reports command result")
async def report_command_result(
    body: dict,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    result = await commander.report_command_result(
        command_id=body.get("command_id", ""),
        success=body.get("success", False),
        output_data=body.get("output", ""),
        error=body.get("error", ""),
    )
    return result


@router.post("/{agent_id}/kill-process", summary="Kill process on endpoint")
async def kill_process(
    agent_id: str,
    body: dict,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    result = await commander.kill_process(agent_id, body.get("pid", 0), body.get("process_name", ""))
    return result


@router.post("/{agent_id}/isolate", summary="Isolate endpoint from network")
async def isolate_endpoint(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.isolate_endpoint(agent_id)


@router.post("/{agent_id}/release", summary="Release isolated endpoint")
async def release_endpoint(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.release_endpoint(agent_id)


@router.post("/{agent_id}/quarantine-file", summary="Quarantine file on endpoint")
async def quarantine_file(
    agent_id: str,
    body: dict,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.quarantine_file(agent_id, body.get("filepath", ""))


@router.post("/{agent_id}/forensics", summary="Collect forensic data")
async def collect_forensics(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.collect_forensics(agent_id)


@router.post("/{agent_id}/scan", summary="Trigger full endpoint scan")
async def scan_endpoint(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.scan_endpoint(agent_id)


@router.get("/{agent_id}/command-history", summary="Get agent command history")
async def get_command_history(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    from app.services.agent_commander import AgentCommander
    commander = AgentCommander(db)
    return await commander.get_command_history(agent_id)
