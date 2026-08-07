"""
AEGIS - Agent Enrollment & Hardware/Software Inventory API
Wazuh-style agent deployment with one-liner enrollment commands.
Full hardware, software, services, and vulnerability inventory.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, async_session_factory
from app.api.deps import get_current_user, require_tenant
from app.models import Agent, Asset

router = APIRouter()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AgentEnrollRequest(BaseModel):
    hostname: str
    platform: str = "linux"
    os: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    agent_key: Optional[str] = None


class AgentEnrollResponse(BaseModel):
    agent_id: str
    agent_key: str
    enrollment_command: str
    enrollment_command_ps: str
    enrollment_command_bash: str


class HardwareReport(BaseModel):
    cpu: Optional[Dict] = None
    memory: Optional[Dict] = None
    disks: Optional[List[Dict]] = None
    motherboard: Optional[Dict] = None
    bios: Optional[Dict] = None
    gpu: Optional[List[Dict]] = None
    network_adapters: Optional[List[Dict]] = None
    tpm: Optional[Dict] = None
    secure_boot: Optional[Dict] = None


class SoftwareReport(BaseModel):
    os: Dict
    installed_apps: List[Dict] = []
    outdated_apps: List[Dict] = []
    running_services: List[Dict] = []
    browser_extensions: List[Dict] = []
    certificates: List[Dict] = []
    eol_software: List[Dict] = []


class VulnerabilityFix(BaseModel):
    name: str
    cve_id: Optional[str] = None
    severity: str
    description: str
    fix: str
    fix_command: Optional[str] = None
    auto_fix: bool = False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Agent Enrollment (Wazuh-style one-liner deployment)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post("/enroll", response_model=AgentEnrollResponse, summary="Enroll a new agent")
async def enroll_agent(
    body: AgentEnrollRequest,
    request: Request,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from app.core.security import generate_secure_token, hash_api_key

    agent_key = generate_secure_token(32)
    agent_id = uuid.uuid4()
    tid = uuid.UUID(tenant_id)

    agent = Agent(
        id=agent_id,
        tenant_id=tid,
        name=body.hostname,
        agent_key=hash_api_key(agent_key),
        platform=body.platform,
        hostname=body.hostname,
        ip_address=body.ip_address,
        status="offline",
        version="1.1.0",
        config={
            "os": body.os or "",
            "os_version": body.os_version or "",
        },
    )
    db.add(agent)

    asset = Asset(
        id=uuid.uuid4(),
        tenant_id=tid,
        name=body.hostname,
        type="endpoint",
        hostname=body.hostname,
        ip_address=body.ip_address,
        os=body.os,
        os_version=body.os_version,
    )
    db.add(asset)

    await db.flush()

    server_host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")
    if ":" in server_host:
        server_host = server_host.split(":")[0]

    if server_host in ("localhost", "127.0.0.1", "0.0.0.0"):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_host = s.getsockname()[0]
            s.close()
        except Exception:
            server_host = "127.0.0.1"

    port = getattr(settings, 'PORT', 8001)
    server_url = f"http://{server_host}:{port}"
    api_url = f"{server_url}/api/v1"

    return AgentEnrollResponse(
        agent_id=str(agent_id),
        agent_key=agent_key,
        enrollment_command=(
            f'curl -sSL {api_url}/agents/enroll '
            f'-H "X-Tenant-ID: {tenant_id}" '
            f'-H "X-API-Key: {agent_key}" '
            f'-d \'{{"hostname":"$(hostname)","platform":"linux","os":"$(uname -s)","os_version":"$(uname -r)","ip_address":"$(hostname -I | awk \'{{print $1}}\')","agent_key":"{agent_key}"}}\''
        ),
        enrollment_command_ps=(
            f'Invoke-RestMethod -Uri {api_url}/agents/enroll '
            f'-Method POST '
            f'-Headers @{{"X-Tenant-ID"="{tenant_id}";"X-API-Key"="{agent_key}"}} '
            f'-Body (ConvertTo-Json @{{hostname=$env:COMPUTERNAME;platform="windows";ip_address=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{$_.InterfaceAlias -notmatch "Loopback"}} | Select-Object -First 1).IPAddress;agent_key="{agent_key}"}})'
        ),
        enrollment_command_bash=(
            f'curl -sSL {api_url}/agents/enroll \\\n'
            f'  -H "X-Tenant-ID: {tenant_id}" \\\n'
            f'  -H "X-API-Key: {agent_key}" \\\n'
            f'  -d \'{{"hostname":"$(hostname)","platform":"linux","ip_address":"$(hostname -I | awk \'{{print $1}}\')","agent_key":"{agent_key}"}}\''
        ),
    )


@router.get("/enroll/command", summary="Get enrollment command for current tenant")
async def get_enrollment_command(
    request: Request,
    platform: str = Query("linux", pattern="^(linux|windows|macos)$"),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    from app.core.security import generate_secure_token

    agent_key = generate_secure_token(32)

    server_host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")
    if ":" in server_host:
        server_host = server_host.split(":")[0]
    if server_host in ("localhost", "127.0.0.1", "0.0.0.0"):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_host = s.getsockname()[0]
            s.close()
        except Exception:
            server_host = "127.0.0.1"

    port = getattr(settings, 'PORT', 8001)
    server_url = f"http://{server_host}:{port}"
    api_url = f"{server_url}/api/v1"

    commands = {
        "linux": f'curl -sSL {api_url}/agents/enroll -H "X-Tenant-ID: {tenant_id}" -H "X-API-Key: {agent_key}" -d \'{{"hostname":"$(hostname)","platform":"linux","os":"$(uname -s)","os_version":"$(uname -r)","agent_key":"{agent_key}"}}\'',
        "windows": f'powershell -Command "Invoke-RestMethod -Uri {api_url}/agents/enroll -Method POST -Headers @{{\\"X-Tenant-ID\\"=\\"{tenant_id}\\";\\"X-API-Key\\"=\\"{agent_key}\\"}} -Body (ConvertTo-Json @{{hostname=$env:COMPUTERNAME;platform=\\"windows\\";agent_key=\\"{agent_key}\\"}})"',
        "macos": f'curl -sSL {api_url}/agents/enroll -H "X-Tenant-ID: {tenant_id}" -H "X-API-Key: {agent_key}" -d \'{{"hostname":"$(scutil --get ComputerName)","platform":"darwin","os":"macOS","agent_key":"{agent_key}"}}\'',
    }

    return {
        "agent_key": agent_key,
        "command": commands.get(platform, commands["linux"]),
        "platform": platform,
        "server_url": server_url,
        "dashboard_url": f"{server_url}/agents",
        "note": "Agent key shown only once. Save it. The agent will appear in the console after enrollment.",
    }


@router.get("/server/info", summary="Get server connection info (IP, port, dashboard URL)")
async def get_server_info(request: Request):
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "localhost")
    if ":" in host:
        host = host.split(":")[0]
    if host in ("localhost", "127.0.0.1", "0.0.0.0"):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            host = s.getsockname()[0]
            s.close()
        except Exception:
            host = "127.0.0.1"

    port = getattr(settings, 'PORT', 8001)

    return {
        "server_ip": host,
        "api_port": port,
        "api_url": f"http://{host}:{port}/api/v1",
        "dashboard_url": f"http://{host}:{port}",
        "agent_dashboard": f"http://{host}:5174/agents",
        "enrollment_endpoint": f"http://{host}:{port}/api/v1/agents/enroll/command",
        "services": {
            "prometheus": f"http://{host}:9090",
            "grafana": f"http://{host}:3000",
            "jaeger": f"http://{host}:16686",
            "minio": f"http://{host}:9001",
        }
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Hardware & Software Inventory
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post("/{agent_id}/hardware", summary="Submit hardware inventory report")
async def submit_hardware(
    agent_id: str,
    report: HardwareReport,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    config = agent.config or {}
    config["hardware"] = report.model_dump()
    agent.config = config
    agent.last_heartbeat = datetime.now(timezone.utc)
    agent.status = "online"
    await db.commit()

    return {"status": "accepted", "agent_id": agent_id}


@router.post("/{agent_id}/software", summary="Submit software inventory report")
async def submit_software(
    agent_id: str,
    report: SoftwareReport,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    config = agent.config or {}
    config["software"] = report.model_dump()
    agent.config = config
    agent.last_heartbeat = datetime.now(timezone.utc)
    agent.status = "online"
    await db.commit()

    return {"status": "accepted", "agent_id": agent_id}


@router.get("/{agent_id}/inventory", summary="Get full agent inventory")
async def get_inventory(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    config = agent.config or {}

    return {
        "agent_id": str(agent.id),
        "hostname": agent.hostname,
        "platform": agent.platform,
        "status": agent.status,
        "version": agent.version,
        "ip_address": agent.ip_address,
        "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        "hardware": config.get("hardware", {}),
        "software": config.get("software", {}),
        "vulnerabilities": config.get("vulnerabilities", []),
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Vulnerability Detection
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/{agent_id}/vulnerabilities", summary="Get detected vulnerabilities with fix suggestions")
async def get_vulnerabilities(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    config = agent.config or {}
    software = config.get("software", {})
    outdated = software.get("outdated_apps", [])
    eol = software.get("eol_software", [])
    services = software.get("running_services", [])

    vulnerabilities: List[Dict] = []

    for app in outdated:
        name = app.get("name", "unknown")
        sev = app.get("severity", "medium")
        vulnerabilities.append({
            "name": f"Outdated: {name}",
            "severity": sev,
            "description": f"{name} {app.get('current_version', '?')} is outdated. Latest: {app.get('latest_version', '?')}",
            "fix": f"Update {name} to version {app.get('latest_version', 'latest')}",
            "fix_command": get_update_command(agent.platform, name),
            "auto_fix": sev == "low",
        })

    for app in eol:
        vulnerabilities.append({
            "name": f"EOL: {app.get('name', 'unknown')}",
            "severity": app.get("severity", "critical"),
            "description": f"{app.get('name', 'unknown')} {app.get('version', '?')} reached end-of-life on {app.get('eol_date', '?')}",
            "fix": f"Uninstall {app.get('name', 'unknown')} and migrate to a supported alternative",
            "fix_command": get_uninstall_command(agent.platform, app.get("name", "")),
            "auto_fix": False,
        })

    for svc in services:
        if svc.get("risk") == "high":
            vulnerabilities.append({
                "name": f"High-risk service: {svc.get('name', 'unknown')}",
                "severity": "high",
                "description": f"Service {svc.get('display_name', svc.get('name', ''))} running as {svc.get('user', 'unknown')} (high risk)",
                "fix": f"Disable or harden the {svc.get('name', 'unknown')} service. Change to a least-privilege user.",
                "fix_command": get_service_disable_command(agent.platform, svc.get("name", "")),
                "auto_fix": False,
            })

    return {
        "agent_id": agent_id,
        "total": len(vulnerabilities),
        "critical": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
        "high": sum(1 for v in vulnerabilities if v["severity"] == "high"),
        "medium": sum(1 for v in vulnerabilities if v["severity"] == "medium"),
        "low": sum(1 for v in vulnerabilities if v["severity"] == "low"),
        "vulnerabilities": vulnerabilities,
    }


def get_update_command(platform: Optional[str], app_name: str) -> Optional[str]:
    cmds = {
        "linux": f"sudo apt-get update && sudo apt-get upgrade -y {app_name} || sudo yum update -y {app_name}",
        "windows": f'winget upgrade --id "{app_name}"',
        "darwin": f"brew upgrade {app_name}",
    }
    return cmds.get(platform or "linux")


def get_uninstall_command(platform: Optional[str], app_name: str) -> Optional[str]:
    cmds = {
        "linux": f"sudo apt-get remove -y {app_name} || sudo yum remove -y {app_name}",
        "windows": f'winget uninstall "{app_name}"',
        "darwin": f"brew uninstall {app_name}",
    }
    return cmds.get(platform or "linux")


def get_service_disable_command(platform: Optional[str], service_name: str) -> Optional[str]:
    cmds = {
        "linux": f"sudo systemctl stop {service_name} && sudo systemctl disable {service_name}",
        "windows": f'sc config "{service_name}" start=disabled && sc stop "{service_name}"',
        "darwin": f"sudo launchctl unload /Library/LaunchDaemons/{service_name}.plist",
    }
    return cmds.get(platform or "linux")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Agent Dashboard Summary
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/dashboard/summary", summary="Get agent fleet summary for dashboard")
async def agent_summary(
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Agent).where(Agent.tenant_id == uuid.UUID(tenant_id))
    )
    agents = result.scalars().all()

    online = sum(1 for a in agents if a.status == "online")
    offline = sum(1 for a in agents if a.status == "offline")

    total_vulns = 0
    for agent in agents:
        config = agent.config or {}
        sw = config.get("software", {})
        total_vulns += len(sw.get("outdated_apps", []))
        total_vulns += len(sw.get("eol_software", []))

    return {
        "total_agents": len(agents),
        "online": online,
        "offline": offline,
        "total_vulnerabilities": total_vulns,
        "compliance_score": 92,
        "agents": [
            {
                "id": str(a.id),
                "hostname": a.hostname,
                "platform": a.platform,
                "status": a.status,
                "ip_address": a.ip_address,
                "last_heartbeat": a.last_heartbeat.isoformat() if a.last_heartbeat else None,
                "vuln_count": len((a.config or {}).get("software", {}).get("outdated_apps", [])) +
                              len((a.config or {}).get("software", {}).get("eol_software", [])),
            }
            for a in agents
        ],
    }
