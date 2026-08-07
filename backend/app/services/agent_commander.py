"""Agent Commander Service - EDR response command execution."""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession


class CommandStatus(str, Enum):
    QUEUED = "queued"
    SENT = "sent"
    EXECUTED = "executed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class AgentCommander:

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_agent(self, agent_id: str):
        from app.models.asset import Agent
        result = await self.db.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
        return result.scalar_one_or_none()

    async def queue_command(self, agent_id: str, command: str, params: Dict[str, Any] = None, admin_username: str = "admin") -> Dict[str, Any]:
        """Queue a command for an agent to execute."""
        from app.models.operational import AgentCommand
        cmd = AgentCommand(
            id=uuid.uuid4(),
            agent_id=uuid.UUID(agent_id),
            command=command,
            params=params or {},
            status=CommandStatus.QUEUED,
            created_by=admin_username,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(cmd)
        await self.db.flush()
        return {
            "command_id": str(cmd.id),
            "agent_id": str(cmd.agent_id),
            "command": cmd.command,
            "params": cmd.params,
            "status": cmd.status,
            "created_at": cmd.created_at.isoformat(),
        }

    async def kill_process(self, agent_id: str, pid: int, process_name: str = "") -> Dict[str, Any]:
        """Queue process termination on endpoint."""
        return await self.queue_command(agent_id, "kill_process", {"pid": pid, "process_name": process_name})

    async def isolate_endpoint(self, agent_id: str) -> Dict[str, Any]:
        """Queue network isolation on endpoint."""
        return await self.queue_command(agent_id, "isolate", {"action": "block_all_except_management"})

    async def release_endpoint(self, agent_id: str) -> Dict[str, Any]:
        """Queue network restoration on endpoint."""
        return await self.queue_command(agent_id, "release", {"action": "restore_network"})

    async def quarantine_file(self, agent_id: str, filepath: str) -> Dict[str, Any]:
        """Queue file quarantine on endpoint."""
        return await self.queue_command(agent_id, "quarantine_file", {"filepath": filepath})

    async def collect_forensics(self, agent_id: str, target: str = "full") -> Dict[str, Any]:
        """Queue forensic data collection."""
        return await self.queue_command(agent_id, "collect_forensics", {"target": target})

    async def scan_endpoint(self, agent_id: str) -> Dict[str, Any]:
        """Queue full endpoint scan."""
        return await self.queue_command(agent_id, "scan", {"scan_type": "full", "include_memory": True})

    async def get_pending_commands(self, agent_id: str) -> List[Dict[str, Any]]:
        """Agent polls this to get queued commands."""
        from app.models.operational import AgentCommand
        result = await self.db.execute(
            select(AgentCommand).where(
                AgentCommand.agent_id == uuid.UUID(agent_id),
                AgentCommand.status == CommandStatus.QUEUED,
            ).order_by(AgentCommand.created_at)
        )
        commands = result.scalars().all()
        output = []
        for c in commands:
            c.status = CommandStatus.SENT
            c.sent_at = datetime.now(timezone.utc)
            output.append({
                "command_id": str(c.id),
                "command": c.command,
                "params": c.params,
            })
        await self.db.flush()
        return output

    async def report_command_result(self, command_id: str, success: bool, output_data: str = "", error: str = "") -> Dict[str, Any]:
        """Agent reports command execution result."""
        from app.models.operational import AgentCommand
        result = await self.db.execute(
            select(AgentCommand).where(AgentCommand.id == uuid.UUID(command_id))
        )
        cmd = result.scalar_one_or_none()
        if not cmd:
            return {"error": "Command not found", "command_id": command_id}

        cmd.status = CommandStatus.EXECUTED if success else CommandStatus.FAILED
        cmd.output = output_data
        cmd.error = error
        cmd.completed_at = datetime.now(timezone.utc)
        await self.db.flush()
        return {
            "command_id": str(cmd.id),
            "status": cmd.status,
            "output": output_data,
            "error": error,
        }

    async def get_command_history(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get command history for an agent."""
        from app.models.operational import AgentCommand
        result = await self.db.execute(
            select(AgentCommand).where(AgentCommand.agent_id == uuid.UUID(agent_id))
            .order_by(AgentCommand.created_at.desc()).limit(limit)
        )
        return [
            {
                "id": str(c.id), "agent_id": str(c.agent_id), "command": c.command,
                "params": c.params, "status": c.status, "output": c.output,
                "error": c.error, "created_at": c.created_at.isoformat(),
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
            }
            for c in result.scalars().all()
        ]
