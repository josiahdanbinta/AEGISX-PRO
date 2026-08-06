"""
AEGISX - Real-Time WebSocket Endpoints
Live dashboard updates, agent communication, alert streaming
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.database import async_session_factory, get_db
from app.core.security import decode_token
from app.models import Alert, Asset, Incident, Agent

router = APIRouter()


# ════════════════════════════════════════════════════════════════════
# Connection Manager
# ════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.agent_channels: Dict[str, WebSocket] = {}
        self.incident_watchers: Dict[str, List[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, tenant_id: str, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            if tenant_id not in self.active_connections:
                self.active_connections[tenant_id] = []
            self.active_connections[tenant_id].append(websocket)

    async def disconnect(self, tenant_id: str, websocket: WebSocket):
        async with self._lock:
            if tenant_id in self.active_connections:
                try:
                    self.active_connections[tenant_id].remove(websocket)
                except ValueError:
                    pass
                if not self.active_connections[tenant_id]:
                    del self.active_connections[tenant_id]
            for incident_id, watchers in list(self.incident_watchers.items()):
                try:
                    watchers.remove(websocket)
                except ValueError:
                    pass
                if not watchers:
                    del self.incident_watchers[incident_id]
            for agent_id, ws in list(self.agent_channels.items()):
                if ws is websocket:
                    del self.agent_channels[agent_id]

    async def broadcast_to_tenant(self, tenant_id: str, message: dict):
        for ws in self.active_connections.get(tenant_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(tenant_id, ws)

    async def send_personal(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    async def broadcast_incident_update(self, incident_id: str, tenant_id: str, message: dict):
        for ws in self.incident_watchers.get(incident_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                pass

    async def watch_incident(self, incident_id: str, websocket: WebSocket):
        async with self._lock:
            if incident_id not in self.incident_watchers:
                self.incident_watchers[incident_id] = []
            self.incident_watchers[incident_id].append(websocket)

    async def register_agent(self, agent_id: str, websocket: WebSocket):
        async with self._lock:
            self.agent_channels[agent_id] = websocket

    async def send_to_agent(self, agent_id: str, message: dict):
        ws = self.agent_channels.get(agent_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                async with self._lock:
                    self.agent_channels.pop(agent_id, None)

    @property
    def active_count(self) -> int:
        return sum(len(v) for v in self.active_connections.values())


manager = ConnectionManager()


# ════════════════════════════════════════════════════════════════════
# Auth Helper
# ════════════════════════════════════════════════════════════════════

async def _ws_authenticate(websocket: WebSocket) -> Optional[dict]:
    token = websocket.query_params.get("token")
    if not token:
        token = websocket.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return None

    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return None

    if payload.get("type") != "access":
        await websocket.close(code=4001, reason="Invalid token type")
        return None

    return {
        "user_id": payload.get("sub"),
        "tenant_id": payload.get("tenant_id"),
        "roles": payload.get("roles", []),
    }


async def _get_dashboard_stats(tenant_id: str) -> dict:
    tid = uuid.UUID(tenant_id)
    try:
        async with async_session_factory() as db:
            incidents = await db.execute(
                select(func.count(Incident.id)).where(Incident.tenant_id == tid)
            )
            alerts = await db.execute(
                select(func.count(Alert.id)).where(Alert.tenant_id == tid)
            )
            assets = await db.execute(
                select(func.count(Asset.id)).where(Asset.tenant_id == tid)
            )
            agents_online = await db.execute(
                select(func.count(Agent.id)).where(
                    Agent.tenant_id == tid,
                    Agent.status == "online",
                )
            )
            open_incidents = await db.execute(
                select(func.count(Incident.id)).where(
                    Incident.tenant_id == tid,
                    Incident.status.in_(["open", "in_progress"]),
                )
            )
            return {
                "incidents_total": incidents.scalar() or 0,
                "incidents_open": open_incidents.scalar() or 0,
                "alerts_total": alerts.scalar() or 0,
                "assets_total": assets.scalar() or 0,
                "agents_online": agents_online.scalar() or 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    except Exception:
        return {
            "incidents_total": 0, "incidents_open": 0,
            "alerts_total": 0, "assets_total": 0,
            "agents_online": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ════════════════════════════════════════════════════════════════════
# WebSocket Endpoints
# ════════════════════════════════════════════════════════════════════

@router.websocket("/live/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """Real-time dashboard statistics pushed every 30 seconds."""
    user = await _ws_authenticate(websocket)
    if not user:
        return

    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)

    try:
        initial_stats = await _get_dashboard_stats(tenant_id)
        await manager.send_personal(websocket, {
            "type": "dashboard_init",
            "data": initial_stats,
        })

        while True:
            await asyncio.sleep(30)
            stats = await _get_dashboard_stats(tenant_id)
            await manager.send_personal(websocket, {
                "type": "dashboard_update",
                "data": stats,
            })
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert streaming. Polls new alerts every 5 seconds."""
    user = await _ws_authenticate(websocket)
    if not user:
        return

    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)
    tid = uuid.UUID(tenant_id)
    last_seen_id = None

    try:
        await manager.send_personal(websocket, {
            "type": "alerts_connected",
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        while True:
            try:
                async with async_session_factory() as db:
                    query = select(Alert).where(Alert.tenant_id == tid).order_by(Alert.created_at.desc()).limit(20)
                    result = await db.execute(query)
                    new_alerts = result.scalars().all()

                    for alert in new_alerts:
                        alert_id_str = str(alert.id)
                        if last_seen_id and alert_id_str == last_seen_id:
                            break
                        await manager.send_personal(websocket, {
                            "type": "alert",
                            "data": {
                                "id": alert_id_str,
                                "name": alert.title,
                                "severity": alert.severity,
                                "status": alert.status,
                                "rule_name": alert.rule_name,
                                "source": alert.source_ip,
                                "description": alert.description,
                                "triggered_at": alert.created_at.isoformat() if alert.created_at else None,
                            },
                        })

                    if new_alerts:
                        last_seen_id = str(new_alerts[0].id)
            except Exception:
                pass

            await asyncio.sleep(5)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/agent/{agent_id}")
async def websocket_agent(websocket: WebSocket, agent_id: str):
    """Bidirectional agent communication channel with heartbeat monitoring."""
    user = await _ws_authenticate(websocket)
    if not user:
        return

    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)
    await manager.register_agent(agent_id, websocket)

    last_heartbeat = datetime.now(timezone.utc)
    command_queue: asyncio.Queue = asyncio.Queue(maxsize=100)

    async def heartbeat_monitor():
        nonlocal last_heartbeat
        while True:
            await asyncio.sleep(settings.AGENT_HEARTBEAT_INTERVAL)
            elapsed = (datetime.now(timezone.utc) - last_heartbeat).total_seconds()
            if elapsed > settings.AGENT_STALE_TIMEOUT:
                try:
                    await websocket.send_json({
                        "type": "agent_offline",
                        "agent_id": agent_id,
                        "reason": "heartbeat_timeout",
                    })
                    await websocket.close(code=4002, reason="Agent heartbeat timeout")
                except Exception:
                    pass
                break

    heartbeat_task = asyncio.create_task(heartbeat_monitor())

    try:
        await manager.send_personal(websocket, {
            "type": "agent_connected",
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        async def receive_loop():
            nonlocal last_heartbeat
            while True:
                raw = await websocket.receive_text()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                msg_type = msg.get("type", "")
                if msg_type == "heartbeat":
                    last_heartbeat = datetime.now(timezone.utc)
                    await manager.send_personal(websocket, {
                        "type": "heartbeat_ack",
                        "timestamp": last_heartbeat.isoformat(),
                    })
                elif msg_type == "agent_data":
                    payload = msg.get("data", {})
                    await manager.broadcast_to_tenant(tenant_id, {
                        "type": "agent_update",
                        "agent_id": agent_id,
                        "data": payload,
                    })
                elif msg_type == "command_response":
                    cmd_id = msg.get("command_id")
                    await manager.broadcast_to_tenant(tenant_id, {
                        "type": "command_response",
                        "agent_id": agent_id,
                        "command_id": cmd_id,
                        "result": msg.get("result", {}),
                    })

        receive_task = asyncio.create_task(receive_loop())

        while True:
            cmd = await command_queue.get()
            await manager.send_personal(websocket, {
                "type": "command",
                "command_id": str(uuid.uuid4()),
                "agent_id": agent_id,
                "action": cmd.get("action"),
                "payload": cmd.get("payload", {}),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    except (WebSocketDisconnect, Exception):
        receive_task.cancel() if 'receive_task' in dir() else None
    finally:
        heartbeat_task.cancel()
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/incidents/{incident_id}")
async def websocket_incident(websocket: WebSocket, incident_id: str):
    """Live incident watcher. Pushes timeline updates, notes, and status changes."""
    user = await _ws_authenticate(websocket)
    if not user:
        return

    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)
    await manager.watch_incident(incident_id, websocket)

    try:
        await manager.send_personal(websocket, {
            "type": "incident_watching",
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type", "")
            if msg_type == "incident_update":
                await manager.broadcast_incident_update(incident_id, tenant_id, {
                    "type": "incident_update",
                    "incident_id": incident_id,
                    "data": msg.get("data", {}),
                    "by": user["user_id"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            elif msg_type == "incident_note":
                await manager.broadcast_incident_update(incident_id, tenant_id, {
                    "type": "incident_note",
                    "incident_id": incident_id,
                    "note": msg.get("note", ""),
                    "by": user["user_id"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            elif msg_type == "incident_timeline":
                await manager.broadcast_incident_update(incident_id, tenant_id, {
                    "type": "incident_timeline",
                    "incident_id": incident_id,
                    "entry": msg.get("entry", ""),
                    "by": user["user_id"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)
