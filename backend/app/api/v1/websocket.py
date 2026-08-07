"""
AEGIS - Real-Time WebSocket Endpoints
Live dashboard updates, agent communication, alert streaming, incident watching.
Event-driven via Redis PubSub (EventBus) â€” no polling.
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session_factory
from app.core.security import decode_token
from app.models import Alert, Asset, Incident, Agent

router = APIRouter()


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

    async def send_personal(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    async def broadcast_to_tenant(self, tenant_id: str, message: dict):
        for ws in self.active_connections.get(tenant_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                await self.disconnect(tenant_id, ws)

    async def broadcast_incident(self, incident_id: str, tenant_id: str, message: dict):
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
            incidents = await db.execute(select(func.count(Incident.id)).where(Incident.tenant_id == tid))
            alerts = await db.execute(select(func.count(Alert.id)).where(Alert.tenant_id == tid))
            assets = await db.execute(select(func.count(Asset.id)).where(Asset.tenant_id == tid))
            agents = await db.execute(
                select(func.count(Agent.id)).where(Agent.tenant_id == tid, Agent.status == "online")
            )
            open_inc = await db.execute(
                select(func.count(Incident.id)).where(
                    Incident.tenant_id == tid,
                    Incident.status.in_(["new", "investigating", "in_progress"]),
                )
            )
            return {
                "incidents_total": incidents.scalar() or 0,
                "incidents_open": open_inc.scalar() or 0,
                "alerts_total": alerts.scalar() or 0,
                "assets_total": assets.scalar() or 0,
                "agents_online": agents.scalar() or 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    except Exception:
        return {
            "incidents_total": 0, "incidents_open": 0,
            "alerts_total": 0, "assets_total": 0, "agents_online": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


async def _alert_to_dict(alert: Alert) -> dict:
    return {
        "id": str(alert.id),
        "name": getattr(alert, "title", getattr(alert, "name", "")),
        "title": getattr(alert, "title", ""),
        "severity": getattr(alert, "severity", "medium"),
        "status": getattr(alert, "status", "new"),
        "rule_name": getattr(alert, "rule_name", ""),
        "source": getattr(alert, "source_ip", ""),
        "source_ip": getattr(alert, "source_ip", ""),
        "destination_ip": getattr(alert, "destination_ip", ""),
        "hostname": getattr(alert, "source_asset_id", ""),
        "description": getattr(alert, "description", ""),
        "confidence": getattr(alert, "confidence", 0.5),
        "triggered_at": alert.created_at.isoformat() if alert.created_at else None,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# WebSocket Endpoints â€” Event-Driven via Redis PubSub
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.websocket("/live/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """Real-time dashboard via Redis PubSub. Stats pushed every 10s by background task."""
    user = await _ws_authenticate(websocket)
    if not user:
        return
    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)

    from app.services.event_bus import event_bus

    try:
        initial = await _get_dashboard_stats(tenant_id)
        await manager.send_personal(websocket, {"type": "dashboard_init", "data": initial})

        async for msg in event_bus.subscribe("AEGIS:dashboard:updates"):
            try:
                await manager.send_personal(websocket, msg)
            except Exception:
                break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert streaming via Redis PubSub. Alerts pushed instantly on creation."""
    user = await _ws_authenticate(websocket)
    if not user:
        return
    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)
    tid = uuid.UUID(tenant_id)

    from app.services.event_bus import event_bus

    try:
        await manager.send_personal(websocket, {
            "type": "alerts_connected",
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        async with async_session_factory() as db:
            result = await db.execute(
                select(Alert)
                .where(Alert.tenant_id == tid)
                .order_by(Alert.created_at.desc())
                .limit(20)
            )
            for alert in result.scalars().all():
                await manager.send_personal(websocket, {
                    "type": "alert",
                    "data": await _alert_to_dict(alert),
                })

        async for msg in event_bus.subscribe(f"AEGIS:alerts:{tenant_id}"):
            try:
                await manager.send_personal(websocket, msg)
            except Exception:
                break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/anomalies")
async def websocket_anomalies(websocket: WebSocket):
    """Real-time UEBA anomaly alerts via Redis PubSub."""
    user = await _ws_authenticate(websocket)
    if not user:
        return
    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)

    from app.services.event_bus import event_bus

    try:
        await manager.send_personal(websocket, {
            "type": "anomalies_connected",
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        async for msg in event_bus.subscribe(f"AEGIS:anomaly:{tenant_id}"):
            try:
                await manager.send_personal(websocket, msg)
            except Exception:
                break
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/agent/{agent_id}")
async def websocket_agent(websocket: WebSocket, agent_id: str):
    """Bidirectional agent communication with heartbeat monitoring."""
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
                        "type": "agent_offline", "agent_id": agent_id,
                        "reason": "heartbeat_timeout",
                    })
                    await websocket.close(code=4002, reason="Agent heartbeat timeout")
                except Exception:
                    pass
                break

    heartbeat_task = asyncio.create_task(heartbeat_monitor())

    try:
        await manager.send_personal(websocket, {
            "type": "agent_connected", "agent_id": agent_id,
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
                    try:
                        from app.services.event_bus import event_bus
                        await event_bus.agent_heartbeat(agent_id, tenant_id, payload)
                    except Exception:
                        pass
                    await manager.broadcast_to_tenant(tenant_id, {
                        "type": "agent_update", "agent_id": agent_id,
                        "data": payload,
                    })
                elif msg_type == "command_response":
                    cmd_id = msg.get("command_id")
                    await manager.broadcast_to_tenant(tenant_id, {
                        "type": "command_response", "agent_id": agent_id,
                        "command_id": cmd_id, "result": msg.get("result", {}),
                    })

        receive_task = asyncio.create_task(receive_loop())

        while True:
            cmd = await command_queue.get()
            await manager.send_personal(websocket, {
                "type": "command", "command_id": str(uuid.uuid4()),
                "agent_id": agent_id, "action": cmd.get("action"),
                "payload": cmd.get("payload", {}),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    except (WebSocketDisconnect, Exception):
        if 'receive_task' in locals():
            receive_task.cancel()
    finally:
        heartbeat_task.cancel()
        await manager.disconnect(tenant_id, websocket)


@router.websocket("/live/incidents/{incident_id}")
async def websocket_incident(websocket: WebSocket, incident_id: str):
    """Live incident watcher â€” event-driven via Redis PubSub + direct client messages."""
    user = await _ws_authenticate(websocket)
    if not user:
        return
    tenant_id = user["tenant_id"]
    await manager.connect(tenant_id, websocket)
    await manager.watch_incident(incident_id, websocket)

    from app.services.event_bus import event_bus

    try:
        await manager.send_personal(websocket, {
            "type": "incident_watching", "incident_id": incident_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        pubsub_task = asyncio.create_task(_listen_incident_pubsub(incident_id, websocket, tenant_id))

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            msg_type = msg.get("type", "")
            payload = {
                "incident_id": incident_id, "by": user["user_id"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if msg_type == "incident_update":
                payload["type"] = "incident_update"
                payload["data"] = msg.get("data", {})
                await event_bus.incident_update(incident_id, tenant_id, msg.get("data", {}))
            elif msg_type == "incident_note":
                payload["type"] = "incident_note"
                payload["note"] = msg.get("note", "")
            elif msg_type == "incident_timeline":
                payload["type"] = "incident_timeline"
                payload["entry"] = msg.get("entry", "")
            await manager.broadcast_incident(incident_id, tenant_id, payload)
    except (WebSocketDisconnect, asyncio.CancelledError, Exception):
        if 'pubsub_task' in locals():
            pubsub_task.cancel()
    finally:
        await manager.disconnect(tenant_id, websocket)


async def _listen_incident_pubsub(incident_id: str, websocket: WebSocket, tenant_id: str):
    """Listen for incident updates from Redis PubSub and push to client."""
    from app.services.event_bus import event_bus
    try:
        async for msg in event_bus.subscribe(f"AEGIS:incident:{incident_id}"):
            try:
                await websocket.send_json(msg)
            except Exception:
                break
    except asyncio.CancelledError:
        pass
