"""
AEGIS - SOC Chat WebSocket API
Real-time SOC analyst chat with AI assistant bot and RBAC room access.
"""
import json
from typing import Any, Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.services.soc_chat import soc_chat

router = APIRouter()

ROLE_ROOMS = {
    "super_admin": ["soc-general", "soc-admin", "soc-incidents"],
    "tenant_admin": ["soc-general", "soc-admin", "soc-incidents"],
    "soc_manager": ["soc-general", "soc-admin", "soc-incidents"],
    "soc_analyst_l3": ["soc-general", "soc-incidents"],
    "soc_analyst_l2": ["soc-general", "soc-incidents"],
    "soc_analyst_l1": ["soc-general"],
    "incident_responder": ["soc-general", "soc-incidents"],
    "threat_hunter": ["soc-general"],
}


@router.websocket("/ws/chat")
async def chat_websocket(
    websocket: WebSocket,
    token: str = Query(...),
    room_id: str = Query("soc-general"),
):
    try:
        from app.core.security import decode_token
        payload = decode_token(token)
        if not payload:
            await websocket.close(code=4001, reason="Invalid token")
            return
        user_id = payload.get("sub", "unknown")
        username = payload.get("username", user_id)
        roles = payload.get("roles", [])
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return

    allowed_rooms = set()
    for role in roles:
        allowed_rooms.update(ROLE_ROOMS.get(role, []))

    if room_id not in allowed_rooms:
        await websocket.close(code=4003,
            reason=f"Access denied to room '{room_id}'. Your roles allow: {', '.join(sorted(allowed_rooms))}")
        return

    role_label = next((r for r in roles if r in ROLE_ROOMS), "user")
    display_name = f"{username} [{role_label}]"

    await websocket.accept()

    try:
        await soc_chat.handle_connection(websocket, user_id, display_name, room_id)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.close(code=1011, reason=str(e)[:120])
        except Exception:
            pass


@router.get("/chat/rooms")
async def get_rooms(token: str = Query(...)):
    try:
        from app.core.security import decode_token
        payload = decode_token(token)
        roles = payload.get("roles", []) if payload else []
    except Exception:
        roles = []

    allowed = set()
    for role in roles:
        allowed.update(ROLE_ROOMS.get(role, []))
    if not allowed:
        allowed = {"soc-general"}

    rooms = soc_chat.get_active_rooms()
    return {
        "rooms": rooms,
        "your_roles": roles,
        "available_rooms": sorted(allowed),
    }


@router.get("/chat/rooms/{room_id}/history")
async def get_room_history(room_id: str, token: str = Query(...),
                            limit: int = Query(100, le=500)):
    try:
        from app.core.security import decode_token
        payload = decode_token(token)
        roles = payload.get("roles", []) if payload else []
    except Exception:
        roles = []

    allowed = set()
    for role in roles:
        allowed.update(ROLE_ROOMS.get(role, []))
    if room_id not in allowed:
        return {"error": "Access denied", "available_rooms": sorted(allowed)}

    return {"room_id": room_id, "messages": soc_chat.get_room_history(room_id, limit)}

