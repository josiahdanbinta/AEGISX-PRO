"""
AEGISX - SOC Chat WebSocket API
Real-time SOC analyst chat with AI assistant bot.
"""
import json
from typing import Any, Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.services.soc_chat import soc_chat

router = APIRouter()


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
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return

    await websocket.accept()

    try:
        await soc_chat.handle_connection(websocket, user_id, username, room_id)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.close(code=1011, reason=str(e)[:120])
        except Exception:
            pass


@router.get("/chat/rooms")
async def get_rooms():
    return {"rooms": soc_chat.get_active_rooms()}


@router.get("/chat/rooms/{room_id}/history")
async def get_room_history(room_id: str, limit: int = Query(100, le=500)):
    return {"room_id": room_id, "messages": soc_chat.get_room_history(room_id, limit)}
