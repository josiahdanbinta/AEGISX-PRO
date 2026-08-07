"""
AEGIS - AI-Smart SOC Chat Service
Real-time WebSocket chat between SOC analysts with AI assistant bot.
The AI bot participates in conversations, suggests remediations, explains alerts,
and provides threat intelligence context.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class SOCChatRoom:
    """A single chat room (per incident or general SOC)."""

    def __init__(self, room_id: str, room_type: str = "general"):
        self.room_id = room_id
        self.room_type = room_type  # "general", "incident", "alert"
        self.messages: List[Dict] = []
        self.participants: Set[str] = set()
        self._websockets: Dict[str, Any] = {}

    def join(self, user_id: str, ws):
        self.participants.add(user_id)
        self._websockets[user_id] = ws
        self._broadcast_system(f"User {user_id} joined")

    def leave(self, user_id: str):
        self.participants.discard(user_id)
        self._websockets.pop(user_id, None)
        self._broadcast_system(f"User {user_id} left")

    async def send_message(self, user_id: str, username: str, content: str,
                            message_type: str = "chat"):
        msg = {
            "id": str(uuid.uuid4())[:8],
            "room_id": self.room_id,
            "user_id": user_id,
            "username": username,
            "content": content,
            "type": message_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.messages.append(msg)
        if len(self.messages) > 500:
            self.messages = self.messages[-500:]

        await self._broadcast(msg)

        if not user_id.startswith("ai-"):
            ai_response = await self._ai_respond(content)
            if ai_response:
                ai_msg = {
                    "id": str(uuid.uuid4())[:8],
                    "room_id": self.room_id,
                    "user_id": "ai-assistant",
                    "username": "AEGIS AI",
                    "content": ai_response,
                    "type": "ai",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.messages.append(ai_msg)
                await self._broadcast(ai_msg)

    async def _ai_respond(self, user_message: str) -> Optional[str]:
        msg = user_message.lower().strip()

        if any(word in msg for word in ("hi", "hello", "hey", "help")):
            return ("Hello! I'm the AEGIS AI Assistant. I can help you:\n"
                    "â€¢ Investigate alerts and IOCs\n"
                    "â€¢ Suggest remediation actions\n"
                    "â€¢ Explain threat intelligence\n"
                    "â€¢ Run osquery commands\n"
                    "â€¢ Generate incident summaries\n\n"
                    "Try: `investigate 10.0.0.5` or `remediate alert-123` or `summarize incident-456`")

        if "investigate" in msg:
            target = msg.replace("investigate", "").strip().strip("`")
            if target:
                return (f"Investigating `{target}`...\n\n"
                        f":mag: I'll search across:\n"
                        f"â€¢ Threat Intelligence (VT, AbuseIPDB, Shodan)\n"
                        f"â€¢ Active alerts and incidents\n"
                        f"â€¢ Asset inventory\n"
                        f"â€¢ Sigma/Falco detection logs\n\n"
                        f"Use `/AEGIS-investigate {target}` in Slack for full results, "
                        f"or check the Threat Hunting page for detailed analysis.")

        if "remediate" in msg:
            return (":shield: I can suggest remediation actions. Available:\n"
                    "â€¢ `isolate_endpoint` â€” Quarantine from network\n"
                    "â€¢ `kill_process` â€” Terminate malicious process\n"
                    "â€¢ `block_ip_firewall` â€” Block at perimeter\n"
                    "â€¢ `quarantine_file` â€” Isolate suspicious file\n"
                    "â€¢ `reset_user_password` â€” Force credential change\n"
                    "â€¢ `suspend_user` â€” Disable compromised account\n"
                    "â€¢ `collect_forensics` â€” Gather evidence\n\n"
                    "Use `/AEGIS-remediate` in Slack or the SOAR console to execute.")

        if "summarize" in msg or "summary" in msg:
            return (":clipboard: I can generate AI-powered summaries of incidents. "
                    "Use the AI Insights panel in the incident detail page, "
                    "or `/AEGIS-investigate <incident-id>` for a quick summary.")

        if "mitre" in msg or "tactic" in msg:
            return (":crossed_swords: I can map alerts to MITRE ATT&CK techniques. "
                    "Check the MITRE ATT&CK tab in the Threat Intel page for full mappings.")

        if any(word in msg for word in ("osquery", "query", "sql")):
            return (":gear: I can help build osquery queries. Try these templates:\n"
                    "â€¢ `list_processes` â€” All running processes\n"
                    "â€¢ `list_listening_ports` â€” Network listeners\n"
                    "â€¢ `list_startup_items` â€” Persistence mechanisms\n"
                    "â€¢ `list_kernel_modules` â€” Loaded kernel modules\n\n"
                    "Use `/osquery/templates` API or the Osquery console to schedule queries.")

        for keyword, response in [
            ("status", "Platform is operational. Use `/AEGIS-status` for detailed health metrics."),
            ("alert", "Check `/AEGIS-alerts` for open alerts or the Real-Time Alert Dashboard."),
            ("block", "To block an IP: use `block_ip_firewall` (perimeter) or `block_ip_edr` (endpoints). Requires approval for external IPs."),
            ("isolate", "Isolate endpoint is a high-risk action requiring SOC Manager approval. Use with caution."),
            ("incident", "View incidents at `/incidents` or use `/AEGIS-investigate <id>`."),
            ("playbook", "Run SOAR playbooks from the SOAR console. Use the Playbook Builder to create custom automation."),
            ("password", "Reset a password via the Admin panel or API: `POST /auth/reset-password/request`."),
            ("log", "View logs in Kibana, audit trail in Admin panel, or raw events in ClickHouse."),
            ("dashboard", "Dashboards available at `/dashboard` (Executive) and `/soc` (Operations)."),
        ]:
            if keyword in msg:
                return response

        return None

    async def _broadcast(self, msg: Dict):
        for ws in list(self._websockets.values()):
            try:
                await ws.send_text(json.dumps(msg))
            except Exception:
                pass

    def _broadcast_system(self, text: str):
        import asyncio
        for ws in list(self._websockets.values()):
            try:
                asyncio.ensure_future(ws.send_text(json.dumps({
                    "type": "system",
                    "content": text,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })))
            except Exception:
                pass

    def get_history(self, limit: int = 50) -> List[Dict]:
        return self.messages[-limit:]


class SOCChatService:
    """Manages multiple chat rooms with AI assistant integration."""

    def __init__(self):
        self._rooms: Dict[str, SOCChatRoom] = {}
        self._user_rooms: Dict[str, Set[str]] = {}

    def _get_or_create_room(self, room_id: str, room_type: str = "general") -> SOCChatRoom:
        if room_id not in self._rooms:
            self._rooms[room_id] = SOCChatRoom(room_id, room_type)
        return self._rooms[room_id]

    async def handle_connection(self, ws, user_id: str, username: str,
                                 room_id: str = "soc-general",
                                 room_type: str = "general"):
        room = self._get_or_create_room(room_id, room_type)
        room.join(user_id, ws)

        if user_id not in self._user_rooms:
            self._user_rooms[user_id] = set()
        self._user_rooms[user_id].add(room_id)

        history = room.get_history(50)
        await ws.send_text(json.dumps({"type": "history", "messages": history}))

        try:
            while True:
                raw = await ws.receive_text()
                data = json.loads(raw)
                content = data.get("content", "").strip()
                if content:
                    await room.send_message(user_id, username, content)
        except Exception:
            pass
        finally:
            room.leave(user_id)
            if user_id in self._user_rooms:
                self._user_rooms[user_id].discard(room_id)

    def get_active_rooms(self) -> List[Dict]:
        return [
            {"room_id": r.room_id, "type": r.room_type,
             "participants": len(r.participants), "messages": len(r.messages)}
            for r in self._rooms.values() if r.participants
        ]

    def get_room_history(self, room_id: str, limit: int = 100) -> List[Dict]:
        room = self._rooms.get(room_id)
        return room.get_history(limit) if room else []


soc_chat = SOCChatService()
