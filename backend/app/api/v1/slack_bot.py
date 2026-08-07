"""
AEGIS - Slack Bot API Router
Manage bot lifecycle, configure channels, test push notifications.
"""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_current_user, RequireSOCManager
from app.services.slack_bot import AEGIS_slack_bot

router = APIRouter()


class SlackTestRequest(BaseModel):
    channel: str = "#soc-alerts"
    message: str = "Test notification from AEGIS"


class SlackConfigRequest(BaseModel):
    bot_token: Optional[str] = None
    app_token: Optional[str] = None
    signing_secret: Optional[str] = None


@router.post("/bot/start", summary="Start the Slack bot")
async def start_bot(current_user: dict = Depends(RequireSOCManager)):
    if not AEGIS_slack_bot._bot_token:
        raise HTTPException(status_code=400, detail="SLACK_BOT_TOKEN not configured")
    if AEGIS_slack_bot._running:
        return {"status": "already_running"}
    AEGIS_slack_bot.start()
    return {"status": "started"}


@router.post("/bot/stop", summary="Stop the Slack bot")
async def stop_bot(current_user: dict = Depends(RequireSOCManager)):
    AEGIS_slack_bot.stop()
    return {"status": "stopped"}


@router.get("/bot/status", summary="Get Slack bot status")
async def bot_status(current_user: dict = Depends(get_current_user)):
    return {
        "running": AEGIS_slack_bot._running,
        "configured": bool(AEGIS_slack_bot._bot_token),
        "socket_mode": True,
    }


@router.post("/test", summary="Send test notification to Slack channel")
async def test_notification(body: SlackTestRequest, current_user: dict = Depends(get_current_user)):
    alert = {
        "id": "test-001",
        "title": body.message,
        "severity": "info",
        "description": "This is a test notification from AEGIS SOC Platform.",
        "source_ip": "192.168.1.1",
        "hostname": "test-endpoint",
    }
    await AEGIS_slack_bot.push_alert(body.channel, alert)
    return {"status": "sent", "channel": body.channel}


@router.post("/push", summary="Push a custom alert to Slack")
async def push_alert(alert: Dict[str, Any], channel: str = "#soc-alerts",
                      current_user: dict = Depends(get_current_user)):
    await AEGIS_slack_bot.push_alert(channel, alert)
    return {"status": "sent", "channel": channel}
