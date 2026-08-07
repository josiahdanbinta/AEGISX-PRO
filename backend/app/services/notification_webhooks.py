"""
AEGISX - Real-Time Notification Webhooks
Tier 6: Push alerts/incidents to Slack, Teams, PagerDuty, Discord, and
generic webhooks from the detection pipeline.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#36A64F",
    "info": "#439FE0",
}


class NotificationWebhookService:
    """Push notifications to external services via webhooks."""

    def __init__(self):
        self._clients: Dict[str, httpx.AsyncClient] = {}

    async def _get_client(self, timeout: float = 30.0) -> httpx.AsyncClient:
        key = str(timeout)
        if key not in self._clients:
            self._clients[key] = httpx.AsyncClient(timeout=timeout)
        return self._clients[key]

    # ── Slack ───────────────────────────────────────────────────

    async def notify_slack(self, webhook_url: str, alert: Dict[str, Any],
                            channel: Optional[str] = None) -> Dict[str, Any]:
        color = SEVERITY_COLORS.get(alert.get("severity", "info"), "#439FE0")
        severity = alert.get("severity", "INFO").upper()

        payload = {
            "attachments": [{
                "color": color,
                "pretext": f":rotating_light: *AEGISX Alert — {severity}*",
                "title": alert.get("title", "Security Alert"),
                "text": alert.get("description", "")[:3000],
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Confidence", "value": f"{alert.get('confidence', 0.5) * 100:.0f}%", "short": True},
                ],
                "footer": f"AEGISX SOAR | {datetime.now(timezone.utc).isoformat()}",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }]
        }

        if channel:
            payload["channel"] = channel

        if alert.get("source_ip"):
            payload["attachments"][0]["fields"].append(
                {"title": "Source IP", "value": alert["source_ip"], "short": True})
        if alert.get("hostname"):
            payload["attachments"][0]["fields"].append(
                {"title": "Host", "value": alert["hostname"], "short": True})
        if alert.get("rule_name"):
            payload["attachments"][0]["fields"].append(
                {"title": "Rule", "value": alert["rule_name"], "short": True})

        try:
            client = await self._get_client()
            resp = await client.post(webhook_url, json=payload)
            return {"success": resp.status_code == 200, "status_code": resp.status_code,
                    "platform": "slack", "response": resp.text[:200]}
        except Exception as e:
            logger.error("Slack notification failed: %s", e)
            return {"success": False, "error": str(e), "platform": "slack"}

    # ── Microsoft Teams ─────────────────────────────────────────

    async def notify_teams(self, webhook_url: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        color = SEVERITY_COLORS.get(alert.get("severity", "info"), "439FE0").lstrip("#")
        severity = alert.get("severity", "INFO").upper()

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": f"AEGISX Alert — {severity}",
            "title": f":rotating_light: {alert.get('title', 'Security Alert')}",
            "text": alert.get("description", "")[:3000],
            "sections": [{
                "facts": [
                    {"name": "Severity", "value": severity},
                    {"name": "Confidence", "value": f"{alert.get('confidence', 0.5) * 100:.0f}%"},
                    {"name": "Time", "value": alert.get("created_at", datetime.now(timezone.utc).isoformat())},
                ]
            }],
        }

        if alert.get("source_ip"):
            payload["sections"][0]["facts"].append({"name": "Source IP", "value": alert["source_ip"]})
        if alert.get("hostname"):
            payload["sections"][0]["facts"].append({"name": "Host", "value": alert["hostname"]})

        try:
            client = await self._get_client()
            resp = await client.post(webhook_url, json=payload)
            return {"success": 200 <= resp.status_code < 300, "status_code": resp.status_code,
                    "platform": "teams", "response": resp.text[:200]}
        except Exception as e:
            logger.error("Teams notification failed: %s", e)
            return {"success": False, "error": str(e), "platform": "teams"}

    # ── PagerDuty ───────────────────────────────────────────────

    async def notify_pagerduty(self, routing_key: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        severity = alert.get("severity", "info")
        pd_severity = "critical" if severity == "critical" else "error" if severity in ("high",) else "warning"

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": alert.get("alert_id") or alert.get("id"),
            "payload": {
                "summary": alert.get("title", "AEGISX Alert"),
                "source": "aegisx-detection",
                "severity": pd_severity,
                "custom_details": {
                    "rule_name": alert.get("rule_name"),
                    "source_ip": alert.get("source_ip"),
                    "hostname": alert.get("hostname"),
                    "confidence": alert.get("confidence"),
                    "description": alert.get("description", "")[:2000],
                },
            },
        }

        try:
            client = await self._get_client()
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=15.0,
            )
            return {"success": resp.status_code == 202, "status_code": resp.status_code,
                    "platform": "pagerduty", "dedup_key": payload["dedup_key"]}
        except Exception as e:
            logger.error("PagerDuty notification failed: %s", e)
            return {"success": False, "error": str(e), "platform": "pagerduty"}

    # ── Discord ─────────────────────────────────────────────────

    async def notify_discord(self, webhook_url: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        color_hex = SEVERITY_COLORS.get(alert.get("severity", "info"), "#439FE0")
        color_int = int(color_hex.lstrip("#"), 16)
        severity = alert.get("severity", "INFO").upper()

        payload = {
            "embeds": [{
                "title": f":rotating_light: {alert.get('title', 'AEGISX Alert')}",
                "description": alert.get("description", "")[:2000],
                "color": color_int,
                "fields": [
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Confidence", "value": f"{alert.get('confidence', 0.5) * 100:.0f}%", "inline": True},
                ],
                "footer": {"text": "AEGISX SOAR"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
        }

        if alert.get("source_ip"):
            payload["embeds"][0]["fields"].append({"name": "Source IP", "value": alert["source_ip"], "inline": True})
        if alert.get("hostname"):
            payload["embeds"][0]["fields"].append({"name": "Host", "value": alert["hostname"], "inline": True})

        try:
            client = await self._get_client()
            resp = await client.post(webhook_url, json=payload)
            return {"success": 200 <= resp.status_code < 300, "status_code": resp.status_code,
                    "platform": "discord"}
        except Exception as e:
            logger.error("Discord notification failed: %s", e)
            return {"success": False, "error": str(e), "platform": "discord"}

    # ── Generic Webhook ─────────────────────────────────────────

    async def notify_webhook(self, url: str, alert: Dict[str, Any],
                              method: str = "POST", headers: Optional[Dict] = None,
                              custom_payload: Optional[Dict] = None) -> Dict[str, Any]:
        payload = custom_payload or {
            "event": "alert.triggered",
            "alert_id": alert.get("id"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "source_ip": alert.get("source_ip"),
            "hostname": alert.get("hostname"),
            "rule_name": alert.get("rule_name"),
            "description": alert.get("description"),
            "timestamp": alert.get("created_at", datetime.now(timezone.utc).isoformat()),
        }

        try:
            client = await self._get_client()
            if method.upper() == "POST":
                resp = await client.post(url, json=payload, headers=headers or {})
            elif method.upper() == "PUT":
                resp = await client.put(url, json=payload, headers=headers or {})
            else:
                return {"success": False, "error": f"Unsupported method: {method}"}

            return {"success": 200 <= resp.status_code < 300, "status_code": resp.status_code,
                    "platform": "webhook", "response": resp.text[:200]}
        except Exception as e:
            logger.error("Webhook notification failed: %s", e)
            return {"success": False, "error": str(e), "platform": "webhook"}

    # ── Batch Notification ──────────────────────────────────────

    async def notify_all_configured(self, alert: Dict[str, Any],
                                     channels: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = []
        for channel in channels:
            channel_type = channel.get("type", "webhook")
            if channel_type == "slack":
                r = await self.notify_slack(channel["webhook_url"], alert, channel.get("channel"))
            elif channel_type == "teams":
                r = await self.notify_teams(channel["webhook_url"], alert)
            elif channel_type == "pagerduty":
                r = await self.notify_pagerduty(channel["routing_key"], alert)
            elif channel_type == "discord":
                r = await self.notify_discord(channel["webhook_url"], alert)
            elif channel_type == "webhook":
                r = await self.notify_webhook(channel["webhook_url"], alert, channel.get("method", "POST"))
            else:
                r = {"success": False, "error": f"Unknown channel type: {channel_type}"}
            results.append(r)

        return {
            "success": any(r.get("success") for r in results),
            "total": len(results),
            "succeeded": sum(1 for r in results if r.get("success")),
            "failed": sum(1 for r in results if not r.get("success")),
            "results": results,
        }

    async def close(self):
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()


notification_webhooks = NotificationWebhookService()
