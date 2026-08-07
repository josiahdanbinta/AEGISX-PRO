"""
AEGISX - Slack Bot Integration
Interactive Slack bot for SOC operations: alert triage, investigation,
AI-powered remediation, and real-time notifications.
Uses Slack Bolt SDK with Socket Mode (no public HTTP endpoint required).
"""
import asyncio
import json
import logging
import re
import signal
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

HAS_SLACK = False
try:
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    HAS_SLACK = True
except ImportError:
    pass


class AEGISXSlackBot:
    """Slack bot for SOC operations with slash commands and interactive messages."""

    def __init__(self):
        self.app = None
        self.handler = None
        self._bot_token = getattr(settings, 'SLACK_BOT_TOKEN', None)
        self._app_token = getattr(settings, 'SLACK_APP_TOKEN', None)
        self._signing_secret = getattr(settings, 'SLACK_SIGNING_SECRET', None)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self):
        if not HAS_SLACK:
            logger.warning("slack-bolt not installed; pip install slack-bolt")
            return

        if not self._bot_token or not self._app_token:
            logger.warning("SLACK_BOT_TOKEN or SLACK_APP_TOKEN not configured")
            return

        self.app = App(token=self._bot_token)
        self._register_commands()
        self._register_actions()
        self._running = True

        self.handler = SocketModeHandler(self.app, self._app_token)
        self._thread = threading.Thread(target=self._run_handler, daemon=True)
        self._thread.start()
        logger.info("Slack bot started (Socket Mode)")

    def _run_handler(self):
        self.handler.start()

    def stop(self):
        self._running = False
        if self.handler:
            self.handler.close()
        logger.info("Slack bot stopped")

    # ── Slash Commands ────────────────────────────────────────

    def _register_commands(self):
        self.app.command("/aegisx-alerts")(self._cmd_alerts)
        self.app.command("/aegisx-investigate")(self._cmd_investigate)
        self.app.command("/aegisx-remediate")(self._cmd_remediate)
        self.app.command("/aegisx-status")(self._cmd_status)
        self.app.command("/aegisx-help")(self._cmd_help)
        self.app.command("/aegisx-search")(self._cmd_search)

    async def _cmd_alerts(self, ack, command, respond):
        await ack()
        tenant = command.get("text", "").strip() or "default"
        try:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(Alert).where(
                        Alert.tenant_id == uuid.UUID(tenant) if self._is_uuid(tenant) else True,
                        Alert.status == "new",
                    ).order_by(Alert.created_at.desc()).limit(20)
                )
                alerts = result.scalars().all()

            if not alerts:
                await respond("No open alerts found.")
                return

            blocks = [{
                "type": "header",
                "text": {"type": "plain_text", "text": f"Top Open Alerts ({len(alerts)})"}
            }]

            for al in alerts[:10]:
                sev_emoji = {"critical": ":red_circle:", "high": ":large_orange_diamond:",
                              "medium": ":large_yellow_circle:", "low": ":large_blue_circle:"}
                emoji = sev_emoji.get(al.severity, ":white_circle:")
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{al.title[:100]}*\n"
                                f"Severity: `{al.severity}` | Confidence: {al.confidence:.0%}\n"
                                f"Rule: {al.rule_name or 'N/A'} | {al.source_ip or 'N/A'}"
                    },
                    "accessory": {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Investigate"},
                        "value": f"investigate_{al.id}",
                        "action_id": "investigate_alert",
                    }
                })

            await respond(blocks=blocks, text="Open alerts")
        except Exception as e:
            await respond(f"Error fetching alerts: {e}")

    async def _cmd_investigate(self, ack, command, respond):
        await ack()
        query = command.get("text", "").strip()
        if not query:
            await respond("Usage: `/aegisx-investigate <IP|hostname|user|alert-id>`")
            return

        blocks = [{
            "type": "header",
            "text": {"type": "plain_text", "text": f"Investigation: {query[:50]}"}
        }]

        try:
            if self._is_ip(query):
                blocks.extend(await self._investigate_ip(query))
            elif self._is_uuid(query):
                blocks.extend(await self._investigate_alert(query))
            else:
                blocks.extend(await self._investigate_host_or_user(query))

            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Auto-Remediate"},
                        "style": "primary",
                        "value": f"remediate_{query}",
                        "action_id": "auto_remediate",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Add to Watchlist"},
                        "value": f"watchlist_{query}",
                        "action_id": "add_watchlist",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Dismiss"},
                        "style": "danger",
                        "value": f"dismiss_{query}",
                        "action_id": "dismiss_alert",
                    },
                ]
            })

        except Exception as e:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"Error: {e}"}})

        await respond(blocks=blocks, text=f"Investigation: {query}")

    async def _investigate_ip(self, ip: str) -> List[Dict]:
        from app.services.threat_intel_pipeline import threat_intel_pipeline
        enrichment = await threat_intel_pipeline.enrich_ioc("ip", ip)
        score = enrichment.get("composite_score", 0)

        fields = [
            {"type": "mrkdwn", "text": f"*IP:* `{ip}`"},
            {"type": "mrkdwn", "text": f"*Risk Level:* {enrichment.get('risk_level', 'unknown').upper()}"},
            {"type": "mrkdwn", "text": f"*Composite Score:* {score:.2f}"},
        ]

        for source, data in enrichment.get("enrichments", {}).items():
            info = f"*{source.upper()}*: "
            if source == "virustotal":
                info += f"{data.get('malicious_votes', 0)}/{data.get('total_votes', 0)} malicious"
            elif source == "abuseipdb":
                info += f"Abuse confidence: {data.get('abuse_confidence_score', 0)}%"
            elif source == "shodan":
                info += f"Ports: {data.get('ports', [])[:5]}"
            fields.append({"type": "mrkdwn", "text": info})

        return [{"type": "section", "fields": fields[:10]}]

    async def _investigate_alert(self, alert_id: str) -> List[Dict]:
        return [{"type": "section", "text": {"type": "mrkdwn",
            "text": f"Alert `{alert_id}` — use `/aegisx-alerts` to see full list."}}]

    async def _investigate_host_or_user(self, query: str) -> List[Dict]:
        return [{"type": "section", "text": {"type": "mrkdwn",
            "text": f"Searching for `{query}` across assets, alerts, and incidents.\n_Results available in AEGISX console._"}}]

    async def _cmd_remediate(self, ack, command, respond):
        await ack()
        text = command.get("text", "").strip()
        parts = text.split()
        if len(parts) < 2:
            await respond("Usage: `/aegisx-remediate <alert-id> <action>`\n"
                          "Actions: isolate, kill, block, reset-password, suspend, quarantine, scan, collect")
            return

        target, action = parts[0], parts[1]
        action_map = {
            "isolate": "isolate_endpoint", "kill": "kill_process",
            "block": "block_ip_firewall", "reset-password": "reset_user_password",
            "suspend": "suspend_user", "quarantine": "quarantine_file",
            "scan": "scan_endpoint", "collect": "collect_forensics",
        }

        mapped = action_map.get(action)
        if not mapped:
            await respond(f"Unknown action: {action}. Use `/aegisx-help` for options.")
            return

        action_def = REMEDIATION_ACTIONS.get(mapped, {})
        risk = action_def.get("risk", "medium")

        if risk in ("high", "critical"):
            await respond({
                "text": f"Remediation requested by {command.get('user_name')}",
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn",
                        "text": f":warning: *Approval Required*\n"
                                f"Action: `{mapped}` on `{target}`\n"
                                f"Risk Level: *{risk.upper()}*\n"
                                f"Requested by: <@{command.get('user_id')}>"}},
                    {"type": "actions", "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": ":white_check_mark: Approve"},
                         "style": "primary", "value": f"approve_{target}_{mapped}",
                         "action_id": "approve_remediation"},
                        {"type": "button", "text": {"type": "plain_text", "text": ":x: Deny"},
                         "style": "danger", "value": f"deny_{target}_{mapped}",
                         "action_id": "deny_remediation"},
                    ]}
                ]
            })
        else:
            from app.services.ai_remediation import ai_remediation
            result = await ai_remediation.execute_action(mapped, {"agent_id": target})
            status = ":white_check_mark:" if result.get("success") else ":x:"
            await respond(f"{status} Auto-remediation `{mapped}` on `{target}`: {result.get('message', result.get('error', 'Done'))}")

    async def _cmd_status(self, ack, command, respond):
        await ack()
        try:
            from app.services.metrics_instrument import poll_db_connections
            await poll_db_connections()

            stats = []
            stats.append(":large_green_circle: AEGISX Platform — Online")
            stats.append(f"Environment: `{settings.APP_ENV}`")
            stats.append(f"Version: `{settings.APP_VERSION}`")
            stats.append(f"Kafka: `{'enabled' if settings.FEATURE_KAFKA else 'disabled'}`")
            stats.append(f"ClickHouse: `{'enabled' if settings.FEATURE_CLICKHOUSE else 'disabled'}`")
            stats.append(f"UEBA: `{'enabled' if settings.FEATURE_UEBA else 'disabled'}`")
            await respond("\n".join(stats))
        except Exception as e:
            await respond(f"Status check failed: {e}")

    async def _cmd_help(self, ack, command, respond):
        await ack()
        await respond({
            "text": "AEGISX SOC Bot Commands",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn",
                "text": "*AEGISX SOC Bot — Commands*\n\n"
                        "`/aegisx-alerts [tenant]` — View open alerts\n"
                        "`/aegisx-investigate <IP|host|user|id>` — Investigate entity\n"
                        "`/aegisx-remediate <target> <action>` — Remediate threat\n"
                        "`/aegisx-search <query>` — Search across platform\n"
                        "`/aegisx-status` — Platform health check\n"
                        "`/aegisx-help` — Show this message\n\n"
                        "Actions: `isolate`, `kill`, `block`, `reset-password`, `suspend`, `quarantine`, `scan`, `collect`"
            }}]
        })

    async def _cmd_search(self, ack, command, respond):
        await ack()
        query = command.get("text", "").strip()
        if not query:
            await respond("Usage: `/aegisx-search <query>`")
            return
        await respond(f"Searching for `{query}` across alerts, incidents, assets, and IOCs...\n"
                      f"_Full results available in AEGISX Threat Hunting console._")

    # ── Interactive Actions ────────────────────────────────────

    def _register_actions(self):
        self.app.action("investigate_alert")(self._on_investigate_alert)
        self.app.action("auto_remediate")(self._on_auto_remediate)
        self.app.action("approve_remediation")(self._on_approve)
        self.app.action("deny_remediation")(self._on_deny)
        self.app.action("add_watchlist")(self._on_add_watchlist)
        self.app.action("dismiss_alert")(self._on_dismiss)

    async def _on_investigate_alert(self, ack, body, respond):
        await ack()
        alert_id = body["actions"][0]["value"].replace("investigate_", "")
        await respond(f"Opening investigation for alert `{alert_id}`...\n"
                       f"View details: <http://aegisx/debug|AEGISX Console>")

    async def _on_auto_remediate(self, ack, body, respond):
        await ack()
        target = body["actions"][0]["value"].replace("remediate_", "")
        from app.services.ai_remediation import ai_remediation
        plan = await ai_remediation.analyze_alert({"id": target, "source_ip": target})
        approval_id = ai_remediation.request_approval(plan)

        auto_actions = plan.get("auto_actions", [])
        await respond(
            f":robot_face: *AI Remediation Plan*\n\n"
            + "\n".join(f"• {a['action_name']} ({a['risk']})" for a in plan["recommendations"])
            + f"\n\nAuto-actions queued: {len(auto_actions)}\n"
            f"Approval ID: `{approval_id}`"
        )

    async def _on_approve(self, ack, body, respond):
        await ack()
        value = body["actions"][0]["value"]
        user = body["user"]["username"]
        from app.services.ai_remediation import ai_remediation
        ai_remediation.approve(value.replace("approve_", ""), user)
        await respond(f":white_check_mark: Remediation approved by <@{body['user']['id']}>. Executing...")

    async def _on_deny(self, ack, body, respond):
        await ack()
        value = body["actions"][0]["value"]
        user = body["user"]["username"]
        from app.services.ai_remediation import ai_remediation
        ai_remediation.deny(value.replace("deny_", ""), user, "Denied from Slack")
        await respond(f":x: Remediation denied by <@{body['user']['id']}>.")

    async def _on_add_watchlist(self, ack, body, respond):
        await ack()
        target = body["actions"][0]["value"].replace("watchlist_", "")
        from app.services.soar_executor import SOARExecutor
        soar = SOARExecutor()
        r = await soar.execute_action("add_to_watchlist", {"indicator": target, "indicator_type": "ip", "severity": "high"})
        await soar.close()
        await respond(f":eyes: {'Added' if r.get('success') else 'Failed to add'} `{target}` to watchlist.")

    async def _on_dismiss(self, ack, body, respond):
        await ack()
        await respond("Alert dismissed.")

    # ── Push Notifications ────────────────────────────────────

    async def push_alert(self, channel: str, alert: Dict[str, Any]):
        if not self.app:
            return
        sev_emoji = {"critical": ":rotating_light:", "high": ":warning:",
                      "medium": ":large_yellow_circle:", "low": ":information_source:"}
        emoji = sev_emoji.get(alert.get("severity", "info"), ":bell:")

        blocks = [
            {"type": "header", "text": {"type": "plain_text",
                "text": f"{emoji} {alert['severity'].upper()} Alert"}},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{alert.get('title', 'Untitled')}*\n{alert.get('description', '')[:500]}"}},
        ]

        if alert.get("source_ip"):
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"Source: `{alert['source_ip']}` | Host: `{alert.get('hostname', 'N/A')}`"}})

        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": ":mag: Investigate"},
             "value": f"investigate_{alert.get('id')}", "action_id": "investigate_alert"},
            {"type": "button", "text": {"type": "plain_text", "text": ":shield: Auto-Remediate"},
             "style": "primary", "value": f"remediate_{alert.get('id')}",
             "action_id": "auto_remediate"},
        ]})

        try:
            self.app.client.chat_postMessage(channel=channel, blocks=blocks,
                                              text=f"AEGISX Alert: {alert.get('title', '')}")
        except Exception as e:
            logger.error("Failed to push to Slack: %s", e)

    # ── Helpers ───────────────────────────────────────────────

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s))

    def _is_uuid(self, s: str) -> bool:
        try:
            import uuid
            uuid.UUID(s)
            return True
        except (ValueError, TypeError):
            return False


aegisx_slack_bot = AEGISXSlackBot()

# Lazy imports (avoid circular deps)
from sqlalchemy import select
from app.core.database import async_session_factory
from app.models import Alert
from app.services.ai_remediation import REMEDIATION_ACTIONS
import uuid
