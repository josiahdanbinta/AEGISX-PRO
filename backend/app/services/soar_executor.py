"""
AEGISX - SOAR Action Executor
Real implementations for security automation actions
"""
import asyncio
import json
import logging
import smtplib
import subprocess
import uuid as uuid_mod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class SOARExecutor:
    """Executes SOAR playbook actions with real implementations."""

    def __init__(self):
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def execute_action(self, action_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        method_name = f"_action_{action_type}"
        handler = getattr(self, method_name, None)

        if handler is None:
            return {
                "success": False,
                "error": f"Unknown action: {action_type}",
                "message": f"Action '{action_type}' is not implemented",
            }

        try:
            result = await handler(parameters)
            return result
        except Exception as e:
            logger.exception(f"Action '{action_type}' failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Action '{action_type}' execution failed: {e}",
            }

    # ═════════════════════════════════════════════════════════════
    # EMAIL
    # ═════════════════════════════════════════════════════════════

    async def _action_send_email(self, params: Dict[str, Any]) -> Dict[str, Any]:
        to = params.get("to", "")
        subject = params.get("subject", "AEGISX Notification")
        body = params.get("body", "")
        body_html = params.get("body_html")
        cc = params.get("cc")
        smtp_host = params.get("smtp_host", settings.SMTP_HOST)
        smtp_port = int(params.get("smtp_port", settings.SMTP_PORT))
        smtp_user = params.get("smtp_user", settings.SMTP_USER)
        smtp_password = params.get("smtp_password", settings.SMTP_PASSWORD)
        smtp_from = params.get("smtp_from", settings.SMTP_FROM)
        use_tls = params.get("use_tls", settings.SMTP_TLS)

        if not to:
            return {"success": False, "error": "Recipient email address required"}

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = smtp_from
            msg["To"] = to
            if cc:
                msg["Cc"] = cc
            msg.attach(MIMEText(body, "plain", "utf-8"))
            if body_html:
                msg.attach(MIMEText(body_html, "html", "utf-8"))

            if use_tls:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.ehlo()
                server.starttls()
                server.ehlo()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)

            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)

            recipients = [to]
            if cc:
                recipients.extend([addr.strip() for addr in cc.split(",") if addr.strip()])

            server.sendmail(smtp_from, recipients, msg.as_string())
            server.quit()

            return {
                "success": True,
                "message": f"Email sent to {to}",
                "details": {"recipient": to, "subject": subject, "timestamp": datetime.now(timezone.utc).isoformat()},
            }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to send email: {e}"}

    # ═════════════════════════════════════════════════════════════
    # SLACK / TEAMS / WEBHOOK NOTIFICATIONS
    # ═════════════════════════════════════════════════════════════

    async def _action_notify_slack(self, params: Dict[str, Any]) -> Dict[str, Any]:
        message = params.get("message", "")
        webhook_url = params.get("webhook_url") or params.get("webhook_url")
        channel = params.get("channel")
        severity = params.get("severity", "info")

        if not message:
            return {"success": False, "error": "Message content required"}

        if not webhook_url:
            return {
                "success": False,
                "error": "Slack webhook URL required in 'webhook_url' parameter",
                "message": "Slack integration requires webhook_url parameter",
            }

        color_map = {"critical": "#FF0000", "high": "#FF6600", "medium": "#FFCC00",
                      "low": "#36A64F", "info": "#439FE0"}
        color = color_map.get(severity, "#439FE0")

        payload = {
            "attachments": [{
                "color": color,
                "title": f"AEGISX Alert - {severity.upper()}",
                "text": message,
                "footer": f"AEGISX SOAR | {datetime.now(timezone.utc).isoformat()}",
            }]
        }
        if channel:
            payload["channel"] = channel

        try:
            client = await self._get_http_client()
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return {"success": True, "message": "Slack notification sent",
                     "details": {"status_code": resp.status_code, "response": resp.text[:500]}}
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Slack notification failed: {e}"}

    async def _action_notify_teams(self, params: Dict[str, Any]) -> Dict[str, Any]:
        message = params.get("message", "")
        webhook_url = params.get("webhook_url")
        severity = params.get("severity", "info")

        if not message:
            return {"success": False, "error": "Message content required"}

        if not webhook_url:
            return {
                "success": False,
                "error": "Teams webhook URL required in 'webhook_url' parameter",
                "message": "Teams integration requires webhook_url parameter",
            }

        color_map = {"critical": "FF0000", "high": "FF6600", "medium": "FFCC00",
                      "low": "36A64F", "info": "439FE0"}
        theme_color = color_map.get(severity, "439FE0")

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"AEGISX Alert - {severity.upper()}",
            "title": f"AEGISX Alert - {severity.upper()}",
            "text": message,
            "sections": [{
                "text": message,
            }],
        }

        try:
            client = await self._get_http_client()
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return {"success": True, "message": "Teams notification sent",
                     "details": {"status_code": resp.status_code, "response": resp.text[:500]}}
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Teams notification failed: {e}"}

    async def _action_webhook(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        method = params.get("method", "POST").upper()
        payload = params.get("payload", {})
        headers = params.get("headers", {})

        if not url:
            return {"success": False, "error": "Webhook URL required"}

        try:
            client = await self._get_http_client()
            if method == "POST":
                resp = await client.post(url, json=payload, headers=headers)
            elif method == "PUT":
                resp = await client.put(url, json=payload, headers=headers)
            elif method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                return {"success": False, "error": f"Unsupported method: {method}"}

            resp.raise_for_status()
            return {
                "success": True,
                "message": f"Webhook {method} to {url} succeeded",
                "details": {"status_code": resp.status_code, "response": resp.text[:1000]},
            }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Webhook call failed: {e}"}

    # ═════════════════════════════════════════════════════════════
    # SCRIPT EXECUTION
    # ═════════════════════════════════════════════════════════════

    async def _action_execute_script(self, params: Dict[str, Any]) -> Dict[str, Any]:
        command = params.get("command", params.get("script_content", ""))
        timeout_seconds = int(params.get("timeout_seconds", 60))
        shell = params.get("shell", True)

        if not command:
            return {"success": False, "error": "Command to execute is required"}

        if timeout_seconds > 300:
            timeout_seconds = 300

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ) if shell else asyncio.create_subprocess_exec(
                    *command.split(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=timeout_seconds,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {"success": False, "error": f"Script timed out after {timeout_seconds}s",
                         "message": "Command execution timed out"}

            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()

            return {
                "success": proc.returncode == 0,
                "message": f"Command exited with code {proc.returncode}",
                "details": {
                    "exit_code": proc.returncode,
                    "stdout": stdout_str[:5000],
                    "stderr": stderr_str[:5000],
                    "timeout_seconds": timeout_seconds,
                },
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Script timed out after {timeout_seconds}s",
                     "message": "Command execution timed out"}
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Script execution failed: {e}"}

    # ═════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE WATCHLIST
    # ═════════════════════════════════════════════════════════════

    async def _action_add_to_watchlist(self, params: Dict[str, Any]) -> Dict[str, Any]:
        indicator = params.get("indicator", "")
        indicator_type = params.get("indicator_type", "ip")
        description = params.get("description", "Added by SOAR playbook")
        severity = params.get("severity", "high")

        if not indicator:
            return {"success": False, "error": "Indicator value required"}

        valid_types = {"ip", "domain", "url", "hash", "email", "file"}
        if indicator_type not in valid_types:
            return {"success": False, "error": f"Invalid indicator type: {indicator_type}"}

        try:
            from app.core.database import async_session_factory
            from app.models.operational import ThreatIndicator
            from sqlalchemy import select

            async with async_session_factory() as db:
                result = await db.execute(
                    select(ThreatIndicator).where(
                        ThreatIndicator.type == indicator_type,
                        ThreatIndicator.value == indicator,
                    )
                )
                existing = result.scalar_one_or_none()

                if existing:
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.description = existing.description + f"\n[Updated] {description}"
                    existing.is_active = True
                    await db.commit()
                    return {
                        "success": True,
                        "message": f"Updated existing watchlist entry for {indicator}",
                        "details": {"indicator_id": str(existing.id), "indicator": indicator, "type": indicator_type, "action": "updated"},
                    }

                ti = ThreatIndicator(
                    type=indicator_type,
                    value=indicator,
                    confidence=0.8,
                    source="SOAR_playbook",
                    description=description,
                    tags=["soar", "playbook", severity],
                    tlp="amber",
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    is_active=True,
                )
                db.add(ti)
                await db.commit()
                await db.refresh(ti)

                return {
                    "success": True,
                    "message": f"Added {indicator} to threat intelligence watchlist",
                    "details": {"indicator_id": str(ti.id), "indicator": indicator, "type": indicator_type, "action": "created"},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to add to watchlist: {e}"}

    # ═════════════════════════════════════════════════════════════
    # INCIDENT MANAGEMENT
    # ═════════════════════════════════════════════════════════════

    async def _action_create_incident(self, params: Dict[str, Any]) -> Dict[str, Any]:
        title = params.get("title", "SOAR-Generated Incident")
        description = params.get("description", "Created automatically by SOAR playbook")
        severity = params.get("severity", "medium")
        assignee_id = params.get("assignee_id")
        mitre_tactics = params.get("mitre_tactics", [])
        mitre_techniques = params.get("mitre_techniques", [])

        try:
            from app.core.database import async_session_factory
            from app.models.operational import Incident
            import uuid

            async with async_session_factory() as db:
                incident = Incident(
                    title=title,
                    description=description,
                    severity=severity,
                    status="new",
                    mitre_tactics=mitre_tactics if isinstance(mitre_tactics, list) else [],
                    mitre_techniques=mitre_techniques if isinstance(mitre_techniques, list) else [],
                    source_alert_ids=[],
                    risk_score=50,
                )
                if assignee_id:
                    try:
                        incident.assignee_id = uuid.UUID(str(assignee_id))
                    except (ValueError, TypeError):
                        pass

                db.add(incident)
                await db.commit()
                await db.refresh(incident)

                return {
                    "success": True,
                    "message": f"Incident '{title}' created",
                    "details": {"incident_id": str(incident.id), "title": title, "severity": severity,
                                 "status": "new", "created_at": incident.created_at.isoformat() if incident.created_at else None},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to create incident: {e}"}

    async def _action_update_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ticket_id = params.get("ticket_id", params.get("incident_id", ""))
        status = params.get("status")
        severity = params.get("severity")
        resolution = params.get("resolution")
        assignee_id = params.get("assignee_id")

        if not ticket_id:
            return {"success": False, "error": "Ticket/Incident ID required"}

        try:
            from app.core.database import async_session_factory
            from app.models.operational import Incident
            from sqlalchemy import select
            import uuid

            async with async_session_factory() as db:
                try:
                    incident_id = uuid.UUID(str(ticket_id))
                except (ValueError, TypeError):
                    return {"success": False, "error": f"Invalid ticket ID: {ticket_id}"}

                result = await db.execute(select(Incident).where(Incident.id == incident_id))
                incident = result.scalar_one_or_none()

                if not incident:
                    return {"success": False, "error": "Incident not found", "message": f"No incident with ID {ticket_id}"}

                updates = {}
                if status:
                    incident.status = status
                    updates["status"] = status
                    if status == "closed":
                        incident.closed_at = datetime.now(timezone.utc)
                if severity:
                    incident.severity = severity
                    updates["severity"] = severity
                if resolution:
                    incident.resolution = resolution
                    updates["resolution"] = resolution
                if assignee_id:
                    try:
                        incident.assignee_id = uuid.UUID(str(assignee_id))
                        updates["assignee_id"] = str(assignee_id)
                    except (ValueError, TypeError):
                        pass

                await db.commit()

                return {
                    "success": True,
                    "message": f"Ticket {ticket_id} updated",
                    "details": {"incident_id": str(incident.id), "updates": updates},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to update ticket: {e}"}

    # ═════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE ENRICHMENT
    # ═════════════════════════════════════════════════════════════

    async def _action_enrich_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        ip_address = params.get("ip_address", "")

        if not ip_address:
            return {"success": False, "error": "IP address required"}

        enrichment = {}
        sources_used = []

        vt_key = settings.VIRUSTOTAL_API_KEY
        if vt_key:
            try:
                client = await self._get_http_client()
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                    headers={"x-apikey": vt_key},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "country": attrs.get("country"),
                        "as_owner": attrs.get("as_owner"),
                        "last_analysis_stats": attrs.get("last_analysis_stats"),
                        "reputation": attrs.get("reputation"),
                    }
                    sources_used.append("virustotal")
                elif resp.status_code == 404:
                    enrichment["virustotal"] = {"error": "IP not found in VirusTotal"}
            except Exception as e:
                logger.warning(f"VirusTotal enrichment failed for {ip_address}: {e}")

        abuse_key = settings.ABUSEIPDB_API_KEY
        if abuse_key:
            try:
                client = await self._get_http_client()
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip_address, "maxAgeInDays": 90},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    enrichment["abuseipdb"] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore"),
                        "total_reports": data.get("totalReports"),
                        "last_reported_at": data.get("lastReportedAt"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "usage_type": data.get("usageType"),
                        "domain": data.get("domain"),
                    }
                    sources_used.append("abuseipdb")
            except Exception as e:
                logger.warning(f"AbuseIPDB enrichment failed for {ip_address}: {e}")

        if not sources_used:
            return {
                "success": True,
                "message": "No enrichment sources configured (set VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY in config)",
                "details": {"ip_address": ip_address, "sources_used": [], "enrichment": {}},
            }

        return {
            "success": True,
            "message": f"Enriched IP {ip_address} via {', '.join(sources_used)}",
            "details": {"ip_address": ip_address, "sources_used": sources_used, "enrichment": enrichment},
        }

    async def _action_enrich_domain(self, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = params.get("domain", "")

        if not domain:
            return {"success": False, "error": "Domain required"}

        enrichment = {}
        sources_used = []

        vt_key = settings.VIRUSTOTAL_API_KEY
        if vt_key:
            try:
                client = await self._get_http_client()
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": vt_key},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "last_analysis_stats": attrs.get("last_analysis_stats"),
                        "reputation": attrs.get("reputation"),
                        "categories": attrs.get("categories"),
                        "last_https_response_date": attrs.get("last_https_response_date"),
                    }
                    sources_used.append("virustotal")
            except Exception as e:
                logger.warning(f"VirusTotal domain enrichment failed for {domain}: {e}")

        if not sources_used:
            return {
                "success": True,
                "message": "No enrichment sources configured (set VIRUSTOTAL_API_KEY in config)",
                "details": {"domain": domain, "sources_used": [], "enrichment": {}},
            }

        return {
            "success": True,
            "message": f"Enriched domain {domain} via {', '.join(sources_used)}",
            "details": {"domain": domain, "sources_used": sources_used, "enrichment": enrichment},
        }

    async def _action_enrich_hash(self, params: Dict[str, Any]) -> Dict[str, Any]:
        file_hash = params.get("hash", "")

        if not file_hash:
            return {"success": False, "error": "File hash required"}

        enrichment = {}
        sources_used = []

        vt_key = settings.VIRUSTOTAL_API_KEY
        if vt_key:
            try:
                client = await self._get_http_client()
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": vt_key},
                    timeout=15.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    enrichment["virustotal"] = {
                        "last_analysis_stats": attrs.get("last_analysis_stats"),
                        "type_description": attrs.get("type_description"),
                        "meaningful_name": attrs.get("meaningful_name"),
                        "reputation": attrs.get("reputation"),
                        "tags": attrs.get("tags", []),
                    }
                    sources_used.append("virustotal")
            except Exception as e:
                logger.warning(f"VirusTotal hash enrichment failed for {file_hash}: {e}")

        if not sources_used:
            return {
                "success": True,
                "message": "No enrichment sources configured (set VIRUSTOTAL_API_KEY in config)",
                "details": {"hash": file_hash, "sources_used": [], "enrichment": {}},
            }

        return {
            "success": True,
            "message": f"Enriched hash {file_hash} via {', '.join(sources_used)}",
            "details": {"hash": file_hash, "sources_used": sources_used, "enrichment": enrichment},
        }

    # ═════════════════════════════════════════════════════════════
    # USER IDENTITY ACTIONS
    # ═════════════════════════════════════════════════════════════

    async def _action_force_password_reset(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params.get("user_id", "")
        reason = params.get("reason", "Forced by SOAR playbook")

        if not user_id:
            return {"success": False, "error": "User ID required"}

        try:
            from app.core.database import async_session_factory
            from app.models.user import User
            from sqlalchemy import select, update
            import uuid

            async with async_session_factory() as db:
                try:
                    user_uuid = uuid.UUID(str(user_id))
                except (ValueError, TypeError):
                    return {"success": False, "error": f"Invalid user ID: {user_id}"}

                result = await db.execute(select(User).where(User.id == user_uuid))
                user = result.scalar_one_or_none()

                if not user:
                    return {"success": False, "error": "User not found"}

                user.must_change_password = True
                await db.commit()

                return {
                    "success": True,
                    "message": f"Password reset forced for user {user.email}",
                    "details": {"user_id": str(user.id), "email": user.email, "reason": reason,
                                 "must_change_password": True},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to force password reset: {e}"}

    async def _action_suspend_user(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params.get("user_id", "")
        reason = params.get("reason", "Suspended by SOAR playbook")

        if not user_id:
            return {"success": False, "error": "User ID required"}

        try:
            from app.core.database import async_session_factory
            from app.models.user import User
            from sqlalchemy import select
            import uuid

            async with async_session_factory() as db:
                try:
                    user_uuid = uuid.UUID(str(user_id))
                except (ValueError, TypeError):
                    return {"success": False, "error": f"Invalid user ID: {user_id}"}

                result = await db.execute(select(User).where(User.id == user_uuid))
                user = result.scalar_one_or_none()

                if not user:
                    return {"success": False, "error": "User not found"}

                user.status = "suspended"
                await db.commit()

                return {
                    "success": True,
                    "message": f"User {user.email} suspended",
                    "details": {"user_id": str(user.id), "email": user.email, "reason": reason,
                                 "status": "suspended"},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to suspend user: {e}"}

    async def _action_revoke_session(self, params: Dict[str, Any]) -> Dict[str, Any]:
        user_id = params.get("user_id", "")
        reason = params.get("reason", "Session revoked by SOAR playbook")

        if not user_id:
            return {"success": False, "error": "User ID required"}

        try:
            from app.core.database import async_session_factory
            from app.models.token import RefreshToken
            from sqlalchemy import select, update
            import uuid

            async with async_session_factory() as db:
                try:
                    user_uuid = uuid.UUID(str(user_id))
                except (ValueError, TypeError):
                    return {"success": False, "error": f"Invalid user ID: {user_id}"}

                result = await db.execute(
                    select(RefreshToken).where(
                        RefreshToken.user_id == user_uuid,
                        RefreshToken.is_revoked == False,
                    )
                )
                tokens = result.scalars().all()

                revoked_count = 0
                for token in tokens:
                    token.is_revoked = True
                    revoked_count += 1

                await db.commit()

                return {
                    "success": True,
                    "message": f"Revoked {revoked_count} active sessions for user",
                    "details": {"user_id": str(user_uuid), "revoked_sessions": revoked_count, "reason": reason},
                }
        except Exception as e:
            return {"success": False, "error": str(e), "message": f"Failed to revoke sessions: {e}"}

    # ═════════════════════════════════════════════════════════════
    # UNAVAILABLE ACTIONS — clear "requires integration" message
    # ═════════════════════════════════════════════════════════════

    async def _action_block_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Block IP action requires firewall/EDR integration (e.g., Palo Alto, Fortinet, CrowdStrike). Configure an integration in SOAR settings.",
        }

    async def _action_unblock_ip(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Unblock IP action requires firewall integration. Configure an integration in SOAR settings.",
        }

    async def _action_disable_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Disable account requires Active Directory/Azure AD integration. Configure an identity integration in SOAR settings.",
        }

    async def _action_enable_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Enable account requires Active Directory/Azure AD integration. Configure an identity integration in SOAR settings.",
        }

    async def _action_restart_service(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Restart service requires endpoint agent or Ansible integration. Deploy an AEGISX agent on the target endpoint.",
        }

    async def _action_kill_process(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Kill process requires endpoint agent (EDR) integration on the target host.",
        }

    async def _action_isolate_endpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Isolate endpoint requires EDR integration (e.g., CrowdStrike, SentinelOne, Microsoft Defender). Configure integration in SOAR settings.",
        }

    async def _action_release_endpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Release endpoint requires EDR integration. Configure integration in SOAR settings.",
        }

    async def _action_collect_forensics(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Collect forensics requires endpoint agent with forensic capabilities. Deploy AEGISX agent on target endpoint.",
        }

    async def _action_open_jira(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Open Jira ticket requires Jira integration. Configure Jira URL and API token in SOAR integration settings.",
        }

    async def _action_open_servicenow(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Create ServiceNow ticket requires ServiceNow integration. Configure ServiceNow instance and credentials in SOAR settings.",
        }

    async def _action_run_ansible(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Run Ansible playbook requires Ansible Tower/AWX integration. Configure API endpoint in SOAR settings.",
        }

    async def _action_quarantine_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Quarantine file requires EDR integration on the target endpoint. Configure EDR integration in SOAR settings.",
        }

    async def _action_add_firewall_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Add firewall rule requires firewall API integration (e.g., Palo Alto PAN-OS, FortiGate). Configure firewall integration in SOAR settings.",
        }

    async def _action_remove_firewall_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Remove firewall rule requires firewall API integration. Configure firewall integration in SOAR settings.",
        }

    async def _action_scan_endpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Integration required",
            "message": "Scan endpoint requires EDR/AV integration on the target endpoint. Configure integration in SOAR settings.",
        }


_soar_executor: Optional[SOARExecutor] = None


def get_soar_executor() -> SOARExecutor:
    global _soar_executor
    if _soar_executor is None:
        _soar_executor = SOARExecutor()
    return _soar_executor


async def close_soar_executor():
    global _soar_executor
    if _soar_executor:
        await _soar_executor.close()
        _soar_executor = None
