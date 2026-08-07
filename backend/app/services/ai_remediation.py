"""
AEGIS - AI Auto-Remediation Engine
Analyzes alerts/incidents, generates remediation plans, and executes
approved actions automatically. Requires human approval for critical actions.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.core.config import settings

logger = logging.getLogger(__name__)


class RemediationRisk(str, Enum):
    LOW = "low"        # Auto-execute
    MEDIUM = "medium"  # Require L1 approval
    HIGH = "high"      # Require L2 approval
    CRITICAL = "critical"  # Require SOC Manager approval


REMEDIATION_ACTIONS = {
    "isolate_endpoint": {
        "name": "Isolate Endpoint from Network",
        "risk": RemediationRisk.HIGH,
        "category": "containment",
        "description": "Quarantine the affected endpoint from the network",
        "service": "agent_commander",
        "method": "isolate_endpoint",
        "reversible": True,
    },
    "kill_process": {
        "name": "Kill Malicious Process",
        "risk": RemediationRisk.MEDIUM,
        "category": "containment",
        "description": "Terminate the identified malicious process",
        "service": "agent_commander",
        "method": "kill_process",
        "reversible": False,
    },
    "quarantine_file": {
        "name": "Quarantine Suspicious File",
        "risk": RemediationRisk.LOW,
        "category": "containment",
        "description": "Move suspicious file to quarantine",
        "service": "agent_commander",
        "method": "quarantine_file",
        "reversible": True,
    },
    "block_ip_firewall": {
        "name": "Block IP at Firewall",
        "risk": RemediationRisk.MEDIUM,
        "category": "blocking",
        "description": "Add source IP to firewall blocklist",
        "service": "soar_executor",
        "method": "add_firewall_rule",
        "reversible": True,
    },
    "block_ip_edr": {
        "name": "Block IP via EDR",
        "risk": RemediationRisk.LOW,
        "category": "blocking",
        "description": "Block IP across all endpoints via EDR",
        "service": "soar_executor",
        "method": "block_ip",
        "reversible": True,
    },
    "reset_user_password": {
        "name": "Force Password Reset",
        "risk": RemediationRisk.LOW,
        "category": "identity",
        "description": "Force password reset for compromised account",
        "service": "soar_executor",
        "method": "force_password_reset",
        "reversible": False,
    },
    "suspend_user": {
        "name": "Suspend User Account",
        "risk": RemediationRisk.MEDIUM,
        "category": "identity",
        "description": "Temporarily disable compromised account",
        "service": "soar_executor",
        "method": "suspend_user",
        "reversible": True,
    },
    "revoke_sessions": {
        "name": "Revoke Active Sessions",
        "risk": RemediationRisk.LOW,
        "category": "identity",
        "description": "Force logout all sessions for the user",
        "service": "soar_executor",
        "method": "revoke_session",
        "reversible": False,
    },
    "collect_forensics": {
        "name": "Collect Forensic Evidence",
        "risk": RemediationRisk.LOW,
        "category": "investigation",
        "description": "Gather memory dumps, disk images, logs",
        "service": "agent_commander",
        "method": "collect_forensics",
        "reversible": False,
    },
    "scan_endpoint": {
        "name": "Full Endpoint Scan",
        "risk": RemediationRisk.LOW,
        "category": "investigation",
        "description": "Run full AV/EDR scan on endpoint",
        "service": "agent_commander",
        "method": "scan_endpoint",
        "reversible": False,
    },
    "add_to_watchlist": {
        "name": "Add IOC to Watchlist",
        "risk": RemediationRisk.LOW,
        "category": "intelligence",
        "description": "Add indicator to threat intel watchlist",
        "service": "soar_executor",
        "method": "add_to_watchlist",
        "reversible": False,
    },
    "notify_soc": {
        "name": "Notify SOC Team",
        "risk": RemediationRisk.LOW,
        "category": "communication",
        "description": "Send notification to SOC channels",
        "service": "soar_executor",
        "method": "notify_slack",
        "reversible": False,
    },
}


class AIRemediationEngine:
    """AI-powered automatic remediation with approval gates."""

    def __init__(self):
        self._pending_approvals: Dict[str, Dict] = {}

    # â”€â”€ Analyze & Recommend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        findings = []

        severity = alert.get("severity", "low")
        alert_type = alert.get("rule_name", "")
        source_ip = alert.get("source_ip")
        hostname = alert.get("hostname")
        confidence = float(alert.get("confidence", 0.5))

        if source_ip and not source_ip.startswith(("10.", "192.168.", "172.")):
            findings.append({
                "action": "block_ip_firewall",
                "reason": f"External IP {source_ip} triggered alert with {confidence:.0%} confidence",
                "priority": 1,
            })
            if confidence > 0.7:
                findings.append({
                    "action": "add_to_watchlist",
                    "reason": f"High-confidence external IOC: {source_ip}",
                    "priority": 2,
                })

        if hostname and severity in ("critical", "high") and confidence > 0.6:
            findings.append({
                "action": "collect_forensics",
                "reason": f"High-severity alert on {hostname} â€” collect forensic evidence",
                "priority": 1,
            })
            findings.append({
                "action": "scan_endpoint",
                "reason": f"Run full scan on {hostname} after forensic collection",
                "priority": 2,
            })

        if "credential" in alert_type.lower() or "login" in alert_type.lower():
            findings.append({
                "action": "revoke_sessions",
                "reason": "Credential-related alert â€” revoke active sessions",
                "priority": 1,
            })

        if "ransomware" in alert_type.lower() or "malware" in alert_type.lower():
            findings.append({
                "action": "isolate_endpoint",
                "reason": f"Ransomware/malware alert â€” isolate {hostname or 'endpoint'}",
                "priority": 1,
            })

        if alert.get("process_name"):
            findings.append({
                "action": "kill_process",
                "reason": f"Kill malicious process: {alert['process_name']}",
                "priority": 3,
            })

        findings.sort(key=lambda f: f["priority"])

        plan = {
            "alert_id": alert.get("id"),
            "alert_title": alert.get("title", ""),
            "severity": severity,
            "confidence": confidence,
            "recommendations": [],
            "auto_actions": [],
            "approval_actions": [],
        }

        for f in findings:
            action_def = REMEDIATION_ACTIONS.get(f["action"], {})
            risk = action_def.get("risk", RemediationRisk.MEDIUM)
            rec = {
                "action": f["action"],
                "action_name": action_def.get("name", f["action"]),
                "risk": risk,
                "reason": f["reason"],
                "reversible": action_def.get("reversible", False),
                "category": action_def.get("category", "unknown"),
            }

            if risk == RemediationRisk.LOW:
                plan["auto_actions"].append(rec)
            else:
                plan["approval_actions"].append(rec)
            plan["recommendations"].append(rec)

        return plan

    async def analyze_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        findings = []
        mitre = incident.get("mitre_techniques", [])
        severity = incident.get("severity", "medium")
        affected_assets = incident.get("affected_assets", [])

        for asset in affected_assets[:5]:
            findings.append({
                "action": "collect_forensics",
                "reason": f"Collect evidence from affected asset: {asset}",
                "priority": 1,
            })
            findings.append({
                "action": "scan_endpoint",
                "reason": f"Scan affected asset: {asset}",
                "priority": 2,
            })

        if "T1059" in mitre or "T1003" in mitre:
            findings.append({
                "action": "revoke_sessions",
                "reason": "Credential dumping or command execution detected",
                "priority": 1,
            })

        if "T1486" in mitre or severity == "critical":
            findings.append({
                "action": "isolate_endpoint",
                "reason": "Critical incident â€” isolate affected endpoints",
                "priority": 1,
            })

        if severity in ("high", "critical"):
            findings.append({
                "action": "notify_soc",
                "reason": "Notify SOC via all communication channels",
                "priority": 1,
            })

        findings.sort(key=lambda f: f["priority"])

        plan = {
            "incident_id": incident.get("id"),
            "incident_title": incident.get("title", ""),
            "severity": severity,
            "recommendations": [],
            "auto_actions": [],
            "approval_actions": [],
        }

        for f in findings:
            action_def = REMEDIATION_ACTIONS.get(f["action"], {})
            risk = action_def.get("risk", RemediationRisk.MEDIUM)
            rec = {
                "action": f["action"],
                "action_name": action_def.get("name", f["action"]),
                "risk": risk,
                "reason": f["reason"],
                "reversible": action_def.get("reversible", False),
                "category": action_def.get("category", "unknown"),
            }
            if risk == RemediationRisk.LOW:
                plan["auto_actions"].append(rec)
            else:
                plan["approval_actions"].append(rec)
            plan["recommendations"].append(rec)

        return plan

    # â”€â”€ Execute â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def execute_action(self, action: str, params: Dict[str, Any],
                              executor: str = "soar") -> Dict[str, Any]:
        action_def = REMEDIATION_ACTIONS.get(action)
        if not action_def:
            return {"success": False, "error": f"Unknown action: {action}"}

        if executor == "agent" and action_def["service"] == "agent_commander":
            try:
                agent_id = params.get("agent_id")
                if not agent_id:
                    return {"success": False, "error": "agent_id required"}
                async with async_session_factory() as db:
                    from app.services.agent_commander import AgentCommander
                    commander = AgentCommander(db)
                    result = await commander.queue_command(
                        agent_id, action_def["method"], params,
                    )
                    return {"success": True, "result": result}
            except Exception as e:
                return {"success": False, "error": str(e)}

        try:
            from app.services.soar_executor import SOARExecutor
            soar = SOARExecutor()
            result = await soar.execute_action(action_def["method"], params)
            await soar.close()
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def execute_plan(self, plan: Dict[str, Any], params: Dict[str, Any],
                            approved_by: Optional[str] = None) -> Dict[str, Any]:
        results = {"auto": [], "approved": [], "denied": []}

        for action in plan.get("auto_actions", []):
            r = await self.execute_action(action["action"], params)
            results["auto"].append({"action": action["action"], "result": r})
            logger.info("Auto-remediated: %s â†’ %s", action["action"], r.get("success"))

        if approved_by:
            for action in plan.get("approval_actions", []):
                r = await self.execute_action(action["action"], params)
                results["approved"].append({
                    "action": action["action"],
                    "result": r,
                    "approved_by": approved_by,
                })
                logger.info("Approved remediation: %s by %s â†’ %s",
                            action["action"], approved_by, r.get("success"))

        return results

    async def auto_remediate_alert(self, alert: Dict[str, Any],
                                     agent_id: Optional[str] = None) -> Dict[str, Any]:
        plan = await self.analyze_alert(alert)
        params = {
            "agent_id": agent_id,
            "source_ip": alert.get("source_ip"),
            "hostname": alert.get("hostname"),
            "process_name": alert.get("process_name"),
            "severity": alert.get("severity"),
        }
        results = await self.execute_plan(plan, params)
        return {"plan": plan, "results": results}

    # â”€â”€ Approval Workflow â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def request_approval(self, plan: Dict[str, Any]) -> str:
        approval_id = str(uuid.uuid4())[:12]
        self._pending_approvals[approval_id] = {
            "plan": plan,
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }
        return approval_id

    def get_pending(self, approval_id: str) -> Optional[Dict]:
        return self._pending_approvals.get(approval_id)

    def approve(self, approval_id: str, user: str) -> Optional[Dict]:
        entry = self._pending_approvals.get(approval_id)
        if entry:
            entry["status"] = "approved"
            entry["approved_by"] = user
            entry["approved_at"] = datetime.now(timezone.utc).isoformat()
        return entry

    def deny(self, approval_id: str, user: str, reason: str = "") -> Optional[Dict]:
        entry = self._pending_approvals.get(approval_id)
        if entry:
            entry["status"] = "denied"
            entry["denied_by"] = user
            entry["denial_reason"] = reason
        return entry


ai_remediation = AIRemediationEngine()
