"""
AEGIS - Auto-Containment Service
Automatic containment actions triggered by critical detection events.
Wires AI remediation into the detection pipeline for instant response.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

CONTAINMENT_RULES = [
    {
        "name": "Critical Ransomware â€” Auto-Isolate",
        "condition": {
            "severity": "critical",
            "keywords": ["ransomware", "wannacry", "lockbit", "conti", "ryuk", ".encrypted"],
        },
        "actions": [
            {"action": "isolate_endpoint", "params": {}, "auto": False, "approval_required": True},
            {"action": "collect_forensics", "params": {}, "auto": True},
            {"action": "notify_soc", "params": {}, "auto": True},
        ],
    },
    {
        "name": "Reverse Shell â€” Kill Process",
        "condition": {
            "severity": "critical",
            "keywords": ["reverse_shell", "bash -i >&", "/dev/tcp/", "netcat"],
        },
        "actions": [
            {"action": "kill_process", "params": {}, "auto": True},
            {"action": "block_ip_firewall", "params": {}, "auto": False, "approval_required": True},
            {"action": "collect_forensics", "params": {}, "auto": True},
        ],
    },
    {
        "name": "Credential Dumping â€” Suspend + Reset",
        "condition": {
            "severity": "critical",
            "keywords": ["mimikatz", "lsass", "credential_dump", "procdump"],
        },
        "actions": [
            {"action": "suspend_user", "params": {}, "auto": True},
            {"action": "reset_user_password", "params": {}, "auto": True},
            {"action": "revoke_sessions", "params": {}, "auto": True},
            {"action": "add_to_watchlist", "params": {}, "auto": True},
        ],
    },
    {
        "name": "Defense Evasion â€” Scan + Alert",
        "condition": {
            "severity": "high",
            "keywords": ["defense_evasion", "disable_defense", "stop.*defender", "sc stop"],
        },
        "actions": [
            {"action": "scan_endpoint", "params": {}, "auto": True},
            {"action": "add_to_watchlist", "params": {}, "auto": True},
        ],
    },
    {
        "name": "High-Confidence External Threat â€” Block IP",
        "condition": {
            "severity": "high",
            "confidence": 0.8,
        },
        "actions": [
            {"action": "block_ip_edr", "params": {}, "auto": True},
            {"action": "add_to_watchlist", "params": {}, "auto": True},
        ],
    },
    {
        "name": "Any Critical Alert â€” Forensic Collection",
        "condition": {
            "severity": "critical",
        },
        "actions": [
            {"action": "collect_forensics", "params": {}, "auto": True},
            {"action": "notify_soc", "params": {"severity": "critical"}, "auto": True},
        ],
    },
]


class AutoContainmentEngine:
    """Evaluates alerts against containment rules and executes auto-actions."""

    def __init__(self):
        self._action_history: List[Dict] = []
        self._max_history = 1000

    async def evaluate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        severity = alert.get("severity", "low")
        title = (alert.get("title", "") + " " + alert.get("description", "")).lower()
        confidence = float(alert.get("confidence", 0.5))
        alert_type = alert.get("rule_name", "")

        triggered_rules = []
        for rule in CONTAINMENT_RULES:
            cond = rule["condition"]

            sev_match = cond.get("severity")
            if sev_match:
                sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                if sev_map.get(severity, 0) < sev_map.get(sev_match, 0):
                    continue

            if "keywords" in cond:
                if not any(kw.lower() in title or kw.lower() in alert_type.lower()
                            for kw in cond["keywords"]):
                    continue

            if "confidence" in cond:
                if confidence < cond["confidence"]:
                    continue

            triggered_rules.append(rule)

        results = {"triggered": len(triggered_rules), "rules": [], "auto_actions": [],
                    "approval_actions": [], "containment_active": False}

        for rule in triggered_rules:
            rule_result = {"rule_name": rule["name"], "actions": []}
            for action_def in rule["actions"]:
                action_result = {
                    "action": action_def["action"],
                    "auto": action_def.get("auto", False),
                    "approval_required": action_def.get("approval_required", False),
                    "status": "pending",
                }

                if action_def.get("auto") and not action_def.get("approval_required"):
                    try:
                        from app.services.ai_remediation import ai_remediation
                        result = await ai_remediation.execute_action(
                            action_def["action"],
                            {**action_def.get("params", {}),
                             "source_ip": alert.get("source_ip"),
                             "hostname": alert.get("hostname"),
                             "process_name": alert.get("process_name"),
                             "severity": severity,
                             "indicator": alert.get("source_ip") or alert.get("hostname", "unknown"),
                             "indicator_type": "ip" if alert.get("source_ip") else "hostname",
                            }
                        )
                        action_result["status"] = "executed" if result.get("success") else "failed"
                        action_result["result"] = result
                        results["auto_actions"].append(action_result)
                        results["containment_active"] = True
                        logger.info("Auto-containment: %s â†’ %s",
                                    rule["name"], action_def["action"])
                    except Exception as e:
                        action_result["status"] = "error"
                        action_result["error"] = str(e)
                        logger.error("Auto-containment failed: %s", e)
                else:
                    results["approval_actions"].append(action_result)

                self._add_history(action_result)

            rule_result["actions"] = [a for a in rule_result["actions"]]
            rule_result["actions"].extend(
                [a for a in results["auto_actions"] + results["approval_actions"]
                 if a["action"] in [ad["action"] for ad in rule["actions"]]]
            )
            results["rules"].append(rule_result)

        return results

    def _add_history(self, action_result: Dict):
        action_result["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._action_history.append(action_result)
        if len(self._action_history) > self._max_history:
            self._action_history = self._action_history[-self._max_history:]

    def get_history(self, limit: int = 50) -> List[Dict]:
        return self._action_history[-limit:]

    def get_containment_rules(self) -> List[Dict]:
        return [
            {"name": r["name"], "severity": r["condition"].get("severity"),
             "keywords": r["condition"].get("keywords", []),
             "actions": [a["action"] for a in r["actions"]]}
            for r in CONTAINMENT_RULES
        ]


auto_containment = AutoContainmentEngine()
