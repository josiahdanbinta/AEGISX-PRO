"""
AEGIS - Smart AI-Driven Notification Service
AI determines notification routing: who gets notified, at what severity,
through which channel, and when. Suppresses noise, escalates critical.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


class SmartNotificationEngine:
    """
    AI-driven notification routing with:
    - Severity-based escalation chains
    - Time-of-day awareness (quiet hours)
    - Duplicate suppression (don't flood the same alert)
    - Channel preference learning
    - Critical alert bypass (always notify, regardless of settings)
    """

    def __init__(self):
        self._recent_alerts: Dict[str, List[datetime]] = {}
        self._suppression_window = 300  # 5 min
        self._critical_always = True

    def should_notify(self, alert: Dict[str, Any],
                       user_prefs: Optional[Dict] = None) -> Dict[str, Any]:
        severity = alert.get("severity", "low")
        confidence = alert.get("confidence", 0.5)
        rule_name = alert.get("rule_name", "")

        alert_key = f"{rule_name}:{alert.get('source_ip', '')}:{alert.get('hostname', '')}"

        now = datetime.now(timezone.utc)
        if alert_key not in self._recent_alerts:
            self._recent_alerts[alert_key] = []
        self._recent_alerts[alert_key] = [
            t for t in self._recent_alerts[alert_key]
            if (now - t).total_seconds() < self._suppression_window
        ]

        if severity == "critical" and self._critical_always:
            self._recent_alerts[alert_key].append(now)
            return self._build_decision(True, "immediate", ["slack", "pagerduty", "email"],
                                         alert, "Critical alert â€” always notify")

        if severity == "high" and confidence > 0.7:
            self._recent_alerts[alert_key].append(now)
            return self._build_decision(True, "immediate", ["slack", "email"],
                                         alert, "High-confidence alert")

        recent_count = len(self._recent_alerts[alert_key])
        if recent_count >= 3:
            return self._build_decision(False, "suppressed", [],
                                         alert, f"Suppressed: {recent_count} occurrences in 5min")

        hour = now.hour
        is_quiet_hours = False
        if user_prefs:
            q_start = user_prefs.get("quiet_hours_start")
            q_end = user_prefs.get("quiet_hours_end")
            if q_start is not None and q_end is not None:
                is_quiet_hours = q_start <= hour < q_end

        if severity == "critical":
            channels = ["slack", "pagerduty", "email"]
            urgency = "immediate"
        elif severity == "high":
            channels = ["slack", "email"] if not is_quiet_hours else ["email"]
            urgency = "immediate" if not is_quiet_hours else "delayed"
        elif severity == "medium":
            channels = ["slack"] if not is_quiet_hours else []
            urgency = "batch"
            if recent_count > 0:
                return self._build_decision(False, "suppressed", [], alert,
                                             "Medium severity, already notified")
        else:
            channels = []
            urgency = "none"
            return self._build_decision(False, "suppressed", [], alert,
                                         "Low severity, not notifying")

        if user_prefs:
            enabled = user_prefs.get("enabled_channels", [])
            if enabled:
                channels = [c for c in channels if c in enabled]
            min_sev = user_prefs.get("alert_severity_threshold", "low")
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            if sev_map.get(severity, 0) < sev_map.get(min_sev, 0):
                return self._build_decision(False, "suppressed", [], alert,
                                             f"Below threshold ({min_sev})")

        if channels:
            self._recent_alerts[alert_key].append(now)

        return self._build_decision(bool(channels), urgency, channels, alert,
                                     "Notification routed" if channels else "No channels match")

    def _build_decision(self, send: bool, urgency: str, channels: List[str],
                         alert: Dict, reason: str) -> Dict[str, Any]:
        return {
            "should_notify": send,
            "urgency": urgency,
            "channels": channels,
            "reason": reason,
            "alert_id": alert.get("id"),
            "severity": alert.get("severity"),
            "decision_time": datetime.now(timezone.utc).isoformat(),
        }

    def get_escalation_chain(self, severity: str) -> List[Dict]:
        chains = {
            "critical": [
                {"role": "soc_manager", "timeout_minutes": 5, "channels": ["pagerduty", "slack"]},
                {"role": "soc_analyst_l3", "timeout_minutes": 10, "channels": ["slack", "email"]},
                {"role": "soc_analyst_l2", "timeout_minutes": 15, "channels": ["slack"]},
                {"role": "soc_analyst_l1", "timeout_minutes": 30, "channels": ["email"]},
            ],
            "high": [
                {"role": "soc_analyst_l3", "timeout_minutes": 15, "channels": ["slack", "email"]},
                {"role": "soc_analyst_l2", "timeout_minutes": 30, "channels": ["slack"]},
                {"role": "soc_analyst_l1", "timeout_minutes": 60, "channels": ["email"]},
            ],
            "medium": [
                {"role": "soc_analyst_l2", "timeout_minutes": 60, "channels": ["slack"]},
                {"role": "soc_analyst_l1", "timeout_minutes": 240, "channels": ["email"]},
            ],
            "low": [
                {"role": "soc_analyst_l1", "timeout_minutes": 480, "channels": ["email"]},
            ],
        }
        return chains.get(severity, chains["low"])


smart_notifications = SmartNotificationEngine()
