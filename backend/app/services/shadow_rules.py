"""
AEGIS - Shadow Rule Engine (A/B Testing for Detection Rules)
Tier 4: Shadow evaluation â€” rules evaluated silently without alerting,
enabling safe testing of new/pre-release detection rules in production.
"""
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DetectionRule

logger = logging.getLogger(__name__)

SHADOW_RESULTS_EXPIRE = 86400  # 24 hours

DEFAULT_WEIGHTS = {
    "process_create": 1.0,
    "powershell": 1.5,
    "wmi_event": 1.3,
    "service_event": 1.2,
    "registry_event": 0.8,
    "authentication": 0.7,
    "network_connect": 0.6,
    "dns_query": 0.5,
    "file_create": 0.4,
    "generic": 0.3,
}


class ShadowRuleResult:
    """Result of a shadow evaluation â€” not promoted to alert."""

    __slots__ = ('rule_id', 'rule_name', 'matched', 'false_positive', 'event_type',
                 'severity_estimate', 'elapsed_ms', 'sample_event', 'evaluated_at')

    def __init__(self, rule_id: str, rule_name: str, matched: bool,
                 event_type: str = "generic", severity_estimate: str = "low",
                 elapsed_ms: float = 0, sample_event: Optional[Dict] = None):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.matched = matched
        self.false_positive = False
        self.event_type = event_type
        self.severity_estimate = severity_estimate
        self.elapsed_ms = elapsed_ms
        self.sample_event = sample_event or {}
        self.evaluated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "matched": self.matched,
            "false_positive": self.false_positive,
            "event_type": self.event_type,
            "severity_estimate": self.severity_estimate,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "evaluated_at": self.evaluated_at,
        }

    @property
    def signal_weight(self) -> float:
        return DEFAULT_WEIGHTS.get(self.event_type, 0.3)


class ShadowRuleEngine:
    """
    Evaluates detection rules in shadow mode â€” full evaluation but no alert generation.
    Supports A/B testing of new rules against production traffic.
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._results: Dict[str, List[ShadowRuleResult]] = {}
        self._stats: Dict[str, Dict[str, Any]] = {}
        self._ab_tests: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, rule: DetectionRule, events: List[Dict[str, Any]],
                 variant: str = "shadow") -> List[ShadowRuleResult]:
        """
        Evaluate a rule against events without triggering alerts.
        variant: 'shadow' (production) or 'candidate' (ab_test)
        """
        import time
        results = []
        rule_id = str(rule.id)
        rule_name = rule.name or "unknown"

        rule_content = rule.rule_content or {}
        sigma_level = rule_content.get("level", "medium") if isinstance(rule_content, dict) else "medium"

        for event in events:
            start = time.monotonic()
            matched = self._check_rule_match(rule, event)
            elapsed = (time.monotonic() - start) * 1000

            event_type = self._classify_event_type(event)
            result = ShadowRuleResult(
                rule_id=rule_id,
                rule_name=rule_name,
                matched=matched,
                event_type=event_type,
                severity_estimate=sigma_level,
                elapsed_ms=elapsed,
                sample_event=event if matched else None,
            )
            results.append(result)

        key = variant
        if key not in self._results:
            self._results[key] = []
        self._results[key].extend(results)

        self._update_stats(variant, rule_id, rule_name, results)

        return results

    def _check_rule_match(self, rule: DetectionRule, event: Dict[str, Any]) -> bool:
        """Simulate rule matching without creating alerts."""
        rule_content = rule.rule_content or {}
        if not isinstance(rule_content, dict) or not rule_content:
            return False

        detection = rule_content.get("detection", {})
        if not detection:
            return False

        condition = detection.get("condition", "")
        if not condition:
            return False

        selections = {}
        for key, value in detection.items():
            if key in ("condition", "timeframe"):
                continue
            selections[key] = value

        try:
            eval_context = {}
            event_str = json.dumps(event).lower()
            for sel_name, sel_def in selections.items():
                if isinstance(sel_def, dict):
                    eval_context[sel_name] = self._evaluate_selection(sel_def, event_str)
                elif isinstance(sel_def, list):
                    eval_context[sel_name] = any(
                        s.lower() in event_str for s in sel_def
                    )

            cond_safe = condition
            for name, val in eval_context.items():
                cond_safe = cond_safe.replace(name, str(val))
            cond_safe = cond_safe.replace(" and ", " and ").replace(" or ", " or ")
            cond_safe = cond_safe.replace(" not ", " not ")

            result = bool(eval(cond_safe, {"__builtins__": {}}))
            return result
        except Exception:
            return False

    def _evaluate_selection(self, sel_def: Dict[str, Any], event_str: str) -> bool:
        if not isinstance(sel_def, dict):
            return False

        for field, value in sel_def.items():
            if isinstance(value, list):
                for item in value:
                    if field.lower() in event_str and str(item).lower() in event_str:
                        return True
            elif isinstance(value, (str, int)):
                if field.lower() in event_str and str(value).lower() in event_str:
                    return True
            elif isinstance(value, dict):
                for modifier, mod_val in value.items():
                    if modifier == "contains":
                        if str(mod_val).lower() in event_str:
                            return True
                    elif modifier in ("startswith", "endswith"):
                        pass
        return False

    def _classify_event_type(self, event: dict) -> str:
        data_str = json.dumps(event).lower()
        if "powershell" in data_str or "scriptblock" in data_str:
            return "powershell"
        if "process" in data_str:
            return "process_create"
        if "wmi" in data_str:
            return "wmi_event"
        if "service" in data_str and "install" in data_str:
            return "service_event"
        if "reg" in data_str:
            return "registry_event"
        if "login" in data_str or "logon" in data_str:
            return "authentication"
        if "network" in data_str or "connect" in data_str:
            return "network_connect"
        if "dns" in data_str:
            return "dns_query"
        if "file" in data_str and "create" in data_str:
            return "file_create"
        return "generic"

    def _update_stats(self, variant: str, rule_id: str, rule_name: str,
                       results: List[ShadowRuleResult]):
        key = f"{variant}:{rule_id}"
        if key not in self._stats:
            self._stats[key] = {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "variant": variant,
                "total_evaluated": 0,
                "total_matched": 0,
                "total_false_positives": 0,
                "avg_elapsed_ms": 0,
                "event_types": {},
                "first_evaluated": None,
                "last_evaluated": None,
            }

        stats = self._stats[key]
        matched = [r for r in results if r.matched]
        stats["total_evaluated"] += len(results)
        stats["total_matched"] += len(matched)
        stats["total_false_positives"] += sum(1 for r in matched if r.false_positive)
        total_elapsed = sum(r.elapsed_ms for r in results)
        total_count = stats["total_evaluated"]
        stats["avg_elapsed_ms"] = round(total_elapsed / max(total_count, 1), 3)

        for r in results:
            et = r.event_type
            if et not in stats["event_types"]:
                stats["event_types"][et] = {"evaluated": 0, "matched": 0}
            stats["event_types"][et]["evaluated"] += 1
            if r.matched:
                stats["event_types"][et]["matched"] += 1

        if not stats["first_evaluated"]:
            stats["first_evaluated"] = datetime.now(timezone.utc).isoformat()
        stats["last_evaluated"] = datetime.now(timezone.utc).isoformat()

    def get_shadow_stats(self, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if rule_id:
            return [
                s for k, s in self._stats.items()
                if s["rule_id"] == rule_id
            ]
        return list(self._stats.values())

    def compare_ab_test(self, rule_id: str) -> Dict[str, Any]:
        """Compare shadow vs candidate A/B test results for a rule."""
        shadow_key = f"shadow:{rule_id}"
        candidate_key = f"candidate:{rule_id}"

        shadow = self._stats.get(shadow_key, {})
        candidate = self._stats.get(candidate_key, {})

        shadow_matches = shadow.get("total_matched", 0)
        candidate_matches = candidate.get("total_matched", 0)
        shadow_total = max(shadow.get("total_evaluated", 1), 1)

        return {
            "rule_id": rule_id,
            "shadow_match_rate": round(shadow_matches / max(shadow_total, 1), 4),
            "candidate_match_rate": round(candidate_matches / max(candidate.get("total_evaluated", 1), 1), 4),
            "shadow_total": shadow_total,
            "candidate_total": candidate.get("total_evaluated", 0),
            "recommendation": "promote" if candidate_matches < shadow_matches * 2 else "review",
            "false_positive_risk": "low" if candidate_matches < shadow_matches * 1.2 else "high",
        }

    def clear_results(self, rule_id: Optional[str] = None):
        if rule_id:
            self._results = {
                k: v for k, v in self._results.items()
                if not any(r.rule_id == rule_id for r in v)
            }
            self._stats = {
                k: v for k, v in self._stats.items()
                if v["rule_id"] != rule_id
            }
        else:
            self._results.clear()
            self._stats.clear()


shadow_engines: Dict[str, ShadowRuleEngine] = {}


def get_shadow_engine(tenant_id: str) -> ShadowRuleEngine:
    if tenant_id not in shadow_engines:
        shadow_engines[tenant_id] = ShadowRuleEngine(tenant_id)
    return shadow_engines[tenant_id]
