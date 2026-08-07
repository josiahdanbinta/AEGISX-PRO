"""
AEGISX - UEBA Scorer (Tier 4)
User and Entity Behavior Analytics — baseline computation and anomaly detection.
Implements statistical anomaly scoring across multiple behavioral dimensions.
"""
import json
import logging
import math
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# Behavioral Dimensions
# ═══════════════════════════════════════════════════════════════

class BaselineProfile:
    """Statistical baseline for a single entity (user, host, IP)."""

    __slots__ = ('entity_id', 'entity_type', 'count', 'mean', 'm2', 'min_val',
                 'max_val', 'recent_values', 'category_counts')

    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0  # Welford's M2 for running std
        self.min_val = float('inf')
        self.max_val = float('-inf')
        self.recent_values: deque = deque(maxlen=1000)
        self.category_counts: Dict[str, int] = defaultdict(int)

    def update(self, value: float):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)
        self.recent_values.append(value)

    @property
    def variance(self) -> float:
        return self.m2 / max(self.count - 1, 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, value: float) -> float:
        if self.std == 0:
            return 0.0 if value == self.mean else 3.0
        return (value - self.mean) / self.std

    def is_anomalous(self, value: float, threshold: float = 2.5) -> bool:
        return abs(self.z_score(value)) > threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "count": self.count,
            "mean": round(self.mean, 4),
            "std": round(self.std, 4),
            "min": self.min_val if self.min_val != float('inf') else 0,
            "max": self.max_val if self.max_val != float('-inf') else 0,
            "categories": dict(self.category_counts),
        }


class UEBAEngine:
    """UEBA scoring engine with multi-dimensional behavioral baseline."""

    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None
        self._profiles: Dict[str, BaselineProfile] = {}
        self._entity_relationships: Dict[str, set] = defaultdict(set)

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    # ── Profile Management ─────────────────────────────────────

    def _get_profile(self, entity_id: str, entity_type: str) -> BaselineProfile:
        key = f"{entity_type}:{entity_id}"
        if key not in self._profiles:
            self._profiles[key] = BaselineProfile(entity_id, entity_type)
        return self._profiles[key]

    async def _save_profile(self, profile: BaselineProfile):
        redis = await self._get_redis()
        key = f"ueba:profile:{profile.entity_type}:{profile.entity_id}"
        await redis.set(key, json.dumps(profile.to_dict()))
        await redis.expire(key, 86400 * 30)  # 30 day TTL

    async def _load_profile(self, entity_id: str, entity_type: str) -> Optional[BaselineProfile]:
        redis = await self._get_redis()
        key = f"ueba:profile:{entity_type}:{entity_id}"
        data = await redis.get(key)
        if data:
            try:
                parsed = json.loads(data)
                profile = BaselineProfile(entity_id, entity_type)
                profile.count = parsed.get("count", 0)
                profile.mean = parsed.get("mean", 0)
                profile.m2 = (parsed.get("std", 1) ** 2) * max(parsed.get("count", 2) - 1, 1)
                profile.min_val = parsed.get("min", 0)
                profile.max_val = parsed.get("max", 0)
                for cat, count in parsed.get("categories", {}).items():
                    profile.category_counts[cat] = count
                return profile
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    # ── Feature Extraction ──────────────────────────────────────

    def _extract_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        features = {}

        data = event.get("normalized_data", event)
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                data = {}

        severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        features["severity_score"] = float(severity_map.get(
            event.get("severity", "info"), 0
        ))

        event_type = event.get("event_type", "generic")
        event_type_risk = {
            "process_create": 3, "service_event": 3, "powershell": 4,
            "wmi_event": 3, "network_connect": 1, "dns_query": 1,
            "authentication": 2, "file_create": 1, "registry_event": 2,
            "process_access": 2, "generic": 0,
        }
        features["event_type_risk"] = float(event_type_risk.get(event_type, 0))

        features["tag_count"] = float(len(event.get("tags", [])))
        tags = event.get("tags", [])
        features["has_persistence_tag"] = 1.0 if "persistence" in tags else 0.0
        features["has_credential_tag"] = 1.0 if "credential_access" in tags else 0.0
        features["is_internal_ip"] = 1.0 if "internal_ip" in tags else 0.0

        enrichment = event.get("enrichment", {})
        ti = enrichment.get("threat_intel", {})
        features["ti_malicious"] = 1.0 if ti.get("is_malicious") else 0.0
        features["ti_score"] = float(ti.get("score", 0)) / 100.0

        return features

    # ── Scoring ─────────────────────────────────────────────────

    async def score_event(self, tenant_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(event)
        anomaly_scores = {}
        details = {}

        entity_ids = []
        hostname = event.get("hostname")
        username = event.get("username")
        source_ip = event.get("source_ip")

        if hostname:
            entity_ids.append(("host", hostname))
        if username:
            entity_ids.append(("user", username))
        if source_ip:
            entity_ids.append(("ip", source_ip))

        entity_count = float(len(entity_ids) or 1)

        for entity_type, entity_id in entity_ids:
            profile = await self._load_profile(entity_id, entity_type)
            if profile is None:
                profile = self._get_profile(entity_id, entity_type)

            per_entity_scores = []
            for feat_name, feat_value in features.items():
                profile.update(feat_value)
                z = profile.z_score(feat_value) if profile.count > 5 else 0.0
                per_entity_scores.append(abs(z))
                details[f"{entity_type}_{feat_name}_z"] = round(z, 3)

            await self._save_profile(profile)

            if per_entity_scores:
                avg_z = sum(per_entity_scores) / len(per_entity_scores)
                anomaly_scores[f"{entity_type}"] = avg_z
                details[f"{entity_type}_avg_z"] = round(avg_z, 3)

        score_vals = list(anomaly_scores.values())
        if score_vals:
            composite_score = sum(score_vals) / len(score_vals)
            composite_score = min(composite_score / 5.0, 1.0)
        else:
            composite_score = 0.0

        max_baseline_deviation = max(score_vals) if score_vals else 0.0

        mitre = []
        tags = event.get("tags", [])
        if "credential_access" in tags:
            mitre.append("T1003")
        if "persistence" in tags:
            mitre.append("T1547")
        if event.get("event_type") == "powershell":
            mitre.append("T1059.001")
        if event.get("event_type") == "service_event":
            mitre.append("T1543")
        if features.get("ti_malicious", 0) > 0:
            mitre.append("T1071")

        return {
            "anomaly_score": round(composite_score, 4),
            "baseline_deviation": round(max_baseline_deviation, 4),
            "entity_scores": anomaly_scores,
            "features": {k: round(v, 3) for k, v in features.items()},
            "details": details,
            "mitre_techniques": mitre,
            "confidence": round(composite_score * 1.2, 4),  # UEBA confidence boost
        }

    # ── Correlation Scoring ────────────────────────────────────

    def correlate_entities(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        entity_map: Dict[str, List[int]] = defaultdict(list)

        for idx, event in enumerate(events):
            for field in ("hostname", "username", "source_ip"):
                val = event.get(field)
                if val:
                    entity_map[f"{field}:{val}"].append(idx)

        correlations = []
        for entity_key, event_indices in entity_map.items():
            if len(event_indices) >= 2:
                related_events = [events[i] for i in event_indices]
                severities = [e.get("severity", "info") for e in related_events]
                sev_weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                max_sev = max(severities, key=lambda s: sev_weights.get(s, 1))

                correlations.append({
                    "entity": entity_key,
                    "event_count": len(event_indices),
                    "events": event_indices,
                    "dominant_severity": max_sev,
                    "score": min(1.0, len(event_indices) * 0.25),
                })

        return correlations


ueba_scorer = UEBAEngine()
