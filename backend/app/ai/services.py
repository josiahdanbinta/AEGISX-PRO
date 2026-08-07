"""
AEGIS - AI Services
Incident analysis, alert explanation, recommendations, threat analysis
"""
import json
from typing import Dict, List, Any, Optional
from app.ai.llm import llm_client


class AIService:
    """Base AI service."""
    pass


class IncidentAnalyzer:
    """AI-powered incident analysis."""

    @staticmethod
    async def summarize_incident(incident: Dict) -> str:
        """Generate concise incident summary."""
        prompt = f"""You are a cybersecurity analyst. Summarize this security incident concisely:
Title: {incident.get('title', 'Unknown')}
Severity: {incident.get('severity', 'unknown')}
Description: {incident.get('description', 'No description')}
Affected Assets: {incident.get('affected_assets', 'Unknown')}
MITRE Techniques: {incident.get('mitre_techniques', [])}

Provide: 1-sentence summary, likely attack vector, recommended immediate action."""
        try:
            result = await llm_client.complete([{"role": "user", "content": prompt}])
            if _is_error(result):
                return _fallback_summary(incident)
            return result
        except Exception:
            return _fallback_summary(incident)

    @staticmethod
    async def root_cause_analysis(incident: Dict, timeline: List[Dict]) -> Dict:
        """Analyze root cause from timeline events."""
        timeline_text = "\n".join(
            [f"- [{e.get('event_type', '')}] {e.get('title', '')}: {e.get('description', '')}"
             for e in (timeline or [])[:20]]
        )
        if not timeline_text:
            timeline_text = "No timeline data available."
        prompt = f"""Analyze this security incident timeline to determine root cause:
Incident: {incident.get('title', 'Unknown')}

Timeline:
{timeline_text}

Return JSON: {{"root_cause": "description", "attack_chain": ["step1", "step2"], "initial_access": "method", "confidence": 0.0-1.0, "prevention_recommendations": ["rec1", "rec2"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {},
                temperature=0.2, max_tokens=2048,
            )
            if _is_error(result):
                return _fallback_root_cause(incident)
            return result
        except Exception:
            return _fallback_root_cause(incident)

    @staticmethod
    async def assess_impact(incident: Dict, assets: List[Dict] = None) -> Dict:
        """Assess business impact of an incident."""
        assets_text = json.dumps(assets or [], default=str)[:2000]
        prompt = f"""Assess the business impact of this security incident:
Incident: {json.dumps(incident, default=str)[:2000]}
Related Assets: {assets_text}

Return JSON: {{"impact_level": "critical/high/medium/low", "affected_business_units": ["unit1"], "data_exposure_risk": "description", "operational_impact": "description", "financial_impact_estimate": "description", "reputation_risk": "description"}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_impact(incident)
            return result
        except Exception:
            return _fallback_impact(incident)


class AlertAnalyzer:
    """AI-powered alert analysis and false positive reduction."""

    @staticmethod
    async def explain_alert(alert: Dict) -> str:
        """Explain what an alert means in plain language."""
        prompt = f"""Explain this security alert in simple terms that a junior analyst can understand:
Alert: {alert.get('title', 'Unknown')}
Severity: {alert.get('severity', 'unknown')}
Type: {alert.get('indicator_type', 'unknown')}
Source: {alert.get('source_ip', 'unknown')}
Rule: {alert.get('rule_name', 'unknown')}

Explain: What happened? Why is it important? Is this likely a real threat or false positive?"""
        try:
            result = await llm_client.complete([{"role": "user", "content": prompt}])
            if _is_error(result):
                return _fallback_alert_explanation(alert)
            return result
        except Exception:
            return _fallback_alert_explanation(alert)

    @staticmethod
    async def classify_false_positive(alert: Dict, historical_context: str = "") -> Dict:
        """Determine if an alert is likely a false positive."""
        prompt = f"""Classify whether this security alert is likely a false positive:
Alert: {json.dumps(alert, default=str)}
Context: {historical_context or 'No additional context'}

Return JSON: {{"is_false_positive": true/false, "confidence": 0.0-1.0, "reasoning": "explanation", "indicators": ["factor1", "factor2"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_false_positive()
            return result
        except Exception:
            return _fallback_false_positive()

    @staticmethod
    async def suggest_triage_action(alert: Dict) -> Dict:
        """Suggest triage actions for an alert."""
        prompt = f"""Suggest triage actions for this security alert:
Alert: {json.dumps(alert, default=str)[:1500]}

Return JSON: {{"recommended_priority": "p1/p2/p3/p4", "immediate_actions": ["action1"], "investigation_steps": ["step1"], "escalation_needed": true/false, "sla_minutes": 30, "playbook_reference": "phrase"}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_triage(alert)
            return result
        except Exception:
            return _fallback_triage(alert)


class ThreatAnalyzer:
    """AI-powered threat analysis."""

    @staticmethod
    async def prioritize_incidents(incidents: List[Dict]) -> List[Dict]:
        """AI-driven incident prioritization."""
        if not incidents:
            return []
        incidents_json = json.dumps(
            [{
                "id": i.get("id"), "title": i.get("title"),
                "severity": i.get("severity"), "mitre": i.get("mitre_techniques", []),
            } for i in (incidents or [])[:10]],
            default=str,
        )
        prompt = f"""You are a SOC manager. Prioritize these security incidents by true risk (not just severity):
{incidents_json}

Consider: exploitability, blast radius, data sensitivity, attacker sophistication.
Return JSON array with id and priority_rank (1=highest), risk_score, and brief_reasoning."""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if isinstance(result, list):
                return result
            if isinstance(result, dict) and not result.get("error"):
                return [result]
            return _fallback_prioritize(incidents)
        except Exception:
            return _fallback_prioritize(incidents)

    @staticmethod
    async def analyze_threat_actor(indicators: List[Dict]) -> Dict:
        """Analyze potential threat actor based on indicators."""
        indicators_json = json.dumps(indicators or [], default=str)[:3000]
        prompt = f"""Based on these threat indicators, identify potential threat actors or APT groups:
Indicators: {indicators_json}

Return JSON: {{"likely_actors": ["actor1"], "confidence": 0.0-1.0, "motivation": "description", "targeting_pattern": "description", "mitre_mapping": {{"tactic1": ["technique1"]}}}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_threat_actor()
            return result
        except Exception:
            return _fallback_threat_actor()

    @staticmethod
    async def predict_attack_path(assets: List[Dict], vulnerabilities: List[Dict] = None) -> Dict:
        """Predict likely attack paths based on asset exposure and vulnerabilities."""
        assets_json = json.dumps(assets or [], default=str)[:2500]
        vulns_json = json.dumps(vulnerabilities or [], default=str)[:2500]
        prompt = f"""Predict the most likely attack paths against this environment:
Assets: {assets_json}
Vulnerabilities: {vulns_json}

Return JSON: {{"attack_paths": [{{"path": ["step1", "step2"], "likelihood": 0.8, "impact": "high", "entry_point": "description"}}], "critical_exposures": ["exposure1"], "recommended_defenses": ["defense1"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {},
                temperature=0.3, max_tokens=2048,
            )
            if _is_error(result):
                return _fallback_attack_path()
            return result
        except Exception:
            return _fallback_attack_path()


class RecommendationEngine:
    """AI-powered security recommendations."""

    @staticmethod
    async def recommend_playbook(incident: Dict, available_playbooks: List[Dict]) -> List[Dict]:
        """Recommend playbooks for an incident."""
        if not available_playbooks:
            return []
        playbooks_json = json.dumps(
            [{"id": p.get("id"), "name": p.get("name"), "description": p.get("description", "")}
             for p in (available_playbooks or [])[:20]]
        )
        prompt = f"""Match the best playbook(s) for this incident:
Incident: {json.dumps(incident, default=str)[:500]}

Available Playbooks:
{playbooks_json}

Return JSON array of recommended playbook IDs with relevance_score (0-100) and reason: [{{"id": "...", "score": 85, "reason": "..."}}]"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if isinstance(result, list):
                return result
            return []
        except Exception:
            return []

    @staticmethod
    async def recommend_fixes(vulnerability: Dict) -> Dict:
        """Recommend fixes for a vulnerability."""
        prompt = f"""Provide remediation guidance for this vulnerability:
CVE: {vulnerability.get('cve_id', 'Unknown')}
Title: {vulnerability.get('title', 'Unknown')}
Severity: {vulnerability.get('severity', 'medium')}
CVSS: {vulnerability.get('cvss_score', 'Unknown')}
Software: {vulnerability.get('affected_software', 'Unknown')}
Version: {vulnerability.get('affected_version', 'Unknown')}

Return JSON: {{"priority": "immediate/soon/routine", "steps": ["step1", "step2"], "patch_available": true/false, "workaround": "if any", "risk_if_not_fixed": "description"}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_fix(vulnerability)
            return result
        except Exception:
            return _fallback_fix(vulnerability)

    @staticmethod
    async def recommend_hardening(asset_info: Dict) -> Dict:
        """Recommend security hardening measures for an asset."""
        prompt = f"""Recommend security hardening measures for this asset:
Asset: {json.dumps(asset_info, default=str)[:1500]}

Return JSON: {{"critical_actions": ["action1"], "configuration_changes": ["change1"], "monitoring_improvements": ["improvement1"], "compliance_gaps": ["gap1"], "references": ["ref1"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_hardening()
            return result
        except Exception:
            return _fallback_hardening()


class AIInvestigator:
    """AI-powered investigation assistant."""

    @staticmethod
    async def answer_question(question: str, context: Dict) -> str:
        """Answer natural language questions about platform data."""
        prompt = f"""You are AEGIS AI Assistant, a cybersecurity operations expert. Answer based on the provided context data.
        
Question: {question}

Context Data:
- Active Incidents: {context.get('active_incidents', 0)}
- Open Alerts: {context.get('open_alerts', 0)}
- Total Assets: {context.get('total_assets', 0)}
- Vulnerabilities: {context.get('vulnerabilities', 0)}
- Risk Score: {context.get('risk_score', 'Unknown')}

Provide a concise, helpful answer. If you need more data to answer, state what's needed."""
        try:
            result = await llm_client.complete([{"role": "user", "content": prompt}])
            if _is_error(result):
                return _fallback_answer(question)
            return result
        except Exception:
            return _fallback_answer(question)

    @staticmethod
    async def generate_report(incident: Dict, timeline: List = None, notes: List = None) -> str:
        """Generate an incident report."""
        context = json.dumps({
            "incident": {k: v for k, v in (incident or {}).items() if k != "raw_event"},
            "timeline": (timeline or [])[:30],
            "notes": (notes or [])[:20],
        }, default=str)[:4000]
        prompt = f"""Generate a professional incident response report based on this data. Include: Executive Summary, Timeline of Events, Impact Analysis, Response Actions Taken, Root Cause, Lessons Learned, and Recommendations. Format in Markdown.

Data:
{context}"""
        try:
            result = await llm_client.complete(
                [{"role": "user", "content": prompt}],
                max_tokens=3000, temperature=0.4,
            )
            if _is_error(result):
                return _fallback_report()
            return result
        except Exception:
            return _fallback_report()

    @staticmethod
    async def investigate_entity(entity_type: str, entity_value: str, surrounding_data: Dict = None) -> Dict:
        """Investigate an entity (IP, domain, hash, user) with AI context."""
        prompt = f"""Investigate this {entity_type} in the context of our environment:
Type: {entity_type}
Value: {entity_value}
Surrounding Context: {json.dumps(surrounding_data or {}, default=str)[:1500]}

Return JSON: {{"risk_assessment": "high/medium/low/unknown", "threat_intelligence_hypothesis": "description", "recommended_actions": ["action1"], "indicators_of_compromise": ["ioc1"], "related_known_threats": ["threat1"], "confidence": 0.0-1.0}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_investigation(entity_type, entity_value)
            return result
        except Exception:
            return _fallback_investigation(entity_type, entity_value)


class AICorrelationEngine:
    """AI-powered event correlation."""

    @staticmethod
    async def correlate_alerts(alerts: List[Dict]) -> Dict:
        """Correlate related alerts into potential incidents."""
        if not alerts:
            return {"groups": [], "ungrouped_alerts": []}
        alerts_json = json.dumps(
            [{k: v for k, v in a.items() if k != "raw_event"}
             for a in (alerts or [])[:50]],
            default=str,
        )[:6000]
        prompt = f"""Analyze these alerts and group them into correlated security incidents:
{alerts_json}

Return JSON: {{"groups": [{{"name": "Incident name", "alert_ids": ["id1", "id2"], "hypothesis": "What's happening", "confidence": 0.8, "recommended_action": "What to do"}}], "ungrouped_alerts": ["id3"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_correlation(alerts)
            return result
        except Exception:
            return _fallback_correlation(alerts)

    @staticmethod
    async def correlate_to_mitre(incident_description: str) -> Dict:
        """Map incident description to MITRE ATT&CK techniques."""
        prompt = f"""Map this security incident to MITRE ATT&CK framework:
Incident Description: {incident_description[:2000]}

Return JSON: {{"tactics": ["tactic1"], "techniques": [{{"id": "T1234", "name": "technique name", "confidence": 0.9}}], "mitre_tactic_flow": ["initial-access", "execution"]}}"""
        try:
            result = await llm_client.complete_structured(
                [{"role": "user", "content": prompt}], {}
            )
            if _is_error(result):
                return _fallback_mitre()
            return result
        except Exception:
            return _fallback_mitre()


# â”€â”€ Fallback functions when AI is unavailable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _is_error(result) -> bool:
    """Check if an AI result contains an error."""
    if isinstance(result, dict):
        return "error" in result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
            return isinstance(parsed, dict) and "error" in parsed
        except Exception:
            return False
    return False


def _fallback_summary(incident: Dict) -> str:
    sev = incident.get("severity", "unknown").upper()
    title = incident.get("title", "Unknown")
    return f"[{sev}] {title}. Immediate investigation required based on severity level."


def _fallback_root_cause(incident: Dict) -> Dict:
    return {
        "root_cause": "Analysis unavailable â€” enable AI for automated root cause analysis.",
        "attack_chain": [],
        "initial_access": "unknown",
        "confidence": 0,
        "prevention_recommendations": [
            "Review incident timeline manually",
            "Check access logs for the affected asset",
            "Isolate affected systems",
        ],
    }


def _fallback_impact(incident: Dict) -> Dict:
    return {
        "impact_level": "unknown",
        "affected_business_units": [],
        "data_exposure_risk": "Assessment unavailable",
        "operational_impact": "Assessment unavailable",
        "financial_impact_estimate": "Assessment unavailable",
        "reputation_risk": "Assessment unavailable",
    }


def _fallback_alert_explanation(alert: Dict) -> str:
    return (
        f"Alert '{alert.get('title', 'Unknown')}' was triggered by a detection rule. "
        "Review the source and affected asset for more details."
    )


def _fallback_false_positive() -> Dict:
    return {
        "is_false_positive": False,
        "confidence": 0.5,
        "reasoning": "Unable to classify â€” enable AI for automated classification.",
        "indicators": [],
    }


def _fallback_triage(alert: Dict) -> Dict:
    return {
        "recommended_priority": "p3",
        "immediate_actions": ["Review alert details manually"],
        "investigation_steps": ["Check source IP reputation", "Verify affected asset"],
        "escalation_needed": False,
        "sla_minutes": 720,
        "playbook_reference": "General Alert Triage",
    }


def _fallback_prioritize(incidents: List[Dict]) -> List[Dict]:
    return [
        {
            "id": i.get("id"),
            "priority_rank": idx + 1,
            "risk_score": 50,
            "brief_reasoning": "Default priority based on order",
        }
        for idx, i in enumerate(incidents or [])
    ]


def _fallback_threat_actor() -> Dict:
    return {
        "likely_actors": [],
        "confidence": 0,
        "motivation": "Unable to determine â€” enable AI for threat actor analysis.",
        "targeting_pattern": "Unknown",
        "mitre_mapping": {},
    }


def _fallback_attack_path() -> Dict:
    return {
        "attack_paths": [],
        "critical_exposures": [],
        "recommended_defenses": [
            "Ensure all systems are patched",
            "Review firewall rules",
            "Enable MFA where possible",
        ],
    }


def _fallback_fix(vulnerability: Dict) -> Dict:
    return {
        "priority": "soon",
        "steps": [
            "Check vendor advisory for patches",
            "Update to the latest version",
            "Apply compensating controls if patch unavailable",
        ],
        "patch_available": False,
        "workaround": "Restrict network access to affected service",
        "risk_if_not_fixed": "Vulnerability may be exploited by attackers",
    }


def _fallback_hardening() -> Dict:
    return {
        "critical_actions": [],
        "configuration_changes": [],
        "monitoring_improvements": [],
        "compliance_gaps": [],
        "references": [],
    }


def _fallback_answer(question: str) -> str:
    return (
        "I'm unable to process your question right now. The AI service may be unavailable. "
        "Please check your API key configuration or try again later."
    )


def _fallback_report() -> str:
    return (
        "# Incident Report\n\n"
        "## Unable to Generate Report\n\n"
        "The AI service is currently unavailable. A report cannot be generated automatically at this time. "
        "Please ensure your AI API key is configured and the service is running, then retry.\n\n"
        "### Manual Report Checklist\n"
        "- Document incident timeline\n"
        "- Record response actions taken\n"
        "- Note lessons learned\n"
        "- List recommendations"
    )


def _fallback_investigation(entity_type: str, entity_value: str) -> Dict:
    return {
        "risk_assessment": "unknown",
        "threat_intelligence_hypothesis": "Investigation unavailable â€” enable AI for automated analysis.",
        "recommended_actions": [f"Manually investigate {entity_type}: {entity_value}"],
        "indicators_of_compromise": [],
        "related_known_threats": [],
        "confidence": 0,
    }


def _fallback_correlation(alerts: List[Dict]) -> Dict:
    return {
        "groups": [],
        "ungrouped_alerts": [a.get("id", "") for a in (alerts or [])],
    }


def _fallback_mitre() -> Dict:
    return {
        "tactics": [],
        "techniques": [],
        "mitre_tactic_flow": [],
    }
