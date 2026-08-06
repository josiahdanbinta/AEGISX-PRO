"""
AEGISX - AI-Powered API Endpoints
Incident analysis, alert explanation, recommendations, Q&A
"""
import uuid
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, RequireSOCAnalyst, RequireSOCManager, require_tenant
from app.core.config import settings
from app.core.database import get_db
from app.models import (
    Incident, IncidentTimeline, IncidentNote, Alert,
    Vulnerability, Playbook, Asset, AuditLog,
)

router = APIRouter()


class AskRequest(BaseModel):
    question: str
    context: Optional[dict] = None

class CorrelateRequest(BaseModel):
    alert_ids: Optional[List[str]] = None
    time_range_hours: int = 24

class AIEnabledResponse(BaseModel):
    enabled: bool
    model: str
    provider: str


@router.get("/health", response_model=AIEnabledResponse)
async def ai_health():
    return AIEnabledResponse(
        enabled=settings.AI_ENABLED,
        model=settings.AI_MODEL or "gpt-4",
        provider=settings.AI_PROVIDER,
    )


@router.post("/incidents/{incident_id}/summarize")
async def summarize_incident(
    incident_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.scalar(
        select(Incident).where(
            Incident.id == uuid.UUID(incident_id),
            Incident.tenant_id == uuid.UUID(current_user["tenant_id"]),
        )
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = (await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == uuid.UUID(incident_id))
        .order_by(IncidentTimeline.timestamp.desc())
        .limit(50)
    )).scalars().all()

    incident_data = {
        "title": incident.title,
        "severity": incident.severity,
        "description": incident.description,
        "mitre_techniques": incident.mitre_techniques or [],
    }

    if settings.AI_ENABLED:
        try:
            from app.ai.services import IncidentAnalyzer
            summary = await IncidentAnalyzer.summarize_incident(incident_data)
            return {"summary": summary, "incident_id": incident_id}
        except Exception:
            pass

    return {
        "summary": f"[{incident.severity.upper()}] {incident.title}. Investigation required.",
        "incident_id": incident_id,
        "ai_disabled": not settings.AI_ENABLED,
    }


@router.post("/incidents/{incident_id}/root-cause")
async def incident_root_cause(
    incident_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.scalar(
        select(Incident).where(Incident.id == uuid.UUID(incident_id))
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = (await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == uuid.UUID(incident_id))
        .order_by(IncidentTimeline.timestamp.asc())
    )).scalars().all()

    timeline_data = [
        {"event_type": t.event_type, "title": t.title, "description": t.description, "timestamp": str(t.timestamp)}
        for t in timeline
    ]

    inc_data = {"title": incident.title, "severity": incident.severity, "description": incident.description}

    if settings.AI_ENABLED:
        try:
            from app.ai.services import IncidentAnalyzer
            analysis = await IncidentAnalyzer.root_cause_analysis(inc_data, timeline_data)
            return {"analysis": analysis, "incident_id": incident_id}
        except Exception:
            pass

    return {
        "analysis": {"root_cause": "Analysis requires AI engine to be enabled", "confidence": 0},
        "incident_id": incident_id,
    }


@router.post("/alerts/{alert_id}/explain")
async def explain_alert(
    alert_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(
        select(Alert).where(Alert.id == uuid.UUID(alert_id))
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_data = {
        "title": alert.title,
        "severity": alert.severity,
        "indicator_type": alert.indicator_type,
        "source_ip": alert.source_ip,
        "rule_name": alert.rule_name,
    }

    if settings.AI_ENABLED:
        try:
            from app.ai.services import AlertAnalyzer
            explanation = await AlertAnalyzer.explain_alert(alert_data)
            return {"explanation": explanation, "alert_id": alert_id}
        except Exception:
            pass

    return {
        "explanation": f"Alert '{alert.title}' triggered by rule '{alert.rule_name or 'unknown'}'.",
        "alert_id": alert_id,
    }


@router.post("/alerts/{alert_id}/classify")
async def classify_alert(
    alert_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.scalar(select(Alert).where(Alert.id == uuid.UUID(alert_id)))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if settings.AI_ENABLED:
        try:
            from app.ai.services import AlertAnalyzer
            result = await AlertAnalyzer.classify_false_positive({
                "title": alert.title, "severity": alert.severity,
                "indicator_type": alert.indicator_type, "confidence": alert.confidence,
            })
            return {"classification": result, "alert_id": alert_id}
        except Exception:
            pass

    return {"classification": {"is_false_positive": False, "confidence": 0.5}, "alert_id": alert_id}


@router.post("/incidents/prioritize")
async def prioritize_incidents(
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    incidents = (await db.execute(
        select(Incident)
        .where(Incident.tenant_id == uuid.UUID(tenant_id), Incident.status.notin_(["closed", "resolved"]))
        .order_by(Incident.created_at.desc())
        .limit(20)
    )).scalars().all()

    inc_data = [
        {"id": str(i.id), "title": i.title, "severity": i.severity, "mitre_techniques": i.mitre_techniques or []}
        for i in incidents
    ]

    if settings.AI_ENABLED and inc_data:
        try:
            from app.ai.services import ThreatAnalyzer
            prioritized = await ThreatAnalyzer.prioritize_incidents(inc_data)
            return {"prioritized": prioritized}
        except Exception:
            pass

    # Fallback: sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_incidents = sorted(inc_data, key=lambda x: severity_order.get(x["severity"], 5))
    return {"prioritized": sorted_incidents, "ai_disabled": True}


@router.post("/incidents/{incident_id}/playbook-recommend")
async def recommend_playbook(
    incident_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    incident = await db.scalar(select(Incident).where(Incident.id == uuid.UUID(incident_id)))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    playbooks = (await db.execute(
        select(Playbook).where(Playbook.tenant_id == uuid.UUID(tenant_id), Playbook.status == "active")
    )).scalars().all()

    if settings.AI_ENABLED:
        try:
            from app.ai.services import RecommendationEngine
            recommendations = await RecommendationEngine.recommend_playbook(
                {"title": incident.title, "severity": incident.severity, "mitre_techniques": incident.mitre_techniques},
                [{"id": str(p.id), "name": p.name, "description": p.description} for p in playbooks],
            )
            return {"recommendations": recommendations, "incident_id": incident_id}
        except Exception:
            pass

    return {
        "recommendations": [{"id": str(p.id), "name": p.name, "score": 50} for p in playbooks[:5]],
        "incident_id": incident_id,
    }


@router.post("/vulnerabilities/{vuln_id}/fix-recommend")
async def recommend_fix(
    vuln_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.id == uuid.UUID(vuln_id)))
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if settings.AI_ENABLED:
        try:
            from app.ai.services import RecommendationEngine
            fix = await RecommendationEngine.recommend_fixes({
                "cve_id": vuln.cve_id, "title": vuln.title, "severity": vuln.severity,
                "cvss_score": vuln.cvss_score, "affected_software": vuln.affected_software,
                "affected_version": vuln.affected_version,
            })
            return {"fix_recommendation": fix, "vulnerability_id": vuln_id}
        except Exception:
            pass

    return {
        "fix_recommendation": {"priority": "soon", "steps": [vuln.remediation or "Apply security updates"]},
        "vulnerability_id": vuln_id,
    }


@router.post("/correlate")
async def correlate_alerts(
    request: CorrelateRequest,
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    if request.alert_ids:
        alerts = (await db.execute(
            select(Alert).where(Alert.id.in_([uuid.UUID(a) for a in request.alert_ids]))
        )).scalars().all()
    else:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(hours=request.time_range_hours)
        alerts = (await db.execute(
            select(Alert)
            .where(Alert.tenant_id == uuid.UUID(tenant_id), Alert.created_at >= cutoff)
            .limit(100)
        )).scalars().all()

    alert_data = [
        {"id": str(a.id), "title": a.title, "severity": a.severity, "indicator_type": a.indicator_type,
         "source_ip": a.source_ip, "source_asset_id": str(a.source_asset_id) if a.source_asset_id else None}
        for a in alerts
    ]

    if settings.AI_ENABLED:
        try:
            from app.ai.services import AICorrelationEngine
            correlated = await AICorrelationEngine.correlate_alerts(alert_data)
            return {"correlated_groups": correlated.get("groups", []), "ungrouped": correlated.get("ungrouped_alerts", [])}
        except Exception:
            pass

    return {"correlated_groups": [], "ungrouped": [a["id"] for a in alert_data], "message": "AI correlation unavailable"}


@router.post("/ask")
async def ask_ai(
    request: AskRequest,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)

    # Gather context
    active_incidents = await db.scalar(
        select(func.count()).select_from(Incident)
        .where(Incident.tenant_id == tid, Incident.status.notin_(["closed", "resolved"]))
    ) or 0
    open_alerts = await db.scalar(
        select(func.count()).select_from(Alert)
        .where(Alert.tenant_id == tid, Alert.status.in_(["new", "acknowledged"]))
    ) or 0
    total_assets = await db.scalar(
        select(func.count()).select_from(Asset)
        .where(Asset.tenant_id == tid, Asset.is_deleted == False)
    ) or 0
    open_vulns = await db.scalar(
        select(func.count()).select_from(Vulnerability)
        .where(Vulnerability.tenant_id == tid, Vulnerability.status.notin_(["remediated", "false_positive"]))
    ) or 0

    context = {
        "active_incidents": active_incidents,
        "open_alerts": open_alerts,
        "total_assets": total_assets,
        "vulnerabilities": open_vulns,
        "risk_score": "Medium",
        **(request.context or {}),
    }

    if settings.AI_ENABLED:
        try:
            from app.ai.services import AIInvestigator
            answer = await AIInvestigator.answer_question(request.question, context)
            return {"question": request.question, "answer": answer}
        except Exception:
            pass

    return {
        "question": request.question,
        "answer": f"I'm unable to process your question right now. Platform has {active_incidents} active incidents and {open_alerts} open alerts.",
    }


@router.post("/incidents/{incident_id}/report")
async def generate_ai_report(
    incident_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.scalar(
        select(Incident).options(selectinload(Incident.timeline_entries))
        .where(Incident.id == uuid.UUID(incident_id))
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    notes = (await db.execute(
        select(IncidentNote)
        .where(IncidentNote.incident_id == uuid.UUID(incident_id))
        .order_by(IncidentNote.created_at.asc())
    )).scalars().all()

    inc_data = {
        "title": incident.title, "severity": incident.severity,
        "description": incident.description, "status": incident.status,
        "mitre_techniques": incident.mitre_techniques or [],
        "resolution": incident.resolution,
    }
    timeline_data = [
        {"event_type": t.event_type, "title": t.title, "description": t.description}
        for t in (incident.timeline_entries or [])
    ]
    notes_data = [{"content": n.content, "note_type": n.note_type} for n in notes]

    if settings.AI_ENABLED:
        try:
            from app.ai.services import AIInvestigator
            report = await AIInvestigator.generate_report(inc_data, timeline_data, notes_data)
            return {"report_markdown": report, "incident_id": incident_id}
        except Exception:
            pass

    return {
        "report_markdown": f"# {incident.title}\n\n**Severity:** {incident.severity}\n**Status:** {incident.status}\n\n{incident.description or 'No description'}",
        "incident_id": incident_id,
    }


@router.get("/insights")
async def ai_insights(
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)

    critical = await db.scalar(
        select(func.count()).select_from(Incident)
        .where(Incident.tenant_id == tid, Incident.severity == "critical", Incident.status.notin_(["closed"]))
    ) or 0
    open_incidents = await db.scalar(
        select(func.count()).select_from(Incident)
        .where(Incident.tenant_id == tid, Incident.status.notin_(["closed", "resolved"]))
    ) or 0
    new_alerts = await db.scalar(
        select(func.count()).select_from(Alert)
        .where(Alert.tenant_id == tid, Alert.status == "new")
    ) or 0
    open_vulns = await db.scalar(
        select(func.count()).select_from(Vulnerability)
        .where(Vulnerability.tenant_id == tid, Vulnerability.status.notin_(["remediated", "false_positive"]))
    ) or 0

    risk_score = min(100, (critical * 25) + (open_incidents * 2) + (new_alerts * 1) + (open_vulns * 0.5))

    return {
        "risk_score": int(risk_score),
        "risk_level": "critical" if risk_score > 75 else "high" if risk_score > 50 else "medium" if risk_score > 25 else "low",
        "insights": {
            "critical_incidents": critical,
            "open_incidents": open_incidents,
            "new_alerts": new_alerts,
            "open_vulnerabilities": open_vulns,
        },
        "recommendations": [
            "Review critical incidents immediately" if critical > 0 else "No critical incidents",
            "Triage new alerts" if new_alerts > 10 else "Alert levels normal",
            "Patch open vulnerabilities" if open_vulns > 50 else "Vulnerability levels manageable",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
