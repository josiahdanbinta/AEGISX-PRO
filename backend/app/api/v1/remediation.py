"""
AEGISX - AI Remediation API Router
Analyze alerts/incidents, generate remediation plans, execute approved actions.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, require_tenant
from app.services.ai_remediation import ai_remediation, REMEDIATION_ACTIONS

router = APIRouter()


class RemediationRequest(BaseModel):
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    agent_id: Optional[str] = None
    auto_execute: bool = False


class ApprovalRequest(BaseModel):
    approval_id: str
    action: str  # "approve" or "deny"
    reason: Optional[str] = None


class ExecuteActionRequest(BaseModel):
    action: str
    params: Dict[str, Any] = {}


@router.post("/analyze/alert", summary="Analyze alert & generate remediation plan")
async def analyze_alert(body: RemediationRequest, current_user: dict = Depends(get_current_user)):
    if not body.alert_id:
        raise HTTPException(status_code=400, detail="alert_id required")

    alert = {
        "id": body.alert_id,
        "title": "Alert from API",
        "severity": "medium",
        "confidence": 0.7,
    }
    plan = await ai_remediation.analyze_alert(alert)
    return plan


@router.post("/analyze/incident", summary="Analyze incident & generate remediation plan")
async def analyze_incident(body: RemediationRequest, current_user: dict = Depends(get_current_user)):
    if not body.incident_id:
        raise HTTPException(status_code=400, detail="incident_id required")

    incident = {
        "id": body.incident_id,
        "title": "Incident from API",
        "severity": "high",
        "mitre_techniques": [],
    }
    plan = await ai_remediation.analyze_incident(incident)
    return plan


@router.post("/execute", summary="Execute a single remediation action")
async def execute_action(body: ExecuteActionRequest, current_user: dict = Depends(get_current_user)):
    action_def = REMEDIATION_ACTIONS.get(body.action)
    if not action_def:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")

    risk = action_def.get("risk", "medium")
    user_roles = current_user.get("roles", [])

    if risk in ("high", "critical") and "soc_manager" not in user_roles:
        raise HTTPException(status_code=403,
            detail=f"Risk level {risk} requires SOC Manager approval. Request approval first.")

    result = await ai_remediation.execute_action(body.action, body.params)
    return result


@router.post("/approve", summary="Approve or deny a pending remediation")
async def approve_remediation(body: ApprovalRequest, current_user: dict = Depends(get_current_user)):
    user = current_user.get("sub", current_user.get("user_id", "unknown"))

    if body.action == "approve":
        entry = ai_remediation.approve(body.approval_id, str(user))
        if not entry:
            raise HTTPException(status_code=404, detail="Approval not found")
        plan = entry["plan"]
        params = {"agent_id": body.approval_id}
        results = await ai_remediation.execute_plan(plan, params, approved_by=str(user))
        return {"status": "approved", "results": results}

    elif body.action == "deny":
        entry = ai_remediation.deny(body.approval_id, str(user), body.reason or "")
        if not entry:
            raise HTTPException(status_code=404, detail="Approval not found")
        return {"status": "denied", "reason": body.reason}

    raise HTTPException(status_code=400, detail="Action must be 'approve' or 'deny'")


@router.get("/actions", summary="List available remediation actions")
async def list_actions(current_user: dict = Depends(get_current_user)):
    return {
        "actions": [
            {
                "id": k,
                "name": v["name"],
                "risk": v["risk"],
                "category": v["category"],
                "description": v["description"],
                "reversible": v["reversible"],
            }
            for k, v in REMEDIATION_ACTIONS.items()
        ]
    }


@router.post("/auto", summary="Auto-remediate an alert (low-risk actions only)")
async def auto_remediate(body: RemediationRequest, current_user: dict = Depends(get_current_user)):
    alert = {
        "id": body.alert_id or "unknown",
        "title": "Auto-remediation alert",
        "severity": "medium",
        "confidence": 0.6,
        "source_ip": None,
        "hostname": None,
    }
    result = await ai_remediation.auto_remediate_alert(alert, body.agent_id)
    return result
