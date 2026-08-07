"""
AEGIS - Smart Notification & Auto-Containment API
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import get_current_user, RequireSOCManager
from app.services.smart_notifications import smart_notifications
from app.services.auto_containment import auto_containment

router = APIRouter()


class EvaluateAlertRequest(BaseModel):
    alert: Dict[str, Any]
    user_prefs: Optional[Dict] = None


class ContainmentEvaluateRequest(BaseModel):
    alert: Dict[str, Any]


@router.post("/smart/evaluate", summary="AI-evaluate if an alert should trigger notification")
async def evaluate_smart_notification(body: EvaluateAlertRequest,
                                       current_user: dict = Depends(get_current_user)):
    return smart_notifications.should_notify(body.alert, body.user_prefs)


@router.get("/smart/escalation/{severity}", summary="Get escalation chain for severity")
async def get_escalation(severity: str, current_user: dict = Depends(get_current_user)):
    return {"severity": severity, "chain": smart_notifications.get_escalation_chain(severity)}


@router.post("/containment/evaluate", summary="Evaluate alert against containment rules")
async def evaluate_containment(body: ContainmentEvaluateRequest,
                                current_user: dict = Depends(get_current_user)):
    return await auto_containment.evaluate_alert(body.alert)


@router.get("/containment/rules", summary="List containment rules")
async def list_containment_rules(current_user: dict = Depends(get_current_user)):
    return {"rules": auto_containment.get_containment_rules()}


@router.get("/containment/history", summary="Get containment action history")
async def get_containment_history(limit: int = Query(50, le=200),
                                   current_user: dict = Depends(get_current_user)):
    return {"history": auto_containment.get_history(limit)}
