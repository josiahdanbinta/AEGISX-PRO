"""
AEGIS - Osquery API Router
Osquery query builder, template library, and scheduling for endpoint interrogation.
"""
import uuid as uuid_mod
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, require_tenant
from app.services.osquery_service import osquery_service

router = APIRouter()


class OsqueryTemplate(BaseModel):
    id: str
    name: str
    query: str
    category: str
    description: str
    interval: int = 3600
    tags: List[str] = []
    platform: str = "all"


class CreateTemplate(BaseModel):
    name: str
    query: str
    category: str = "custom"
    description: str = ""
    interval: int = 3600
    tags: List[str] = []
    platform: str = "all"


class ScheduleRequest(BaseModel):
    agent_id: str
    template_id: str
    interval_seconds: int = 3600


class ValidateQueryRequest(BaseModel):
    query: str


@router.get("/templates", response_model=List[OsqueryTemplate], summary="List osquery templates")
async def list_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform (windows,linux,darwin,all)"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    current_user: dict = Depends(get_current_user),
):
    templates = osquery_service.get_all_templates()

    if category:
        templates = [t for t in templates if t.get("category") == category]
    if platform:
        templates = [t for t in templates if t.get("platform") in (platform, "all")]
    if search:
        q = search.lower()
        templates = [t for t in templates if q in t.get("name","").lower() or q in t.get("description","").lower()]

    return templates


@router.get("/templates/{template_id}", response_model=OsqueryTemplate, summary="Get osquery template")
async def get_template(template_id: str, current_user: dict = Depends(get_current_user)):
    tmpl = osquery_service.get_template(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return tmpl


@router.post("/templates", status_code=201, summary="Create custom osquery template")
async def create_template(body: CreateTemplate, current_user: dict = Depends(get_current_user)):
    validated = osquery_service.validate_query(body.query)
    if not validated["valid"]:
        raise HTTPException(status_code=400, detail=validated["error"])
    return osquery_service.create_template(body.model_dump())


@router.delete("/templates/{template_id}", summary="Delete custom osquery template")
async def delete_template(template_id: str, current_user: dict = Depends(get_current_user)):
    if not osquery_service.delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found or is built-in")
    return {"message": "Template deleted"}


@router.post("/validate", summary="Validate an osquery SQL query")
async def validate_query(body: ValidateQueryRequest, current_user: dict = Depends(get_current_user)):
    return osquery_service.validate_query(body.query)


@router.post("/schedule", summary="Schedule osquery on an agent")
async def schedule_query(body: ScheduleRequest, current_user: dict = Depends(get_current_user)):
    tmpl = osquery_service.get_template(body.template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    result = await osquery_service.schedule_query(
        body.agent_id, tmpl["query"], body.template_id, body.interval_seconds,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.delete("/schedule/{agent_id}/{template_id}", summary="Remove osquery schedule")
async def un_schedule_query(agent_id: str, template_id: str, current_user: dict = Depends(get_current_user)):
    result = await osquery_service.un_schedule_query(agent_id, template_id)
    return result


@router.get("/schedule/{agent_id}", summary="Get agent osquery schedules")
async def get_agent_schedules(agent_id: str, current_user: dict = Depends(get_current_user)):
    return await osquery_service.get_agent_schedules(agent_id)


@router.get("/categories", summary="List osquery template categories")
async def list_categories(current_user: dict = Depends(get_current_user)):
    templates = osquery_service.get_all_templates()
    categories = sorted(set(t.get("category", "other") for t in templates))
    return categories
