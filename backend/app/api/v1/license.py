"""
AEGISX - License Info API
"""
from fastapi import APIRouter
from app.core.config import settings
from app.core.license_key import validate_license, ENTERPRISE_FEATURES

router = APIRouter()


@router.get("/info")
async def license_info():
    """Return current license information."""
    if not settings.LICENSE_KEY:
        return {"licensed": False, "edition": "Community", "message": "No license key configured"}

    result = validate_license(settings.LICENSE_KEY)

    return {
        "licensed": result.get("valid", False),
        "customer": result.get("customer", "Unknown"),
        "email": result.get("email", ""),
        "edition": "Enterprise" if result.get("valid") else "Community",
        "max_tenants": result.get("max_tenants", 3),
        "max_endpoints": result.get("max_endpoints", 50),
        "features": result.get("features", []),
        "is_trial": result.get("is_trial", False),
        "days_remaining": result.get("days_remaining", 0),
        "expired": result.get("expired", False),
        "error": result.get("error"),
        **({"features_detail": {f: ENTERPRISE_FEATURES.get(f, {}) for f in result.get("features", [])}} if result.get("valid") else {}),
    }
