"""
AEGIS - License Key Generator & Validator
For Enterprise Edition. Generates cryptographically signed license keys
with tenant limits, expiry, and feature flags.
"""
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

LICENSE_SECRET = "change-this-to-a-strong-secret-in-production"

# Feature gating
ENTERPRISE_FEATURES = {
    "ai_remediation": {"name": "AI Auto-Remediation", "edition": "enterprise"},
    "slack_bot": {"name": "Slack/Teams Bot", "edition": "enterprise"},
    "soc_chat_ai": {"name": "SOC Chat with AI Assistant", "edition": "enterprise"},
    "sso": {"name": "SSO (SAML/OIDC/LDAP)", "edition": "enterprise"},
    "whitelabel": {"name": "White-Label / MSSP", "edition": "enterprise"},
    "unlimited_tenants": {"name": "Unlimited Tenants", "edition": "enterprise"},
    "unlimited_endpoints": {"name": "Unlimited Endpoints", "edition": "enterprise"},
    "unlimited_playbooks": {"name": "Unlimited SOAR Playbooks", "edition": "enterprise"},
    "custom_roles": {"name": "Custom RBAC Roles", "edition": "enterprise"},
    "priority_support": {"name": "Priority 24/7 Support", "edition": "enterprise"},
    "misp_opencti": {"name": "MISP + OpenCTI Integration", "edition": "enterprise"},
    "compliance_reports": {"name": "Auto Compliance Reports", "edition": "enterprise"},
}

TRIAL_DURATION_DAYS = 14


def generate_license(
    customer_name: str,
    customer_email: str,
    max_tenants: int = 10,
    max_endpoints: int = 500,
    expiry_days: int = 365,
    features: Optional[List[str]] = None,
    is_trial: bool = False,
) -> str:
    payload = {
        "customer": customer_name,
        "email": customer_email,
        "max_tenants": max_tenants,
        "max_endpoints": max_endpoints,
        "issued_at": int(time.time()),
        "expires_at": int(time.time() + (expiry_days * 86400)),
        "features": features or list(ENTERPRISE_FEATURES.keys()),
        "is_trial": is_trial,
        "version": "2.0",
    }

    payload_str = json.dumps(payload, sort_keys=True)
    signature = hmac.new(
        LICENSE_SECRET.encode(),
        payload_str.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]

    return f"AEGIS-{signature}-{_encode(payload_str)}"


def _encode(data: str) -> str:
    import base64
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _decode(encoded: str) -> str:
    import base64
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded).decode()


def validate_license(license_key: str) -> Dict[str, Any]:
    try:
        parts = license_key.split("-")
        if len(parts) < 3 or parts[0] != "AEGIS":
            return {"valid": False, "error": "Invalid license format"}

        signature = parts[1]
        payload_str = _decode("-".join(parts[2:]))
        payload = json.loads(payload_str)

        expected_sig = hmac.new(
            LICENSE_SECRET.encode(),
            payload_str.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

        if not hmac.compare_digest(signature, expected_sig):
            return {"valid": False, "error": "Invalid license signature"}

        now = int(time.time())
        if payload.get("expires_at", 0) < now:
            days_ago = (now - payload["expires_at"]) // 86400
            return {
                "valid": False,
                "error": f"License expired {days_ago} days ago",
                "expired": True,
            }

        return {
            "valid": True,
            "customer": payload["customer"],
            "email": payload["email"],
            "max_tenants": payload["max_tenants"],
            "max_endpoints": payload["max_endpoints"],
            "features": payload.get("features", []),
            "is_trial": payload.get("is_trial", False),
            "expires_at": payload["expires_at"],
            "days_remaining": (payload["expires_at"] - now) // 86400,
            "version": payload.get("version", "1.0"),
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def generate_trial(customer_name: str, customer_email: str) -> str:
    return generate_license(
        customer_name=customer_name,
        customer_email=customer_email,
        max_tenants=3,
        max_endpoints=50,
        expiry_days=TRIAL_DURATION_DAYS,
        features=list(ENTERPRISE_FEATURES.keys()),
        is_trial=True,
    )


# CLI for generating licenses
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python license_key.py <customer_name> <customer_email> [--trial] [--tenants N] [--endpoints N] [--days N]")
        print("")
        print("Example:")
        print("  python license_key.py 'ACME Corp' 'soc@acme.com' --tenants 10 --endpoints 500 --days 365")
        print("  python license_key.py 'ACME Corp' 'soc@acme.com' --trial")
        sys.exit(0)

    name = sys.argv[1]
    email = sys.argv[2]
    args = sys.argv[3:]

    is_trial = "--trial" in args
    tenants = 10
    endpoints = 500
    days = 365

    for i, arg in enumerate(args):
        if arg == "--tenants" and i + 1 < len(args):
            tenants = int(args[i + 1])
        if arg == "--endpoints" and i + 1 < len(args):
            endpoints = int(args[i + 1])
        if arg == "--days" and i + 1 < len(args):
            days = int(args[i + 1])

    if is_trial:
        key = generate_trial(name, email)
        print(f"Trial license (14 days): {key}")
    else:
        key = generate_license(name, email, tenants, endpoints, days)
        print(f"License key: {key}")
