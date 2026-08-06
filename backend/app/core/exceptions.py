"""
AEGISX - Custom Exception Classes
"""
from typing import Any, Dict, Optional


class AegisxException(Exception):
    """Base exception for all AEGISX errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: str = "INTERNAL_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)


class AuthenticationError(AegisxException):
    def __init__(self, message: str = "Authentication failed", details=None):
        super().__init__(message, status_code=401, error_code="AUTHENTICATION_FAILED", details=details)


class AuthorizationError(AegisxException):
    def __init__(self, message: str = "Insufficient permissions", details=None):
        super().__init__(message, status_code=403, error_code="FORBIDDEN", details=details)


class NotFoundError(AegisxException):
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            f"{resource} not found: {identifier}",
            status_code=404,
            error_code="NOT_FOUND",
            details={"resource": resource, "identifier": identifier},
        )


class ValidationError(AegisxException):
    def __init__(self, message: str = "Validation failed", details=None):
        super().__init__(message, status_code=422, error_code="VALIDATION_FAILED", details=details)


class ConflictError(AegisxException):
    def __init__(self, message: str = "Resource already exists", details=None):
        super().__init__(message, status_code=409, error_code="CONFLICT", details=details)


class RateLimitError(AegisxException):
    def __init__(self, retry_after: int = 60):
        super().__init__(
            "Rate limit exceeded",
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details={"retry_after": retry_after},
        )


class TenantNotFoundError(NotFoundError):
    def __init__(self, identifier: str):
        super().__init__("Tenant", identifier)


class UserNotFoundError(NotFoundError):
    def __init__(self, identifier: str):
        super().__init__("User", identifier)


class AssetNotFoundError(NotFoundError):
    def __init__(self, identifier: str):
        super().__init__("Asset", identifier)


class IncidentNotFoundError(NotFoundError):
    def __init__(self, identifier: str):
        super().__init__("Incident", identifier)


class PlaybookNotFoundError(NotFoundError):
    def __init__(self, identifier: str):
        super().__init__("Playbook", identifier)


class AccountLockedError(AegisxException):
    def __init__(self, message: str = "Account is locked", details=None):
        super().__init__(message, status_code=423, error_code="ACCOUNT_LOCKED", details=details)


class AccountSuspendedError(AegisxException):
    def __init__(self, message: str = "Account is suspended", details=None):
        super().__init__(message, status_code=423, error_code="ACCOUNT_SUSPENDED", details=details)


class PasswordExpiredError(AegisxException):
    def __init__(self, message: str = "Password has expired", details=None):
        super().__init__(message, status_code=401, error_code="PASSWORD_EXPIRED", details=details)


class MFARrequiredError(AegisxException):
    def __init__(self, details=None):
        super().__init__(
            "MFA verification required",
            status_code=401,
            error_code="MFA_REQUIRED",
            details=details,
        )


class TenantQuotaExceededError(AegisxException):
    def __init__(self, resource: str):
        super().__init__(
            f"Tenant quota exceeded for {resource}",
            status_code=403,
            error_code="QUOTA_EXCEEDED",
            details={"resource": resource},
        )


class FeatureDisabledError(AegisxException):
    def __init__(self, feature: str):
        super().__init__(
            f"Feature '{feature}' is not enabled for this tenant",
            status_code=403,
            error_code="FEATURE_DISABLED",
            details={"feature": feature},
        )


class IntegrationError(AegisxException):
    def __init__(self, integration: str, message: str, details=None):
        super().__init__(
            f"Integration error [{integration}]: {message}",
            status_code=502,
            error_code="INTEGRATION_ERROR",
            details={"integration": integration, **(details or {})},
        )


class AgentConnectionError(AegisxException):
    def __init__(self, agent_id: str, message: str = "Agent connection failed"):
        super().__init__(
            message,
            status_code=502,
            error_code="AGENT_ERROR",
            details={"agent_id": agent_id},
        )
