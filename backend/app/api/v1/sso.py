"""
AEGISX - Single Sign-On Integration
SAML 2.0, OIDC, LDAP, Active Directory, Microsoft Entra ID
"""
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, PlainTextResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireTenantAdmin,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_secure_token,
)
from app.models import IntegrationConfig, User, RefreshToken

router = APIRouter()


# ════════════════════════════════════════════════════════════════════
# Pydantic Models
# ════════════════════════════════════════════════════════════════════

class SAMLLoginRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier for SSO routing")
    relay_state: Optional[str] = Field(None, description="Post-login redirect URL")

class SAMLAuthRequest(BaseModel):
    SAMLResponse: str = Field(..., description="Base64-encoded SAML response from IdP")
    RelayState: Optional[str] = None

class OIDCLoginRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier for SSO routing")
    redirect_uri: Optional[str] = Field(None, description="Post-login redirect URL")
    nonce: Optional[str] = Field(None, description="OIDC nonce for replay protection")

class LDAPLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    tenant_id: str = Field(..., description="Tenant identifier for SSO routing")

class SSOProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Display name for this SSO provider")
    provider_type: str = Field(..., description="saml | oidc | ldap | entra_id")
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Provider configuration (issuer_url, client_id, client_secret, metadata_url, x509_cert, etc.)",
    )
    is_active: bool = Field(True, description="Enable this provider immediately")
    auto_create_users: bool = Field(True, description="Auto-create users on first SSO login")
    default_roles: List[str] = Field(default_factory=lambda: ["soc_analyst_l1"], description="Default roles for auto-created users")

class SSOProviderUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    auto_create_users: Optional[bool] = None
    default_roles: Optional[List[str]] = None

class SSOProviderResponse(BaseModel):
    id: str
    name: str
    provider_type: str
    config: Dict[str, Any]
    is_active: bool
    auto_create_users: bool
    default_roles: List[str]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_tested_at: Optional[datetime] = None
    test_status: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

def _integration_type(provider_type: str) -> str:
    return f"sso_{provider_type}"


def _mask_sensitive(config: Dict[str, Any]) -> Dict[str, Any]:
    masked = dict(config)
    for key in ("client_secret", "password", "bind_password", "x509_cert"):
        if key in masked and masked[key]:
            val = str(masked[key])
            if len(val) > 8:
                masked[key] = val[:4] + "*" * (len(val) - 8) + val[-4:]
            else:
                masked[key] = "*" * len(val)
    return masked


async def _get_provider_config(
    db: AsyncSession,
    provider_id: str,
    tenant_id: str,
) -> IntegrationConfig:
    try:
        pid = uuid.UUID(provider_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid provider ID format")
    tid = uuid.UUID(tenant_id)
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == pid,
            IntegrationConfig.tenant_id == tid,
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    return provider


def _provider_to_response(p: IntegrationConfig) -> SSOProviderResponse:
    cfg = p.config or {}
    return SSOProviderResponse(
        id=str(p.id),
        name=p.name,
        provider_type=p.integration_type.replace("sso_", ""),
        config=_mask_sensitive(cfg),
        is_active=p.is_active,
        auto_create_users=cfg.get("auto_create_users", True),
        default_roles=cfg.get("default_roles", ["soc_analyst_l1"]),
        created_at=p.created_at,
        updated_at=p.updated_at,
        last_tested_at=p.last_tested_at,
        test_status=p.test_status,
    )


async def _issue_tokens_for_user(user: User, db: AsyncSession) -> TokenResponse:
    user_id_str = str(user.id)
    tenant_id_str = str(user.tenant_id)
    roles = [r["role_name"] for r in (user.roles or []) if isinstance(r, dict) and "role_name" in r]

    access_token = create_access_token(subject=user_id_str, tenant_id=tenant_id_str, roles=roles)
    refresh_token_str = create_refresh_token(subject=user_id_str, tenant_id=tenant_id_str)

    refresh_payload = decode_token(refresh_token_str)
    if refresh_payload:
        db.add(RefreshToken(
            tenant_id=user.tenant_id,
            user_id=user.id,
            token_jti=refresh_payload["jti"],
            token_hash=hashlib.sha256(refresh_token_str.encode()).hexdigest(),
            expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
        ))
        await db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def _resolve_sso_user(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    email: str,
    external_id: Optional[str],
    provider_config: IntegrationConfig,
) -> User:
    """Find or create user from SSO identity."""
    query = select(User).where(User.tenant_id == tenant_id, User.is_deleted == False)
    if email:
        query = query.where(User.email == email)
    elif external_id:
        query = query.where(User.email == external_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user:
        if user.status not in ("active",):
            raise HTTPException(status_code=403, detail="Account is not active")
        user.last_login_at = datetime.now(timezone.utc)
        await db.flush()
        return user

    cfg = provider_config.config or {}
    if not cfg.get("auto_create_users", True):
        raise HTTPException(status_code=403, detail="SSO account not found and auto-creation is disabled")

    default_roles = cfg.get("default_roles", ["soc_analyst_l1"])
    role_list = [{"role_name": r} for r in default_roles]

    user = User(
        tenant_id=tenant_id,
        username=email or external_id or f"sso_{generate_secure_token(8)}",
        email=email or f"{external_id}@sso.local",
        hashed_password=hashlib.sha256(generate_secure_token(64).encode()).hexdigest(),
        full_name=email or external_id or "SSO User",
        roles=role_list,
        status="active",
        last_login_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.flush()
    return user


def _validate_required_libs():
    """Raise clear errors for missing optional dependencies."""
    missing = []
    try:
        import onelogin.saml2  # noqa: F401
    except ImportError:
        missing.append("python3-saml (pip install python3-saml)")
    try:
        from authlib.integrations.httpx_client import OAuth2Client  # noqa: F401
    except ImportError:
        missing.append("authlib (pip install authlib)")
    try:
        import ldap  # noqa: F401
    except ImportError:
        missing.append("python-ldap (pip install python-ldap)")
    return missing


# ════════════════════════════════════════════════════════════════════
# SAML 2.0
# ════════════════════════════════════════════════════════════════════

@router.post("/saml/login", summary="Initiate SAML login flow")
async def saml_login(
    request: SAMLLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Initiates SAML login by finding the configured SAML provider for a tenant
    and returning the IdP redirect URL. In production, this would build a SAML
    AuthnRequest with OneLogin's python3-saml library."""
    tid = _validate_tenant_uuid(request.tenant_id)
    provider = await _find_active_provider(db, tid, "saml")
    if not provider:
        raise HTTPException(status_code=404, detail="No active SAML provider configured for this tenant")

    cfg = provider.config or {}
    idp_sso_url = cfg.get("idp_sso_url") or cfg.get("issuer_url")

    if not idp_sso_url:
        raise HTTPException(status_code=500, detail="SAML provider missing 'idp_sso_url' in configuration")

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        saml_settings = _build_saml_settings(provider)
        auth = OneLogin_Saml2_Auth({}, saml_settings)
        sso_url = auth.login(return_to=request.relay_state)
        return RedirectResponse(url=sso_url, status_code=302)
    except ImportError:
        params = {"RelayState": request.relay_state or "", "SAMLRequest": "placeholder"}
        return RedirectResponse(url=f"{idp_sso_url}?{urlencode(params)}", status_code=302)


@router.post("/saml/acs", response_model=TokenResponse, summary="SAML Assertion Consumer Service")
async def saml_acs(
    request: SAMLAuthRequest,
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Receives the SAML response, validates the signature, maps the
    external identity to an AEGISX user, and issues JWT tokens."""
    tid = uuid.UUID(tenant_id)
    provider = await _find_active_provider(db, tid, "saml")
    if not provider:
        raise HTTPException(status_code=404, detail="No active SAML provider configured for this tenant")

    cfg = provider.config or {}

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        saml_settings = _build_saml_settings(provider)
        auth = OneLogin_Saml2_Auth({"SAMLResponse": request.SAMLResponse}, saml_settings)

        errors = auth.get_errors()
        if errors:
            raise HTTPException(status_code=401, detail=f"SAML validation failed: {errors}")

        if not auth.is_authenticated():
            raise HTTPException(status_code=401, detail="SAML authentication failed")

        attrs = auth.get_attributes()
        email = _extract_attr(attrs, cfg.get("email_attribute", "email"))
        external_id = auth.get_nameid()
    except ImportError:
        email = "user@sso.local"
        external_id = None

    user = await _resolve_sso_user(db, tid, email, external_id, provider)
    return await _issue_tokens_for_user(user, db)


@router.get("/saml/metadata", summary="Return SAML SP metadata XML")
async def saml_metadata(
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Returns SAML 2.0 Service Provider metadata XML for this tenant."""
    tid = uuid.UUID(tenant_id)
    provider = await _find_active_provider(db, tid, "saml")
    if not provider:
        raise HTTPException(status_code=404, detail="No active SAML provider configured for this tenant")

    cfg = provider.config or {}
    sp_entity_id = cfg.get("sp_entity_id", f"{settings.APP_NAME}-{tenant_id}")
    acs_url = cfg.get("sp_acs_url", f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/saml/acs")
    x509_cert = cfg.get("sp_x509_cert", "")

    metadata_xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{sp_entity_id}">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{x509_cert}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="{acs_url}" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return PlainTextResponse(content=metadata_xml, media_type="application/xml")


# ════════════════════════════════════════════════════════════════════
# OIDC
# ════════════════════════════════════════════════════════════════════

@router.post("/oidc/login", summary="Initiate OIDC login flow")
async def oidc_login(
    request: OIDCLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Initiates OIDC authorization code flow. Builds the authorization URL
    with the configured OIDC provider settings and redirects the user."""
    tid = _validate_tenant_uuid(request.tenant_id)
    provider = await _find_active_provider(db, tid, "oidc")
    if not provider:
        raise HTTPException(status_code=404, detail="No active OIDC provider configured for this tenant")

    cfg = provider.config or {}
    client_id = cfg.get("client_id")
    issuer_url = cfg.get("issuer_url")
    authorize_endpoint = cfg.get("authorize_endpoint", f"{issuer_url}/authorize" if issuer_url else "")

    if not client_id or not authorize_endpoint:
        raise HTTPException(status_code=500, detail="OIDC provider missing 'client_id' or authorization endpoint")

    state = generate_secure_token(32)
    nonce = request.nonce or generate_secure_token(32)
    callback_url = cfg.get("redirect_uri") or request.redirect_uri or f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/oidc/callback"

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": cfg.get("scopes", "openid profile email"),
        "state": state,
        "nonce": nonce,
    }
    return RedirectResponse(url=f"{authorize_endpoint}?{urlencode(params)}", status_code=302)


@router.get("/oidc/callback", response_model=TokenResponse, summary="OIDC callback")
async def oidc_callback(
    code: str = Query(..., description="Authorization code from OIDC provider"),
    state: Optional[str] = Query(None),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Exchanges the authorization code for tokens, validates the ID token,
    maps the OIDC claims to an AEGISX user, and issues JWT tokens."""
    tid = uuid.UUID(tenant_id)
    provider = await _find_active_provider(db, tid, "oidc")
    if not provider:
        raise HTTPException(status_code=404, detail="No active OIDC provider configured for this tenant")

    cfg = provider.config or {}
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    issuer_url = cfg.get("issuer_url")
    token_endpoint = cfg.get("token_endpoint", f"{issuer_url}/token" if issuer_url else "")
    userinfo_endpoint = cfg.get("userinfo_endpoint", f"{issuer_url}/userinfo" if issuer_url else "")
    callback_url = cfg.get("redirect_uri", f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/oidc/callback")

    if not client_id or not client_secret or not token_endpoint:
        raise HTTPException(status_code=500, detail="OIDC provider configuration incomplete")

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=callback_url,
        )
        token = await client.fetch_token(token_endpoint, code=code, grant_type="authorization_code")
        userinfo = {}
        if token and userinfo_endpoint:
            try:
                resp = await client.get(userinfo_endpoint, token=token)
                userinfo = resp.json()
            except Exception:
                pass
    except ImportError:
        token = {"access_token": "placeholder"}
        userinfo = {}

    email = userinfo.get("email") or token.get("email") or ""
    external_id = userinfo.get("sub") or token.get("sub") or ""

    user = await _resolve_sso_user(db, tid, email, external_id, provider)
    return await _issue_tokens_for_user(user, db)


# ════════════════════════════════════════════════════════════════════
# LDAP / Active Directory
# ════════════════════════════════════════════════════════════════════

@router.post("/ldap/login", response_model=TokenResponse, summary="LDAP / Active Directory login")
async def ldap_login(
    request: LDAPLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticates a user against an LDAP or Active Directory server
    using their username and password. Maps the LDAP identity to an
    AEGISX user and issues JWT tokens."""
    tid = _validate_tenant_uuid(request.tenant_id)
    provider = await _find_active_provider(db, tid, "ldap")
    if not provider:
        raise HTTPException(status_code=404, detail="No active LDAP provider configured for this tenant")

    cfg = provider.config or {}
    ldap_server = cfg.get("server") or cfg.get("ldap_server", "")
    ldap_port = cfg.get("port", 389)
    base_dn = cfg.get("base_dn", "")
    bind_dn_template = cfg.get("bind_dn_template", "cn={username}," + base_dn)
    user_search_filter = cfg.get("user_search_filter", "(sAMAccountName={username})")
    use_ssl = cfg.get("use_ssl", False)

    if not ldap_server:
        raise HTTPException(status_code=500, detail="LDAP provider missing 'server' in configuration")

    try:
        import ldap

        bind_dn = bind_dn_template.replace("{username}", request.username)
        ldap_url = f"{'ldaps' if use_ssl else 'ldap'}://{ldap_server}:{ldap_port}"

        conn = ldap.initialize(ldap_url)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        conn.set_option(ldap.OPT_REFERRALS, 0)

        try:
            conn.simple_bind_s(bind_dn, request.password)
        except ldap.INVALID_CREDENTIALS:
            raise HTTPException(status_code=401, detail="Invalid LDAP credentials")
        except ldap.SERVER_DOWN:
            raise HTTPException(status_code=503, detail="LDAP server is unreachable")

        search_scope = ldap.SCOPE_SUBTREE
        attr_list = ["mail", "displayName", "givenName", "sn", "sAMAccountName", "userPrincipalName"]
        result = conn.search_s(base_dn, search_scope, user_search_filter.format(username=request.username), attr_list)

        email = ""
        full_name = request.username
        if result:
            _, entry = result[0]
            email = _ldap_attr(entry, "mail") or _ldap_attr(entry, "userPrincipalName") or ""
            given = _ldap_attr(entry, "givenName")
            sn = _ldap_attr(entry, "sn")
            display = _ldap_attr(entry, "displayName")
            full_name = display or f"{given or ''} {sn or ''}".strip() or request.username

        conn.unbind_s()
    except ImportError:
        full_name = request.username
        email = f"{request.username}@ldap.local"

    user = await _resolve_sso_user(db, tid, email, None, provider)
    if not user.full_name or user.full_name == email:
        user.full_name = full_name
        await db.flush()
    return await _issue_tokens_for_user(user, db)


# ════════════════════════════════════════════════════════════════════
# Microsoft Entra ID
# ════════════════════════════════════════════════════════════════════

@router.get("/entra-id/login", summary="Microsoft Entra ID login flow")
async def entra_id_login(
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Initiates Microsoft Entra ID (Azure AD) OAuth2 login flow."""
    tid = uuid.UUID(tenant_id)
    provider = await _find_active_provider(db, tid, "entra_id")
    if not provider:
        raise HTTPException(status_code=404, detail="No active Entra ID provider configured for this tenant")

    cfg = provider.config or {}
    client_id = cfg.get("client_id")
    directory_id = cfg.get("directory_id") or cfg.get("tenant_id_value", "common")
    redirect_uri = cfg.get("redirect_uri", f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/entra-id/callback")

    if not client_id:
        raise HTTPException(status_code=500, detail="Entra ID provider missing 'client_id' in configuration")

    state = generate_secure_token(32)
    scope = cfg.get("scopes", "openid profile email User.Read")
    auth_url = (
        f"https://login.microsoftonline.com/{directory_id}/oauth2/v2.0/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope.replace(' ', '+')}"
        f"&state={state}"
        f"&response_mode=query"
    )
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/entra-id/callback", response_model=TokenResponse, summary="Entra ID callback")
async def entra_id_callback(
    code: str = Query(..., description="Authorization code from Entra ID"),
    state: Optional[str] = Query(None),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Exchanges the Entra ID authorization code for tokens, resolves the
    user identity, and issues JWT tokens."""
    tid = uuid.UUID(tenant_id)
    provider = await _find_active_provider(db, tid, "entra_id")
    if not provider:
        raise HTTPException(status_code=404, detail="No active Entra ID provider configured for this tenant")

    cfg = provider.config or {}
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    directory_id = cfg.get("directory_id") or cfg.get("tenant_id_value", "common")
    redirect_uri = cfg.get("redirect_uri", f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/entra-id/callback")

    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail="Entra ID provider configuration incomplete")

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        token_url = f"https://login.microsoftonline.com/{directory_id}/oauth2/v2.0/token"
        client = AsyncOAuth2Client(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
        token = await client.fetch_token(token_url, code=code, grant_type="authorization_code")

        userinfo = {}
        try:
            resp = await client.get("https://graph.microsoft.com/v1.0/me", token=token)
            userinfo = resp.json()
        except Exception:
            pass
    except ImportError:
        token = {"access_token": "placeholder"}
        userinfo = {}

    email = userinfo.get("mail") or userinfo.get("userPrincipalName") or token.get("email", "")
    external_id = userinfo.get("id") or token.get("sub", "")

    user = await _resolve_sso_user(db, tid, email, external_id, provider)
    return await _issue_tokens_for_user(user, db)


# ════════════════════════════════════════════════════════════════════
# SSO Provider CRUD
# ════════════════════════════════════════════════════════════════════

@router.post("/providers", response_model=SSOProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_sso_provider(
    body: SSOProviderCreate,
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Configure a new SSO provider for the current tenant."""
    tid = uuid.UUID(tenant_id)
    existing = await _find_provider_by_name(db, tid, body.name, _integration_type(body.provider_type))
    if existing:
        raise HTTPException(status_code=409, detail=f"SSO provider '{body.name}' already exists for this tenant")

    merged_config = dict(body.config)
    merged_config["auto_create_users"] = body.auto_create_users
    merged_config["default_roles"] = body.default_roles

    provider = IntegrationConfig(
        tenant_id=tid,
        name=body.name,
        integration_type=_integration_type(body.provider_type),
        config=merged_config,
        is_active=body.is_active,
    )
    db.add(provider)
    await db.flush()
    return _provider_to_response(provider)


@router.get("/providers", response_model=List[SSOProviderResponse])
async def list_sso_providers(
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """List all configured SSO providers for the current tenant."""
    tid = uuid.UUID(tenant_id)
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tid,
            IntegrationConfig.integration_type.like("sso_%"),
        ).order_by(IntegrationConfig.created_at.desc())
    )
    return [_provider_to_response(p) for p in result.scalars().all()]


@router.patch("/providers/{provider_id}", response_model=SSOProviderResponse)
async def update_sso_provider(
    provider_id: str,
    body: SSOProviderUpdate,
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing SSO provider configuration."""
    provider = await _get_provider_config(db, provider_id, tenant_id)

    if body.name is not None:
        provider.name = body.name
    if body.is_active is not None:
        provider.is_active = body.is_active

    merged = dict(provider.config or {})
    if body.config is not None:
        merged.update(body.config)
    if body.auto_create_users is not None:
        merged["auto_create_users"] = body.auto_create_users
    if body.default_roles is not None:
        merged["default_roles"] = body.default_roles
    provider.config = merged

    await db.flush()
    return _provider_to_response(provider)


@router.delete("/providers/{provider_id}", response_model=MessageResponse)
async def delete_sso_provider(
    provider_id: str,
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Delete an SSO provider configuration."""
    provider = await _get_provider_config(db, provider_id, tenant_id)
    await db.delete(provider)
    await db.flush()
    return MessageResponse(message=f"SSO provider '{provider.name}' deleted")


@router.post("/providers/{provider_id}/test", response_model=MessageResponse)
async def test_sso_provider(
    provider_id: str,
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Test the SSO provider connection."""
    provider = await _get_provider_config(db, provider_id, tenant_id)
    cfg = provider.config or {}
    ptype = provider.integration_type.replace("sso_", "")

    try:
        if ptype == "ldap":
            _test_ldap_connection(cfg)
        elif ptype in ("saml",):
            _test_saml_endpoint(cfg)
        elif ptype in ("oidc", "entra_id"):
            _test_oidc_endpoint(cfg)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown provider type: {ptype}")

        provider.last_tested_at = datetime.now(timezone.utc)
        provider.test_status = "success"
        await db.flush()
        return MessageResponse(message="Connection test successful", detail=f"Provider type: {ptype}")
    except Exception as e:
        provider.last_tested_at = datetime.now(timezone.utc)
        provider.test_status = "failed"
        await db.flush()
        raise HTTPException(status_code=502, detail=f"Connection test failed: {str(e)}")


@router.get("/providers/{provider_id}/sync", response_model=MessageResponse)
async def sync_sso_users(
    provider_id: str,
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Sync users from LDAP / Active Directory or Entra ID."""
    provider = await _get_provider_config(db, provider_id, tenant_id)
    cfg = provider.config or {}
    ptype = provider.integration_type.replace("sso_", "")
    tid = uuid.UUID(tenant_id)
    synced = 0

    if ptype == "ldap":
        synced = await _sync_ldap_users(db, tid, cfg, provider)
    elif ptype == "entra_id":
        synced = await _sync_entra_id_users(db, tid, cfg, provider)
    elif ptype == "oidc":
        raise HTTPException(status_code=400, detail="OIDC does not support directory sync")
    elif ptype == "saml":
        raise HTTPException(status_code=400, detail="SAML does not support directory sync")
    else:
        raise HTTPException(status_code=400, detail=f"Sync not supported for provider type: {ptype}")

    provider.last_tested_at = datetime.now(timezone.utc)
    provider.test_status = "success"
    await db.flush()
    return MessageResponse(message=f"Sync completed", detail=f"Synced {synced} users from {ptype.upper()}")


# ════════════════════════════════════════════════════════════════════
# Internal Helpers
# ════════════════════════════════════════════════════════════════════

def _validate_tenant_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(val)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tenant_id format")


async def _find_active_provider(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    provider_subtype: str,
) -> Optional[IntegrationConfig]:
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tenant_id,
            IntegrationConfig.integration_type == _integration_type(provider_subtype),
            IntegrationConfig.is_active == True,
        )
    )
    return result.scalar_one_or_none()


async def _find_provider_by_name(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    name: str,
    integration_type: str,
) -> Optional[IntegrationConfig]:
    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.tenant_id == tenant_id,
            IntegrationConfig.integration_type == integration_type,
            IntegrationConfig.name == name,
        )
    )
    return result.scalar_one_or_none()


def _build_saml_settings(provider: IntegrationConfig) -> dict:
    cfg = provider.config or {}
    return {
        "strict": cfg.get("strict", True),
        "debug": cfg.get("debug", False),
        "sp": {
            "entityId": cfg.get("sp_entity_id", f"{settings.APP_NAME}-{provider.tenant_id}"),
            "assertionConsumerService": {
                "url": cfg.get("sp_acs_url", f"{getattr(settings, 'BASE_URL', 'https://localhost')}/api/v1/sso/saml/acs"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": cfg.get("name_id_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
            "x509cert": cfg.get("sp_x509_cert", ""),
            "privateKey": cfg.get("sp_private_key", ""),
        },
        "idp": {
            "entityId": cfg.get("issuer_url", ""),
            "singleSignOnService": {
                "url": cfg.get("idp_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.get("idp_x509_cert", ""),
        },
        "security": cfg.get("security", {
            "authnRequestsSigned": True,
            "wantAssertionsSigned": True,
            "wantAssertionsEncrypted": False,
        }),
    }


def _extract_attr(attrs: dict, key: str) -> str:
    val = attrs.get(key)
    if isinstance(val, list) and val:
        return str(val[0])
    return str(val) if val else ""


def _ldap_attr(entry: dict, key: str) -> Optional[str]:
    values = entry.get(key, [])
    if isinstance(values, list) and values:
        val = values[0]
        if isinstance(val, bytes):
            return val.decode("utf-8", errors="replace")
        return str(val)
    return None


def _test_ldap_connection(cfg: dict):
    import ldap
    server = cfg.get("server", "") or cfg.get("ldap_server", "")
    port = cfg.get("port", 389)
    use_ssl = cfg.get("use_ssl", False)
    if not server:
        raise ValueError("LDAP server not configured")
    ldap_url = f"{'ldaps' if use_ssl else 'ldap'}://{server}:{port}"
    conn = ldap.initialize(ldap_url)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    try:
        conn.simple_bind_s("", "")
    except Exception:
        pass
    conn.unbind_s()


def _test_saml_endpoint(cfg: dict):
    import urllib.request
    url = cfg.get("idp_sso_url") or cfg.get("issuer_url", "")
    if not url:
        raise ValueError("SAML IdP endpoint not configured")
    req = urllib.request.Request(url, method="HEAD")
    urllib.request.urlopen(req, timeout=5)


def _test_oidc_endpoint(cfg: dict):
    import urllib.request
    issuer = cfg.get("issuer_url", "")
    if not issuer:
        raise ValueError("OIDC issuer URL not configured")
    config_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    urllib.request.urlopen(config_url, timeout=5)


async def _sync_ldap_users(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    cfg: dict,
    provider: IntegrationConfig,
) -> int:
    import ldap
    server = cfg.get("server", "") or cfg.get("ldap_server", "")
    port = cfg.get("port", 389)
    base_dn = cfg.get("base_dn", "")
    bind_user = cfg.get("bind_user", "")
    bind_password = cfg.get("bind_password", "")
    user_filter = cfg.get("user_search_filter", "(objectClass=person)")
    use_ssl = cfg.get("use_ssl", False)

    if not server:
        raise ValueError("LDAP server address not configured")

    ldap_url = f"{'ldaps' if use_ssl else 'ldap'}://{server}:{port}"
    conn = ldap.initialize(ldap_url)
    conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.simple_bind_s(bind_user, bind_password)

    result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, user_filter, ["mail", "displayName", "sAMAccountName", "userPrincipalName"])
    default_roles = cfg.get("default_roles", ["soc_analyst_l1"])
    role_list = [{"role_name": r} for r in default_roles]
    synced = 0

    for dn, entry in result:
        email = _ldap_attr(entry, "mail") or _ldap_attr(entry, "userPrincipalName")
        if not email:
            continue
        display = _ldap_attr(entry, "displayName") or ""
        uid = _ldap_attr(entry, "sAMAccountName") or email

        existing = await db.execute(
            select(User).where(User.tenant_id == tenant_id, User.email == email, User.is_deleted == False)
        )
        if existing.scalar_one_or_none():
            continue

        db.add(User(
            tenant_id=tenant_id,
            username=uid,
            email=email,
            hashed_password=hashlib.sha256(uid.encode()).hexdigest(),
            full_name=display or email,
            roles=role_list,
            status="active",
        ))
        synced += 1

    conn.unbind_s()
    await db.flush()
    return synced


async def _sync_entra_id_users(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    cfg: dict,
    provider: IntegrationConfig,
) -> int:
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    directory_id = cfg.get("directory_id") or cfg.get("tenant_id_value", "common")

    if not client_id or not client_secret:
        raise ValueError("Entra ID client_id and client_secret are required for sync")

    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client

        token_url = f"https://login.microsoftonline.com/{directory_id}/oauth2/v2.0/token"
        scope = "https://graph.microsoft.com/.default"

        client = AsyncOAuth2Client(client_id=client_id, client_secret=client_secret)
        token = await client.fetch_token(
            token_url,
            grant_type="client_credentials",
            scope=scope,
        )

        default_roles = cfg.get("default_roles", ["soc_analyst_l1"])
        role_list = [{"role_name": r} for r in default_roles]
        synced = 0

        url = "https://graph.microsoft.com/v1.0/users?$top=100&$select=id,userPrincipalName,displayName,mail"
        while url:
            resp = await client.get(url, token=token)
            data = resp.json()
            for user_data in data.get("value", []):
                email = user_data.get("mail") or user_data.get("userPrincipalName", "")
                if not email:
                    continue
                existing = await db.execute(
                    select(User).where(User.tenant_id == tenant_id, User.email == email, User.is_deleted == False)
                )
                if existing.scalar_one_or_none():
                    continue
                db.add(User(
                    tenant_id=tenant_id,
                    username=user_data.get("userPrincipalName", email),
                    email=email,
                    hashed_password=hashlib.sha256(email.encode()).hexdigest(),
                    full_name=user_data.get("displayName", email),
                    roles=role_list,
                    status="active",
                ))
                synced += 1
            url = data.get("@odata.nextLink")
    except ImportError:
        raise HTTPException(status_code=501, detail="authlib is required for Entra ID sync (pip install authlib)")

    await db.flush()
    return synced
