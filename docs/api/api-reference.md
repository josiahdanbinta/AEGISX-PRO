# AEGISX API Reference v1.0.0

A comprehensive, AI-powered cybersecurity platform combining SIEM, SOAR, XDR,
Vulnerability Management, Asset Management, Threat Intelligence, Compliance,
and Incident Response.

**Base URL:** `/api/v1`
**Authentication:** Bearer JWT token in `Authorization` header
**Multi-Tenancy:** `X-Tenant-ID` header required for all tenant-scoped endpoints

---

## Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Login with email/password |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Invalidate current session |
| POST | `/auth/mfa/verify` | Verify MFA code (TOTP or backup) |
| POST | `/auth/mfa/setup` | Initialize MFA setup, returns QR URI |
| POST | `/auth/mfa/enable` | Confirm and enable MFA |
| POST | `/auth/mfa/disable` | Disable MFA (requires password) |
| POST | `/auth/password/reset-request` | Request password reset |
| POST | `/auth/password/reset-approve/{request_id}` | Admin approves reset request |
| POST | `/auth/password/reset/{token}` | Execute reset with approved token |
| POST | `/auth/password/change` | Change own password |
| POST | `/auth/webauthn/register` | Register passkey |
| POST | `/auth/webauthn/verify` | Complete passkey registration |
| POST | `/auth/api-key/generate` | Generate API key |
| GET | `/auth/api-key/list` | List API keys |
| DELETE | `/auth/api-key/{key_id}` | Revoke API key |
| GET | `/auth/me` | Get current user profile |
| PATCH | `/auth/me` | Update profile |

## SSO & Identity

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/sso/saml/login` | Initiate SAML login flow |
| POST | `/sso/saml/acs` | SAML Assertion Consumer Service |
| GET | `/sso/saml/metadata` | SAML SP metadata XML |
| POST | `/sso/oidc/login` | Initiate OIDC login flow |
| GET | `/sso/oidc/callback` | OIDC callback |
| POST | `/sso/ldap/login` | LDAP / Active Directory login |
| GET | `/sso/entra-id/login` | Microsoft Entra ID login flow |
| GET | `/sso/entra-id/callback` | Entra ID callback |
| POST | `/sso/providers` | Create SSO provider |
| GET | `/sso/providers` | List SSO providers |
| PATCH | `/sso/providers/{provider_id}` | Update SSO provider |
| DELETE | `/sso/providers/{provider_id}` | Remove SSO provider |
| POST | `/sso/providers/{provider_id}/test` | Test SSO provider connection |
| GET | `/sso/providers/{provider_id}/sync` | Sync users from provider |

## Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health/` | Basic health check |
| GET | `/health/ready` | Readiness probe (DB, cache, search) |
| GET | `/health/live` | Kubernetes liveness probe |

---

# Endpoints by Category

---

## 1. Authentication (18 endpoints)

### POST /auth/login
Authenticate with email/password and receive JWT tokens. Returns MFA challenge if enabled.

**Endpoint:** `POST /api/v1/auth/login`

### POST /auth/refresh
Exchange a valid refresh token for a new access/refresh token pair.

**Endpoint:** `POST /api/v1/auth/refresh`

### POST /auth/logout
Invalidate current session token.

**Endpoint:** `POST /api/v1/auth/logout`

### POST /auth/mfa/verify
Verify MFA code (TOTP or backup code) and complete login.

**Endpoint:** `POST /api/v1/auth/mfa/verify`

### POST /auth/mfa/setup
Initialize MFA setup, returns secret and QR code URI.

**Endpoint:** `POST /api/v1/auth/mfa/setup`

### POST /auth/mfa/enable
Confirm MFA setup and enable it for the account.

**Endpoint:** `POST /api/v1/auth/mfa/enable`

### POST /auth/mfa/disable
Disable MFA for the account (requires password confirmation).

**Endpoint:** `POST /api/v1/auth/mfa/disable`

### POST /auth/password/reset-request
Submit a password reset request. Requires admin approval.

**Endpoint:** `POST /api/v1/auth/password/reset-request`

### POST /auth/password/reset-approve/{request_id}
Tenant admin approves a password reset request.

**Endpoint:** `POST /api/v1/auth/password/reset-approve/{request_id}`

### POST /auth/password/reset/{token}
Reset password using the approved reset token.

**Endpoint:** `POST /api/v1/auth/password/reset/{token}`

### POST /auth/password/change
Change your own password (requires current password).

**Endpoint:** `POST /api/v1/auth/password/change`

### POST /auth/webauthn/register
Start WebAuthn/passkey registration.

**Endpoint:** `POST /api/v1/auth/webauthn/register`

### POST /auth/webauthn/verify
Verify and complete WebAuthn passkey registration.

**Endpoint:** `POST /api/v1/auth/webauthn/verify`

### POST /auth/api-key/generate
Create a new API key for programmatic access.

**Endpoint:** `POST /api/v1/auth/api-key/generate`

### GET /auth/api-key/list
List all API keys for the current user.

**Endpoint:** `GET /api/v1/auth/api-key/list`

### DELETE /auth/api-key/{key_id}
Revoke and delete an API key.

**Endpoint:** `DELETE /api/v1/auth/api-key/{key_id}`

### GET /auth/me
Return the authenticated user's profile.

**Endpoint:** `GET /api/v1/auth/me`

### PATCH /auth/me
Update your own profile information.

**Endpoint:** `PATCH /api/v1/auth/me`

---

## 2. SSO & Identity Federation (14 endpoints)

### POST /sso/saml/login
Initiate SAML login flow.

**Endpoint:** `POST /api/v1/sso/saml/login`

### POST /sso/saml/acs
SAML Assertion Consumer Service endpoint.

**Endpoint:** `POST /api/v1/sso/saml/acs`

### GET /sso/saml/metadata
Return SAML SP metadata XML.

**Endpoint:** `GET /api/v1/sso/saml/metadata`

### POST /sso/oidc/login
Initiate OIDC login flow.

**Endpoint:** `POST /api/v1/sso/oidc/login`

### GET /sso/oidc/callback
OIDC callback endpoint.

**Endpoint:** `GET /api/v1/sso/oidc/callback`

### POST /sso/ldap/login
LDAP / Active Directory login.

**Endpoint:** `POST /api/v1/sso/ldap/login`

### GET /sso/entra-id/login
Microsoft Entra ID login flow.

**Endpoint:** `GET /api/v1/sso/entra-id/login`

### GET /sso/entra-id/callback
Entra ID callback endpoint.

**Endpoint:** `GET /api/v1/sso/entra-id/callback`

### POST /sso/providers
Create an SSO provider configuration.

**Endpoint:** `POST /api/v1/sso/providers`

### GET /sso/providers
List all SSO provider configurations.

**Endpoint:** `GET /api/v1/sso/providers`

### PATCH /sso/providers/{provider_id}
Update an SSO provider configuration.

**Endpoint:** `PATCH /api/v1/sso/providers/{provider_id}`

### DELETE /sso/providers/{provider_id}
Remove an SSO provider configuration.

**Endpoint:** `DELETE /api/v1/sso/providers/{provider_id}`

### POST /sso/providers/{provider_id}/test
Test SSO provider connection.

**Endpoint:** `POST /api/v1/sso/providers/{provider_id}/test`

### GET /sso/providers/{provider_id}/sync
Sync users from the SSO provider.

**Endpoint:** `GET /api/v1/sso/providers/{provider_id}/sync`

---

## 3. Tenants (9 endpoints)

### POST /tenants
Create a new tenant.

**Endpoint:** `POST /api/v1/tenants`

### GET /tenants
List all tenants (paginated).

**Endpoint:** `GET /api/v1/tenants`

### GET /tenants/{tenant_id}
Get tenant details.

**Endpoint:** `GET /api/v1/tenants/{tenant_id}`

### PATCH /tenants/{tenant_id}
Update tenant configuration.

**Endpoint:** `PATCH /api/v1/tenants/{tenant_id}`

### DELETE /tenants/{tenant_id}
Delete a tenant.

**Endpoint:** `DELETE /api/v1/tenants/{tenant_id}`

### POST /tenants/{tenant_id}/suspend
Suspend a tenant.

**Endpoint:** `POST /api/v1/tenants/{tenant_id}/suspend`

### POST /tenants/{tenant_id}/activate
Activate a suspended tenant.

**Endpoint:** `POST /api/v1/tenants/{tenant_id}/activate`

### GET /tenants/{tenant_id}/stats
Get tenant usage statistics.

**Endpoint:** `GET /api/v1/tenants/{tenant_id}/stats`

### GET /tenants/{tenant_id}/users
List users within a tenant.

**Endpoint:** `GET /api/v1/tenants/{tenant_id}/users`

---

## 4. Users (19 endpoints)

### POST /users
Create a new user.

**Endpoint:** `POST /api/v1/users`

### GET /users
List users (paginated, filterable).

**Endpoint:** `GET /api/v1/users`

### GET /users/{user_id}
Get user details.

**Endpoint:** `GET /api/v1/users/{user_id}`

### PATCH /users/{user_id}
Update user details.

**Endpoint:** `PATCH /api/v1/users/{user_id}`

### DELETE /users/{user_id}
Soft-delete a user.

**Endpoint:** `DELETE /api/v1/users/{user_id}`

### POST /users/{user_id}/roles
Assign roles to a user.

**Endpoint:** `POST /api/v1/users/{user_id}/roles`

### DELETE /users/{user_id}/roles
Remove roles from a user.

**Endpoint:** `DELETE /api/v1/users/{user_id}/roles`

### POST /users/{user_id}/suspend
Suspend a user account.

**Endpoint:** `POST /api/v1/users/{user_id}/suspend`

### POST /users/{user_id}/activate
Activate a suspended user.

**Endpoint:** `POST /api/v1/users/{user_id}/activate`

### GET /roles
List all roles.

**Endpoint:** `GET /api/v1/users/roles`

### POST /roles
Create a new role.

**Endpoint:** `POST /api/v1/users/roles`

### PATCH /roles/{role_id}
Update a role.

**Endpoint:** `PATCH /api/v1/users/roles/{role_id}`

### DELETE /roles/{role_id}
Delete a role.

**Endpoint:** `DELETE /api/v1/users/roles/{role_id}`

### GET /departments
List departments.

**Endpoint:** `GET /api/v1/users/departments`

### POST /departments
Create a department.

**Endpoint:** `POST /api/v1/users/departments`

### PATCH /departments/{dept_id}
Update a department.

**Endpoint:** `PATCH /api/v1/users/departments/{dept_id}`

### DELETE /departments/{dept_id}
Delete a department.

**Endpoint:** `DELETE /api/v1/users/departments/{dept_id}`

### GET /users/bulk
Bulk export users.

**Endpoint:** `GET /api/v1/users/bulk`

### POST /users/bulk
Bulk import users.

**Endpoint:** `POST /api/v1/users/bulk`

---

## 5. Assets (27 endpoints)

### POST /assets
Register a new asset.

**Endpoint:** `POST /api/v1/assets`

### GET /assets
List assets (paginated, filterable).

**Endpoint:** `GET /api/v1/assets`

### GET /assets/{asset_id}
Get asset details.

**Endpoint:** `GET /api/v1/assets/{asset_id}`

### PATCH /assets/{asset_id}
Update asset information.

**Endpoint:** `PATCH /api/v1/assets/{asset_id}`

### DELETE /assets/{asset_id}
Remove an asset.

**Endpoint:** `DELETE /api/v1/assets/{asset_id}`

### POST /assets/discover/scan
Start a discovery scan.

**Endpoint:** `POST /api/v1/assets/discover/scan`

### GET /assets/discover/scan/{scan_id}
Get discovery scan status.

**Endpoint:** `GET /api/v1/assets/discover/scan/{scan_id}`

### GET /assets/{asset_id}/hardware
Get asset hardware inventory.

**Endpoint:** `GET /api/v1/assets/{asset_id}/hardware`

### GET /assets/{asset_id}/software
Get asset software inventory.

**Endpoint:** `GET /api/v1/assets/{asset_id}/software`

### GET /assets/{asset_id}/network
Get asset network configuration.

**Endpoint:** `GET /api/v1/assets/{asset_id}/network`

### GET /assets/{asset_id}/processes
Get asset running processes.

**Endpoint:** `GET /api/v1/assets/{asset_id}/processes`

### POST /assets/{asset_id}/monitor/start
Start real-time monitoring.

**Endpoint:** `POST /api/v1/assets/{asset_id}/monitor/start`

### POST /assets/{asset_id}/monitor/stop
Stop real-time monitoring.

**Endpoint:** `POST /api/v1/assets/{asset_id}/monitor/stop`

### GET /assets/{asset_id}/vulnerabilities
Get vulnerabilities on an asset.

**Endpoint:** `GET /api/v1/assets/{asset_id}/vulnerabilities`

### GET /assets/{asset_id}/alerts
Get alerts for an asset.

**Endpoint:** `GET /api/v1/assets/{asset_id}/alerts`

### GET /assets/{asset_id}/incidents
Get incidents for an asset.

**Endpoint:** `GET /api/v1/assets/{asset_id}/incidents`

### POST /assets/{asset_id}/tags
Add tags to an asset.

**Endpoint:** `POST /api/v1/assets/{asset_id}/tags`

### DELETE /assets/{asset_id}/tags
Remove tags from an asset.

**Endpoint:** `DELETE /api/v1/assets/{asset_id}/tags`

### GET /assets/agents
List deployment agents.

**Endpoint:** `GET /api/v1/assets/agents`

### GET /assets/agents/{agent_id}
Get agent details.

**Endpoint:** `GET /api/v1/assets/agents/{agent_id}`

### POST /assets/agents/{agent_id}/command
Send command to an agent.

**Endpoint:** `POST /api/v1/assets/agents/{agent_id}/command`

### GET /assets/groups
List asset groups.

**Endpoint:** `GET /api/v1/assets/groups`

### POST /assets/groups
Create an asset group.

**Endpoint:** `POST /api/v1/assets/groups`

### PATCH /assets/groups/{group_id}
Update an asset group.

**Endpoint:** `PATCH /api/v1/assets/groups/{group_id}`

### DELETE /assets/groups/{group_id}
Delete an asset group.

**Endpoint:** `DELETE /api/v1/assets/groups/{group_id}`

### POST /assets/groups/{group_id}/assets
Add assets to a group.

**Endpoint:** `POST /api/v1/assets/groups/{group_id}/assets`

### DELETE /assets/groups/{group_id}/assets
Remove assets from a group.

**Endpoint:** `DELETE /api/v1/assets/groups/{group_id}/assets`

---

## 6. Detection (34 endpoints)

### POST /detection/rules
Create a detection rule.

**Endpoint:** `POST /api/v1/detection/rules`

### GET /detection/rules
List detection rules.

**Endpoint:** `GET /api/v1/detection/rules`

### GET /detection/rules/{rule_id}
Get rule details.

**Endpoint:** `GET /api/v1/detection/rules/{rule_id}`

### PATCH /detection/rules/{rule_id}
Update a rule.

**Endpoint:** `PATCH /api/v1/detection/rules/{rule_id}`

### DELETE /detection/rules/{rule_id}
Delete a rule.

**Endpoint:** `DELETE /api/v1/detection/rules/{rule_id}`

### POST /detection/rules/{rule_id}/enable
Enable a rule.

**Endpoint:** `POST /api/v1/detection/rules/{rule_id}/enable`

### POST /detection/rules/{rule_id}/disable
Disable a rule.

**Endpoint:** `POST /api/v1/detection/rules/{rule_id}/disable`

### POST /detection/rules/{rule_id}/test
Test a rule against sample data.

**Endpoint:** `POST /api/v1/detection/rules/{rule_id}/test`

### POST /detection/rules/bulk
Bulk import/update rules.

**Endpoint:** `POST /api/v1/detection/rules/bulk`

### GET /detection/rules/stats
Rule statistics.

**Endpoint:** `GET /api/v1/detection/rules/stats`

### POST /detection/signatures
Create a signature.

**Endpoint:** `POST /api/v1/detection/signatures`

### GET /detection/signatures
List signatures.

**Endpoint:** `GET /api/v1/detection/signatures`

### PATCH /detection/signatures/{sig_id}
Update a signature.

**Endpoint:** `PATCH /api/v1/detection/signatures/{sig_id}`

### DELETE /detection/signatures/{sig_id}
Delete a signature.

**Endpoint:** `DELETE /api/v1/detection/signatures/{sig_id}`

### GET /detection/alerts
List alerts (paginated, filterable).

**Endpoint:** `GET /api/v1/detection/alerts`

### GET /detection/alerts/{alert_id}
Get alert details.

**Endpoint:** `GET /api/v1/detection/alerts/{alert_id}`

### PATCH /detection/alerts/{alert_id}
Update alert status.

**Endpoint:** `PATCH /api/v1/detection/alerts/{alert_id}`

### POST /detection/alerts/{alert_id}/acknowledge
Acknowledge an alert.

**Endpoint:** `POST /api/v1/detection/alerts/{alert_id}/acknowledge`

### POST /detection/alerts/{alert_id}/dismiss
Dismiss an alert.

**Endpoint:** `POST /api/v1/detection/alerts/{alert_id}/dismiss`

### POST /detection/alerts/{alert_id}/escalate
Escalate alert to incident.

**Endpoint:** `POST /api/v1/detection/alerts/{alert_id}/escalate`

### GET /detection/alerts/stats
Alert statistics.

**Endpoint:** `GET /api/v1/detection/alerts/stats`

### POST /detection/behaviors
Create behavioral baseline.

**Endpoint:** `POST /api/v1/detection/behaviors`

### GET /detection/behaviors
List behavioral baselines.

**Endpoint:** `GET /api/v1/detection/behaviors`

### GET /detection/behaviors/{baseline_id}
Get baseline details.

**Endpoint:** `GET /api/v1/detection/behaviors/{baseline_id}`

### PATCH /detection/behaviors/{baseline_id}
Update baseline.

**Endpoint:** `PATCH /api/v1/detection/behaviors/{baseline_id}`

### DELETE /detection/behaviors/{baseline_id}
Delete baseline.

**Endpoint:** `DELETE /api/v1/detection/behaviors/{baseline_id}`

### GET /detection/anomalies
List anomalies detected.

**Endpoint:** `GET /api/v1/detection/anomalies`

### POST /detection/ml/train
Train ML model.

**Endpoint:** `POST /api/v1/detection/ml/train`

### GET /detection/ml/models
List ML models.

**Endpoint:** `GET /api/v1/detection/ml/models`

### POST /detection/ml/predict
Run ML prediction.

**Endpoint:** `POST /api/v1/detection/ml/predict`

### POST /detection/correlations
Create correlation rule.

**Endpoint:** `POST /api/v1/detection/correlations`

### GET /detection/correlations
List correlation rules.

**Endpoint:** `GET /api/v1/detection/correlations`

### GET /detection/intel-feeds
List threat intel feeds.

**Endpoint:** `GET /api/v1/detection/intel-feeds`

### GET /detection/alerts/{alert_id}/evidence
Get alert evidence.

**Endpoint:** `GET /api/v1/detection/alerts/{alert_id}/evidence`

---

## 7. Incidents (26 endpoints)

### POST /incidents
Create an incident.

**Endpoint:** `POST /api/v1/incidents`

### GET /incidents
List incidents (paginated, filterable).

**Endpoint:** `GET /api/v1/incidents`

### GET /incidents/{incident_id}
Get incident details.

**Endpoint:** `GET /api/v1/incidents/{incident_id}`

### PATCH /incidents/{incident_id}
Update incident.

**Endpoint:** `PATCH /api/v1/incidents/{incident_id}`

### DELETE /incidents/{incident_id}
Delete an incident.

**Endpoint:** `DELETE /api/v1/incidents/{incident_id}`

### POST /incidents/{incident_id}/assign
Assign incident to analyst.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/assign`

### POST /incidents/{incident_id}/escalate
Escalate incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/escalate`

### POST /incidents/{incident_id}/close
Close incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/close`

### POST /incidents/{incident_id}/reopen
Reopen a closed incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/reopen`

### POST /incidents/{incident_id}/merge
Merge incidents.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/merge`

### GET /incidents/{incident_id}/timeline
Get incident timeline.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/timeline`

### POST /incidents/{incident_id}/timeline/entry
Add timeline entry.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/timeline/entry`

### POST /incidents/{incident_id}/notes
Add a note to incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/notes`

### GET /incidents/{incident_id}/notes
Get incident notes.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/notes`

### POST /incidents/{incident_id}/evidence
Add evidence to incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/evidence`

### GET /incidents/{incident_id}/evidence
Get incident evidence.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/evidence`

### GET /incidents/{incident_id}/evidence/{evidence_id}
Get evidence item.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/evidence/{evidence_id}`

### DELETE /incidents/{incident_id}/evidence/{evidence_id}
Remove evidence.

**Endpoint:** `DELETE /api/v1/incidents/{incident_id}/evidence/{evidence_id}`

### GET /incidents/{incident_id}/mitre
Get MITRE ATT&CK mapping.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/mitre`

### POST /incidents/{incident_id}/mitre
Add MITRE ATT&CK mapping.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/mitre`

### GET /incidents/{incident_id}/attack-graph
Get attack graph visualization.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/attack-graph`

### GET /incidents/{incident_id}/playbooks
Get applicable playbooks.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/playbooks`

### POST /incidents/{incident_id}/playbooks/{playbook_id}/run
Run a playbook on incident.

**Endpoint:** `POST /api/v1/incidents/{incident_id}/playbooks/{playbook_id}/run`

### GET /incidents/{incident_id}/report
Generate incident report.

**Endpoint:** `GET /api/v1/incidents/{incident_id}/report`

### GET /incidents/stats
Incident statistics.

**Endpoint:** `GET /api/v1/incidents/stats`

### GET /incidents/cases
List cases (structured incident views).

**Endpoint:** `GET /api/v1/incidents/cases`

---

## 8. SOAR (26 endpoints)

### POST /soar/playbooks
Create a playbook.

**Endpoint:** `POST /api/v1/soar/playbooks`

### GET /soar/playbooks
List playbooks.

**Endpoint:** `GET /api/v1/soar/playbooks`

### GET /soar/playbooks/{playbook_id}
Get playbook details.

**Endpoint:** `GET /api/v1/soar/playbooks/{playbook_id}`

### PATCH /soar/playbooks/{playbook_id}
Update a playbook.

**Endpoint:** `PATCH /api/v1/soar/playbooks/{playbook_id}`

### DELETE /soar/playbooks/{playbook_id}
Delete a playbook.

**Endpoint:** `DELETE /api/v1/soar/playbooks/{playbook_id}`

### POST /soar/playbooks/{playbook_id}/execute
Execute a playbook.

**Endpoint:** `POST /api/v1/soar/playbooks/{playbook_id}/execute`

### GET /soar/playbooks/{playbook_id}/runs
Get playbook execution history.

**Endpoint:** `GET /api/v1/soar/playbooks/{playbook_id}/runs`

### GET /soar/playbooks/{playbook_id}/runs/{run_id}
Get playbook run details.

**Endpoint:** `GET /api/v1/soar/playbooks/{playbook_id}/runs/{run_id}`

### POST /soar/playbooks/{playbook_id}/runs/{run_id}/approve
Approve a manual action step.

**Endpoint:** `POST /api/v1/soar/playbooks/{playbook_id}/runs/{run_id}/approve`

### POST /soar/automations
Create automation rule.

**Endpoint:** `POST /api/v1/soar/automations`

### GET /soar/automations
List automation rules.

**Endpoint:** `GET /api/v1/soar/automations`

### PATCH /soar/automations/{automation_id}
Update automation.

**Endpoint:** `PATCH /api/v1/soar/automations/{automation_id}`

### DELETE /soar/automations/{automation_id}
Delete automation.

**Endpoint:** `DELETE /api/v1/soar/automations/{automation_id}`

### POST /soar/automations/{automation_id}/enable
Enable automation.

**Endpoint:** `POST /api/v1/soar/automations/{automation_id}/enable`

### POST /soar/automations/{automation_id}/disable
Disable automation.

**Endpoint:** `POST /api/v1/soar/automations/{automation_id}/disable`

### POST /soar/actions
Create an action template.

**Endpoint:** `POST /api/v1/soar/actions`

### GET /soar/actions
List action templates.

**Endpoint:** `GET /api/v1/soar/actions`

### GET /soar/connectors
List connectors.

**Endpoint:** `GET /api/v1/soar/connectors`

### POST /soar/connectors
Create connector.

**Endpoint:** `POST /api/v1/soar/connectors`

### PATCH /soar/connectors/{connector_id}
Update connector.

**Endpoint:** `PATCH /api/v1/soar/connectors/{connector_id}`

### DELETE /soar/connectors/{connector_id}
Delete connector.

**Endpoint:** `DELETE /api/v1/soar/connectors/{connector_id}`

### POST /soar/connectors/{connector_id}/test
Test connector connection.

**Endpoint:** `POST /api/v1/soar/connectors/{connector_id}/test`

### GET /soar/workflows
List workflows.

**Endpoint:** `GET /api/v1/soar/workflows`

### POST /soar/workflows
Create workflow.

**Endpoint:** `POST /api/v1/soar/workflows`

### PATCH /soar/workflows/{workflow_id}
Update workflow.

**Endpoint:** `PATCH /api/v1/soar/workflows/{workflow_id}`

### DELETE /soar/workflows/{workflow_id}
Delete workflow.

**Endpoint:** `DELETE /api/v1/soar/workflows/{workflow_id}`

---

## 9. Threat Intelligence (30 endpoints)

### GET /threat-intel/feeds
List threat intel feeds.

**Endpoint:** `GET /api/v1/threat-intel/feeds`

### POST /threat-intel/feeds
Create a threat intel feed.

**Endpoint:** `POST /api/v1/threat-intel/feeds`

### PATCH /threat-intel/feeds/{feed_id}
Update a feed.

**Endpoint:** `PATCH /api/v1/threat-intel/feeds/{feed_id}`

### DELETE /threat-intel/feeds/{feed_id}
Delete a feed.

**Endpoint:** `DELETE /api/v1/threat-intel/feeds/{feed_id}`

### POST /threat-intel/feeds/{feed_id}/sync
Sync a feed.

**Endpoint:** `POST /api/v1/threat-intel/feeds/{feed_id}/sync`

### GET /threat-intel/feeds/{feed_id}/status
Get feed sync status.

**Endpoint:** `GET /api/v1/threat-intel/feeds/{feed_id}/status`

### GET /threat-intel/indicators
List indicators of compromise (IOCs).

**Endpoint:** `GET /api/v1/threat-intel/indicators`

### GET /threat-intel/indicators/{indicator_id}
Get IOC details.

**Endpoint:** `GET /api/v1/threat-intel/indicators/{indicator_id}`

### POST /threat-intel/indicators
Create an IOC manually.

**Endpoint:** `POST /api/v1/threat-intel/indicators`

### PATCH /threat-intel/indicators/{indicator_id}
Update an IOC.

**Endpoint:** `PATCH /api/v1/threat-intel/indicators/{indicator_id}`

### DELETE /threat-intel/indicators/{indicator_id}
Delete an IOC.

**Endpoint:** `DELETE /api/v1/threat-intel/indicators/{indicator_id}`

### POST /threat-intel/indicators/bulk
Bulk import IOCs.

**Endpoint:** `POST /api/v1/threat-intel/indicators/bulk`

### POST /threat-intel/indicators/enrich
Enrich IOCs with external data.

**Endpoint:** `POST /api/v1/threat-intel/indicators/enrich`

### GET /threat-intel/indicators/stats
IOC statistics.

**Endpoint:** `GET /api/v1/threat-intel/indicators/stats`

### GET /threat-intel/actors
List threat actors.

**Endpoint:** `GET /api/v1/threat-intel/actors`

### GET /threat-intel/actors/{actor_id}
Get actor details.

**Endpoint:** `GET /api/v1/threat-intel/actors/{actor_id}`

### GET /threat-intel/campaigns
List threat campaigns.

**Endpoint:** `GET /api/v1/threat-intel/campaigns`

### GET /threat-intel/campaigns/{campaign_id}
Get campaign details.

**Endpoint:** `GET /api/v1/threat-intel/campaigns/{campaign_id}`

### GET /threat-intel/ttps
List TTPs (Tactics, Techniques, Procedures).

**Endpoint:** `GET /api/v1/threat-intel/ttps`

### GET /threat-intel/ttps/{ttp_id}
Get TTP details.

**Endpoint:** `GET /api/v1/threat-intel/ttps/{ttp_id}`

### GET /threat-intel/mitre/enterprise
MITRE ATT&CK Enterprise matrix.

**Endpoint:** `GET /api/v1/threat-intel/mitre/enterprise`

### GET /threat-intel/mitre/techniques/{technique_id}
MITRE technique details.

**Endpoint:** `GET /api/v1/threat-intel/mitre/techniques/{technique_id}`

### GET /threat-intel/mitre/heatmap
MITRE ATT&CK heatmap.

**Endpoint:** `GET /api/v1/threat-intel/mitre/heatmap`

### POST /threat-intel/lookup/ip/{ip}
Lookup IP address.

**Endpoint:** `POST /api/v1/threat-intel/lookup/ip/{ip}`

### POST /threat-intel/lookup/domain/{domain}
Lookup domain.

**Endpoint:** `POST /api/v1/threat-intel/lookup/domain/{domain}`

### POST /threat-intel/lookup/hash/{hash_value}
Lookup file hash.

**Endpoint:** `POST /api/v1/threat-intel/lookup/hash/{hash_value}`

### POST /threat-intel/lookup/url/{url}
Lookup URL.

**Endpoint:** `POST /api/v1/threat-intel/lookup/url/{url}`

### GET /threat-intel/reports
List threat reports.

**Endpoint:** `GET /api/v1/threat-intel/reports`

### GET /threat-intel/reports/{report_id}
Get report details.

**Endpoint:** `GET /api/v1/threat-intel/reports/{report_id}`

### POST /threat-intel/reports/generate
Generate a threat report.

**Endpoint:** `POST /api/v1/threat-intel/reports/generate`

---

## 10. Vulnerabilities (30 endpoints)

### POST /vulnerabilities/scans
Create a vulnerability scan.

**Endpoint:** `POST /api/v1/vulnerabilities/scans`

### GET /vulnerabilities/scans
List vulnerability scans.

**Endpoint:** `GET /api/v1/vulnerabilities/scans`

### GET /vulnerabilities/scans/{scan_id}
Get scan details.

**Endpoint:** `GET /api/v1/vulnerabilities/scans/{scan_id}`

### POST /vulnerabilities/scans/{scan_id}/start
Start a scan.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/{scan_id}/start`

### POST /vulnerabilities/scans/{scan_id}/stop
Stop a scan.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/{scan_id}/stop`

### POST /vulnerabilities/scans/{scan_id}/pause
Pause a scan.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/{scan_id}/pause`

### POST /vulnerabilities/scans/{scan_id}/resume
Resume a scan.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/{scan_id}/resume`

### GET /vulnerabilities/scans/{scan_id}/results
Get scan results.

**Endpoint:** `GET /api/v1/vulnerabilities/scans/{scan_id}/results`

### GET /vulnerabilities/scans/{scan_id}/report
Get scan report.

**Endpoint:** `GET /api/v1/vulnerabilities/scans/{scan_id}/report`

### GET /vulnerabilities/vulnerabilities
List vulnerabilities (paginated).

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities`

### GET /vulnerabilities/vulnerabilities/stats
Vulnerability statistics.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/stats`

### GET /vulnerabilities/vulnerabilities/{vulnerability_id}
Get vulnerability details.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}`

### PATCH /vulnerabilities/vulnerabilities/{vulnerability_id}
Update vulnerability status.

**Endpoint:** `PATCH /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}`

### POST /vulnerabilities/vulnerabilities/bulk
Bulk update vulnerabilities.

**Endpoint:** `POST /api/v1/vulnerabilities/vulnerabilities/bulk`

### GET /vulnerabilities/vulnerabilities/{vulnerability_id}/affected-assets
Get affected assets.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}/affected-assets`

### GET /vulnerabilities/vulnerabilities/{vulnerability_id}/exploits
Get known exploits.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}/exploits`

### GET /vulnerabilities/vulnerabilities/{vulnerability_id}/mitre
MITRE mapping for vulnerability.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}/mitre`

### GET /vulnerabilities/vulnerabilities/{vulnerability_id}/remediation
Get remediation guidance.

**Endpoint:** `GET /api/v1/vulnerabilities/vulnerabilities/{vulnerability_id}/remediation`

### GET /vulnerabilities/cve/search
Search CVE database.

**Endpoint:** `GET /api/v1/vulnerabilities/cve/search`

### GET /vulnerabilities/cve/{cve_id}
Get CVE details.

**Endpoint:** `GET /api/v1/vulnerabilities/cve/{cve_id}`

### GET /vulnerabilities/scans/templates
List scan templates.

**Endpoint:** `GET /api/v1/vulnerabilities/scans/templates`

### POST /vulnerabilities/scans/templates
Create scan template.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/templates`

### PATCH /vulnerabilities/scans/templates/{template_id}
Update scan template.

**Endpoint:** `PATCH /api/v1/vulnerabilities/scans/templates/{template_id}`

### DELETE /vulnerabilities/scans/templates/{template_id}
Delete scan template.

**Endpoint:** `DELETE /api/v1/vulnerabilities/scans/templates/{template_id}`

### POST /vulnerabilities/scans/schedule
Create scan schedule.

**Endpoint:** `POST /api/v1/vulnerabilities/scans/schedule`

### GET /vulnerabilities/scans/schedules
List scan schedules.

**Endpoint:** `GET /api/v1/vulnerabilities/scans/schedules`

### DELETE /vulnerabilities/scans/schedules/{schedule_id}
Delete scan schedule.

**Endpoint:** `DELETE /api/v1/vulnerabilities/scans/schedules/{schedule_id}`

### GET /vulnerabilities/misconfigurations
List misconfigurations.

**Endpoint:** `GET /api/v1/vulnerabilities/misconfigurations`

### GET /vulnerabilities/misconfigurations/{misconfig_id}
Get misconfiguration details.

**Endpoint:** `GET /api/v1/vulnerabilities/misconfigurations/{misconfig_id}`

### POST /vulnerabilities/misconfigurations/{misconfig_id}/remediate
Remediate misconfiguration.

**Endpoint:** `POST /api/v1/vulnerabilities/misconfigurations/{misconfig_id}/remediate`

---

## 11. Compliance (22 endpoints)

### GET /compliance/frameworks
List compliance frameworks.

**Endpoint:** `GET /api/v1/compliance/frameworks`

### GET /compliance/frameworks/{framework_id}
Get framework details.

**Endpoint:** `GET /api/v1/compliance/frameworks/{framework_id}`

### POST /compliance/frameworks/{framework_id}/assess
Run compliance assessment.

**Endpoint:** `POST /api/v1/compliance/frameworks/{framework_id}/assess`

### GET /compliance/frameworks/{framework_id}/controls
List framework controls.

**Endpoint:** `GET /api/v1/compliance/frameworks/{framework_id}/controls`

### GET /compliance/frameworks/{framework_id}/controls/{control_id}
Get control details.

**Endpoint:** `GET /api/v1/compliance/frameworks/{framework_id}/controls/{control_id}`

### PATCH /compliance/frameworks/{framework_id}/controls/{control_id}
Update control status.

**Endpoint:** `PATCH /api/v1/compliance/frameworks/{framework_id}/controls/{control_id}`

### POST /compliance/frameworks/{framework_id}/controls/{control_id}/evidence
Upload compliance evidence.

**Endpoint:** `POST /api/v1/compliance/frameworks/{framework_id}/controls/{control_id}/evidence`

### GET /compliance/assessments
List assessments.

**Endpoint:** `GET /api/v1/compliance/assessments`

### GET /compliance/assessments/{assessment_id}
Get assessment details.

**Endpoint:** `GET /api/v1/compliance/assessments/{assessment_id}`

### GET /compliance/assessments/{assessment_id}/report
Get assessment report.

**Endpoint:** `GET /api/v1/compliance/assessments/{assessment_id}/report`

### GET /compliance/gap-analysis
Run gap analysis.

**Endpoint:** `GET /api/v1/compliance/gap-analysis`

### GET /compliance/scorecard
Get compliance scorecard.

**Endpoint:** `GET /api/v1/compliance/scorecard`

### GET /compliance/audit-trail
Get audit trail.

**Endpoint:** `GET /api/v1/compliance/audit-trail`

### GET /compliance/policies
List compliance policies.

**Endpoint:** `GET /api/v1/compliance/policies`

### POST /compliance/policies
Create a policy.

**Endpoint:** `POST /api/v1/compliance/policies`

### GET /compliance/policies/{policy_id}
Get policy details.

**Endpoint:** `GET /api/v1/compliance/policies/{policy_id}`

### PATCH /compliance/policies/{policy_id}
Update policy.

**Endpoint:** `PATCH /api/v1/compliance/policies/{policy_id}`

### DELETE /compliance/policies/{policy_id}
Delete policy.

**Endpoint:** `DELETE /api/v1/compliance/policies/{policy_id}`

### GET /compliance/evidence
List evidence items.

**Endpoint:** `GET /api/v1/compliance/evidence`

### POST /compliance/evidence
Upload evidence.

**Endpoint:** `POST /api/v1/compliance/evidence`

### PATCH /compliance/evidence/{evidence_id}
Update evidence.

**Endpoint:** `PATCH /api/v1/compliance/evidence/{evidence_id}`

### GET /compliance/evidence/{evidence_id}/download
Download evidence.

**Endpoint:** `GET /api/v1/compliance/evidence/{evidence_id}/download`

---

## 12. Dashboards (22 endpoints)

### GET /dashboards/executive
Executive dashboard overview.

**Endpoint:** `GET /api/v1/dashboards/executive`

### GET /dashboards/operations
SOC operations dashboard.

**Endpoint:** `GET /api/v1/dashboards/operations`

### GET /dashboards/threat
Threat landscape dashboard.

**Endpoint:** `GET /api/v1/dashboards/threat`

### GET /dashboards/compliance
Compliance posture dashboard.

**Endpoint:** `GET /api/v1/dashboards/compliance`

### GET /dashboards/assets
Asset overview dashboard.

**Endpoint:** `GET /api/v1/dashboards/assets`

### GET /dashboards/vulnerabilities
Vulnerability dashboard.

**Endpoint:** `GET /api/v1/dashboards/vulnerabilities`

### GET /dashboards/risk
Risk matrix dashboard.

**Endpoint:** `GET /api/v1/dashboards/risk`

### GET /dashboards/metrics
Performance metrics dashboard.

**Endpoint:** `GET /api/v1/dashboards/metrics`

### GET /dashboards/incidents
Incident trends dashboard.

**Endpoint:** `GET /api/v1/dashboards/incidents`

### GET /dashboards/alerts
Alert trends dashboard.

**Endpoint:** `GET /api/v1/dashboards/alerts`

### GET /dashboards/soar
SOAR analytics dashboard.

**Endpoint:** `GET /api/v1/dashboards/soar`

### GET /dashboards/custom
List custom dashboards.

**Endpoint:** `GET /api/v1/dashboards/custom`

### POST /dashboards/custom
Create custom dashboard.

**Endpoint:** `POST /api/v1/dashboards/custom`

### GET /dashboards/custom/{dashboard_id}
Get custom dashboard.

**Endpoint:** `GET /api/v1/dashboards/custom/{dashboard_id}`

### PATCH /dashboards/custom/{dashboard_id}
Update custom dashboard.

**Endpoint:** `PATCH /api/v1/dashboards/custom/{dashboard_id}`

### DELETE /dashboards/custom/{dashboard_id}
Delete custom dashboard.

**Endpoint:** `DELETE /api/v1/dashboards/custom/{dashboard_id}`

### GET /dashboards/widgets
List available widgets.

**Endpoint:** `GET /api/v1/dashboards/widgets`

### POST /dashboards/custom/{dashboard_id}/widgets
Add widget to dashboard.

**Endpoint:** `POST /api/v1/dashboards/custom/{dashboard_id}/widgets`

### GET /dashboards/realtime
Real-time events dashboard.

**Endpoint:** `GET /api/v1/dashboards/realtime`

### GET /dashboards/sla
SLA tracking dashboard.

**Endpoint:** `GET /api/v1/dashboards/sla`

### GET /dashboards/usage
Usage and billing dashboard.

**Endpoint:** `GET /api/v1/dashboards/usage`

### GET /dashboards/integrations
Integration health dashboard.

**Endpoint:** `GET /api/v1/dashboards/integrations`

---

## 13. Reports (23 endpoints)

### POST /reports/generate
Generate a report.

**Endpoint:** `POST /api/v1/reports/generate`

### GET /reports
List reports (paginated).

**Endpoint:** `GET /api/v1/reports`

### GET /reports/{report_id}
Get report details.

**Endpoint:** `GET /api/v1/reports/{report_id}`

### DELETE /reports/{report_id}
Delete a report.

**Endpoint:** `DELETE /api/v1/reports/{report_id}`

### GET /reports/{report_id}/download
Download report file.

**Endpoint:** `GET /api/v1/reports/{report_id}/download`

### GET /reports/templates
List report templates.

**Endpoint:** `GET /api/v1/reports/templates`

### POST /reports/templates
Create report template.

**Endpoint:** `POST /api/v1/reports/templates`

### GET /reports/templates/{template_id}
Get template details.

**Endpoint:** `GET /api/v1/reports/templates/{template_id}`

### PATCH /reports/templates/{template_id}
Update template.

**Endpoint:** `PATCH /api/v1/reports/templates/{template_id}`

### DELETE /reports/templates/{template_id}
Delete template.

**Endpoint:** `DELETE /api/v1/reports/templates/{template_id}`

### GET /reports/scheduled
List scheduled reports.

**Endpoint:** `GET /api/v1/reports/scheduled`

### POST /reports/scheduled
Create scheduled report.

**Endpoint:** `POST /api/v1/reports/scheduled`

### PATCH /reports/scheduled/{schedule_id}
Update schedule.

**Endpoint:** `PATCH /api/v1/reports/scheduled/{schedule_id}`

### DELETE /reports/scheduled/{schedule_id}
Delete schedule.

**Endpoint:** `DELETE /api/v1/reports/scheduled/{schedule_id}`

### GET /reports/types
List supported report types.

**Endpoint:** `GET /api/v1/reports/types`

### GET /reports/export/{report_id}
Export report in various formats.

**Endpoint:** `GET /api/v1/reports/export/{report_id}`

### POST /reports/export/bulk
Bulk export reports.

**Endpoint:** `POST /api/v1/reports/export/bulk`

### GET /reports/dashboards/{report_id}
Generate dashboard from report.

**Endpoint:** `GET /api/v1/reports/dashboards/{report_id}`

### GET /reports/compliance
Compliance-specific reports.

**Endpoint:** `GET /api/v1/reports/compliance`

### GET /reports/incidents
Incident-specific reports.

**Endpoint:** `GET /api/v1/reports/incidents`

### GET /reports/vulnerabilities
Vulnerability-specific reports.

**Endpoint:** `GET /api/v1/reports/vulnerabilities`

### GET /reports/audit
Audit trail reports.

**Endpoint:** `GET /api/v1/reports/audit`

### GET /reports/stats
Report usage statistics.

**Endpoint:** `GET /api/v1/reports/stats`

---

## 14. Notifications (22 endpoints)

### GET /notifications
Get notification preferences.

**Endpoint:** `GET /api/v1/notifications`

### PATCH /notifications
Update notification preferences.

**Endpoint:** `PATCH /api/v1/notifications`

### GET /notifications/channels
List notification channels.

**Endpoint:** `GET /api/v1/notifications/channels`

### POST /notifications/channels
Create a notification channel.

**Endpoint:** `POST /api/v1/notifications/channels`

### PATCH /notifications/channels/{channel_id}
Update a channel.

**Endpoint:** `PATCH /api/v1/notifications/channels/{channel_id}`

### DELETE /notifications/channels/{channel_id}
Delete a channel.

**Endpoint:** `DELETE /api/v1/notifications/channels/{channel_id}`

### POST /notifications/channels/{channel_id}/test
Test a notification channel.

**Endpoint:** `POST /api/v1/notifications/channels/{channel_id}/test`

### GET /notifications/history
Notification history (paginated).

**Endpoint:** `GET /api/v1/notifications/history`

### GET /notifications/templates
List notification templates.

**Endpoint:** `GET /api/v1/notifications/templates`

### POST /notifications/templates
Create notification template.

**Endpoint:** `POST /api/v1/notifications/templates`

### PATCH /notifications/templates/{template_id}
Update template.

**Endpoint:** `PATCH /api/v1/notifications/templates/{template_id}`

### DELETE /notifications/templates/{template_id}
Delete template.

**Endpoint:** `DELETE /api/v1/notifications/templates/{template_id}`

### POST /notifications/send
Send a notification.

**Endpoint:** `POST /api/v1/notifications/send`

### GET /notifications/integrations
List integrations.

**Endpoint:** `GET /api/v1/notifications/integrations`

### POST /notifications/integrations/email
Configure email integration.

**Endpoint:** `POST /api/v1/notifications/integrations/email`

### POST /notifications/integrations/sms
Configure SMS integration.

**Endpoint:** `POST /api/v1/notifications/integrations/sms`

### POST /notifications/integrations/slack
Configure Slack integration.

**Endpoint:** `POST /api/v1/notifications/integrations/slack`

### POST /notifications/integrations/teams
Configure Microsoft Teams integration.

**Endpoint:** `POST /api/v1/notifications/integrations/teams`

### POST /notifications/integrations/discord
Configure Discord integration.

**Endpoint:** `POST /api/v1/notifications/integrations/discord`

### POST /notifications/integrations/telegram
Configure Telegram integration.

**Endpoint:** `POST /api/v1/notifications/integrations/telegram`

### POST /notifications/integrations/webhook
Configure webhook integration.

**Endpoint:** `POST /api/v1/notifications/integrations/webhook`

### POST /notifications/integrations/mobile-push
Configure mobile push integration.

**Endpoint:** `POST /api/v1/notifications/integrations/mobile-push`

---

## 15. Search (18 endpoints)

### GET /search/global
Global search across all resources.

**Endpoint:** `GET /api/v1/search/global`

### GET /search/natural
Natural language search.

**Endpoint:** `GET /api/v1/search/natural`

### GET /search/assets
Search assets.

**Endpoint:** `GET /api/v1/search/assets`

### GET /search/incidents
Search incidents.

**Endpoint:** `GET /api/v1/search/incidents`

### GET /search/alerts
Search alerts.

**Endpoint:** `GET /api/v1/search/alerts`

### GET /search/iocs
Search IOCs.

**Endpoint:** `GET /api/v1/search/iocs`

### GET /search/users
Search users.

**Endpoint:** `GET /api/v1/search/users`

### GET /search/processes
Search processes.

**Endpoint:** `GET /api/v1/search/processes`

### GET /search/logs
Search audit logs.

**Endpoint:** `GET /api/v1/search/logs`

### GET /search/vulnerabilities
Search vulnerabilities.

**Endpoint:** `GET /api/v1/search/vulnerabilities`

### GET /search/playbooks
Search playbooks.

**Endpoint:** `GET /api/v1/search/playbooks`

### GET /search/reports
Search reports.

**Endpoint:** `GET /api/v1/search/reports`

### GET /search/evidence
Search evidence.

**Endpoint:** `GET /api/v1/search/evidence`

### GET /search/suggestions
Search autocomplete suggestions.

**Endpoint:** `GET /api/v1/search/suggestions`

### GET /search/saved
List saved searches.

**Endpoint:** `GET /api/v1/search/saved`

### POST /search/saved
Save a search query.

**Endpoint:** `POST /api/v1/search/saved`

### DELETE /search/saved/{search_id}
Delete a saved search.

**Endpoint:** `DELETE /api/v1/search/saved/{search_id}`

### GET /search/index-stats
Search index statistics.

**Endpoint:** `GET /api/v1/search/index-stats`

---

## 16. Audit (18 endpoints)

### GET /audit/logs
List audit logs (paginated, filterable).

**Endpoint:** `GET /api/v1/audit/logs`

### GET /audit/logs/{log_id}
Get audit log details.

**Endpoint:** `GET /api/v1/audit/logs/{log_id}`

### GET /audit/stats
Audit log statistics.

**Endpoint:** `GET /api/v1/audit/stats`

### GET /audit/users/{user_id}
Audit logs for a specific user.

**Endpoint:** `GET /api/v1/audit/users/{user_id}`

### GET /audit/resources/{resource_type}/{resource_id}
Audit logs for a specific resource.

**Endpoint:** `GET /api/v1/audit/resources/{resource_type}/{resource_id}`

### GET /audit/export
Export audit logs.

**Endpoint:** `GET /api/v1/audit/export`

### POST /audit/export/bulk
Bulk export audit logs.

**Endpoint:** `POST /api/v1/audit/export/bulk`

### GET /audit/exports/{export_id}
Check export status.

**Endpoint:** `GET /api/v1/audit/exports/{export_id}`

### GET /audit/exports/{export_id}/download
Download audit export.

**Endpoint:** `GET /api/v1/audit/exports/{export_id}/download`

### GET /audit/retention
Get retention configuration.

**Endpoint:** `GET /api/v1/audit/retention`

### PATCH /audit/retention
Update retention configuration.

**Endpoint:** `PATCH /api/v1/audit/retention`

### POST /audit/purge
Purge old audit logs.

**Endpoint:** `POST /api/v1/audit/purge`

### GET /audit/sessions
List active sessions.

**Endpoint:** `GET /api/v1/audit/sessions`

### POST /audit/sessions/{session_id}/revoke
Revoke a session.

**Endpoint:** `POST /api/v1/audit/sessions/{session_id}/revoke`

### GET /audit/api-usage
API usage statistics.

**Endpoint:** `GET /api/v1/audit/api-usage`

### GET /audit/summary/daily
Daily audit summary.

**Endpoint:** `GET /api/v1/audit/summary/daily`

### GET /audit/summary/weekly
Weekly audit summary.

**Endpoint:** `GET /api/v1/audit/summary/weekly`

### GET /audit/anomalies
Detect audit anomalies.

**Endpoint:** `GET /api/v1/audit/anomalies`

---

## 17. AI (12 endpoints)

### GET /ai/health
AI service health check.

**Endpoint:** `GET /api/v1/ai/health`

### POST /ai/incidents/{incident_id}/summarize
AI-generated incident summary.

**Endpoint:** `POST /api/v1/ai/incidents/{incident_id}/summarize`

### POST /ai/incidents/{incident_id}/root-cause
AI root cause analysis.

**Endpoint:** `POST /api/v1/ai/incidents/{incident_id}/root-cause`

### POST /ai/alerts/{alert_id}/explain
AI alert explanation.

**Endpoint:** `POST /api/v1/ai/alerts/{alert_id}/explain`

### POST /ai/alerts/{alert_id}/classify
AI alert classification.

**Endpoint:** `POST /api/v1/ai/alerts/{alert_id}/classify`

### POST /ai/incidents/prioritize
AI incident prioritization.

**Endpoint:** `POST /api/v1/ai/incidents/prioritize`

### POST /ai/incidents/{incident_id}/playbook-recommend
AI playbook recommendation.

**Endpoint:** `POST /api/v1/ai/incidents/{incident_id}/playbook-recommend`

### POST /ai/vulnerabilities/{vuln_id}/fix-recommend
AI fix recommendation for vulnerabilities.

**Endpoint:** `POST /api/v1/ai/vulnerabilities/{vuln_id}/fix-recommend`

### POST /ai/correlate
AI event correlation.

**Endpoint:** `POST /api/v1/ai/correlate`

### POST /ai/ask
Ask AI (natural language query).

**Endpoint:** `POST /api/v1/ai/ask`

### POST /ai/incidents/{incident_id}/report
AI-generated incident report.

**Endpoint:** `POST /api/v1/ai/incidents/{incident_id}/report`

### GET /ai/insights
AI-generated security insights.

**Endpoint:** `GET /api/v1/ai/insights`

---

## 18. WebSocket (Real-Time Events)

| Method | Endpoint | Description |
|--------|----------|-------------|
| WS | `/ws/events` | Stream real-time security events |
| WS | `/ws/alerts` | Stream live alerts |
| WS | `/ws/incidents` | Stream incident updates |
| WS | `/ws/metrics` | Stream real-time metrics |

---

## Schema Definitions

### Security Schemes

| Scheme | Type | Header | Description |
|--------|------|--------|-------------|
| BearerAuth | HTTP Bearer | `Authorization: Bearer <token>` | JWT access token |
| TenantHeader | API Key | `X-Tenant-ID: <uuid>` | Tenant isolation |
| ApiKey | API Key | `X-API-Key: <key>` | Service-to-service auth |

### Common Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (1-indexed) |
| `per_page` | integer | Items per page (max 100) |
| `sort_by` | string | Field to sort by |
| `sort_order` | string | `asc` or `desc` |
| `q` | string | Search/filter query |
| `from_date` | ISO 8601 | Filter start date |
| `to_date` | ISO 8601 | Filter end date |
| `status` | string | Filter by status |
| `severity` | string | Filter by severity |

### Standard Response Envelope

```json
{
  "data": { ... },
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1500,
    "total_pages": 30,
    "has_next": true,
    "has_prev": false
  },
  "links": {
    "self": "/api/v1/resources?page=1",
    "next": "/api/v1/resources?page=2",
    "first": "/api/v1/resources?page=1",
    "last": "/api/v1/resources?page=30"
  }
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request — invalid input |
| 401 | Unauthorized — missing/invalid token |
| 403 | Forbidden — insufficient permissions |
| 404 | Not Found — resource doesn't exist |
| 409 | Conflict — duplicate resource |
| 422 | Validation Error — invalid fields |
| 429 | Rate Limited — too many requests |
| 500 | Internal Server Error |

## Rate Limits

| Endpoint Group | Limit |
|---------------|-------|
| Authentication endpoints | 10 requests/minute per IP |
| API endpoints | 100 requests/minute per IP |
| AI endpoints | 30 requests/minute per user |
| Search endpoints | 60 requests/minute per user |
| Bulk operations | 5 requests/minute per user |
| WebSocket connections | 5 concurrent per user |

## Role-Based Access

| Role | Permissions |
|------|-------------|
| `super_admin` | Full platform access, tenant management |
| `tenant_admin` | Tenant-level administration, user management |
| `soc_manager` | SOC operations, playbook creation, report generation |
| `soc_analyst` | Alert triage, incident investigation, asset management |
| `compliance_officer` | Compliance framework management, assessments |
| `read_only` | View-only access to dashboards and reports |

---

*Comprehensive API Reference — AEGISX Platform v1.0.0 — 330+ Endpoints across 18 Categories*
