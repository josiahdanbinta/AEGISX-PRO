-- AEGISX PostgreSQL OLTP Indexes
-- Run after table creation. Adds indexes for common query patterns.

-- Users
CREATE INDEX IF NOT EXISTS idx_users_tenant_email ON users (tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_users_tenant_username ON users (tenant_id, username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users (tenant_id, last_login_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_users_created ON users (tenant_id, created_at DESC);

-- API Keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys (expires_at) WHERE is_active = TRUE;

-- Refresh Tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id, is_revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_jti ON refresh_tokens (token_jti);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens (expires_at) WHERE is_revoked = FALSE;

-- Blacklisted Tokens
CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens_jti ON blacklisted_tokens (token_jti);

-- Password Reset Tokens
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens (user_id, is_used);
CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens (expires_at) WHERE is_used = FALSE;

-- Assets
CREATE INDEX IF NOT EXISTS idx_assets_tenant_name ON assets (tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_hostname ON assets (tenant_id, hostname);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_ip ON assets (tenant_id, ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_type ON assets (tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets (tenant_id, criticality);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets (tenant_id, last_seen DESC NULLS LAST);

-- Agents
CREATE INDEX IF NOT EXISTS idx_agents_tenant_asset ON agents (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents (tenant_id, last_heartbeat DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents (tenant_id, hostname);
CREATE INDEX IF NOT EXISTS idx_agents_key ON agents (agent_key);

-- Incidents
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity ON incidents (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_assignee ON incidents (tenant_id, assignee_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_closed ON incidents (closed_at) WHERE closed_at IS NOT NULL;

-- Incident Notes
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_notes_user ON incident_notes (user_id);

-- Alerts
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_severity ON alerts (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_rule ON alerts (tenant_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_source_ip ON alerts (tenant_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_indicator ON alerts (tenant_id, indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_promoted ON alerts (promoted_to_incident_id) WHERE promoted_to_incident_id IS NOT NULL;

-- Detection Rules
CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant_type ON detection_rules (tenant_id, rule_type, status);
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre ON detection_rules (tenant_id) USING gin (mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_detection_rules_last_triggered ON detection_rules (tenant_id, last_triggered DESC NULLS LAST);

-- IOC Rules
CREATE INDEX IF NOT EXISTS idx_ioc_rules_tenant_type_val ON ioc_rules (tenant_id, ioc_type, value);
CREATE INDEX IF NOT EXISTS idx_ioc_rules_active ON ioc_rules (tenant_id, is_active) WHERE is_active = TRUE;

-- Playbooks
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_status ON playbooks (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_trigger ON playbooks (tenant_id, trigger_type);

-- Playbook Executions
CREATE INDEX IF NOT EXISTS idx_playbook_execs_playbook ON playbook_executions (playbook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_playbook_execs_status ON playbook_executions (tenant_id, status);

-- Integration Configs
CREATE INDEX IF NOT EXISTS idx_integration_tenant_type ON integration_configs (tenant_id, integration_type, is_active);

-- Threat Indicators
CREATE INDEX IF NOT EXISTS idx_threat_indicators_tenant_type ON threat_indicators (tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators (tenant_id, value);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_active ON threat_indicators (tenant_id, is_active) WHERE is_active = TRUE;

-- Threat Feeds
CREATE INDEX IF NOT EXISTS idx_threat_feeds_tenant_type ON threat_feeds (tenant_id, source_type, is_active);

-- Reports
CREATE INDEX IF NOT EXISTS idx_reports_tenant_type ON reports (tenant_id, report_type, status);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports (tenant_id, created_at DESC);

-- Roles
CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles (tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles (tenant_id, name);

-- Departments
CREATE INDEX IF NOT EXISTS idx_departments_tenant ON departments (tenant_id);
