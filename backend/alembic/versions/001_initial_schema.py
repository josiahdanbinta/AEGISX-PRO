"""initial schema

Revision ID: 001
Revises: 
Create Date: 2026-08-07

Creates all core AEGIS tables for multi-tenant cybersecurity platform.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('display_name', sa.String(255)),
        sa.Column('subscription_tier', sa.String(50)),
        sa.Column('status', sa.String(50), default='active'),
        sa.Column('quota_assets', sa.Integer, default=1000),
        sa.Column('quota_users', sa.Integer, default=100),
        sa.Column('quota_storage_gb', sa.Integer, default=500),
        sa.Column('config', sa.JSON),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_index('ix_tenants_name', 'tenants', ['name'])

    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('display_name', sa.String(255)),
        sa.Column('description', sa.String(500)),
        sa.Column('permissions', postgresql.ARRAY(sa.String)),
        sa.Column('is_system', sa.Boolean, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'departments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.String(500)),
        sa.Column('manager_id', postgresql.UUID(as_uuid=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('username', sa.String(150), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('phone', sa.String(20)),
        sa.Column('department_id', postgresql.UUID(as_uuid=True)),
        sa.Column('roles', sa.JSON),
        sa.Column('status', sa.String(50), default='active'),
        sa.Column('mfa_enabled', sa.Boolean, default=False),
        sa.Column('mfa_secret', sa.String(255)),
        sa.Column('mfa_backup_codes', sa.JSON),
        sa.Column('webauthn_credentials', sa.JSON),
        sa.Column('must_change_password', sa.Boolean, default=False),
        sa.Column('failed_login_attempts', sa.Integer, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True)),
        sa.Column('last_login_at', sa.DateTime(timezone=True)),
        sa.Column('last_password_change', sa.DateTime(timezone=True)),
        sa.Column('is_deleted', sa.Boolean, default=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_tenant_status', 'users', ['tenant_id', 'status'])

    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('prefix', sa.String(16), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('scopes', postgresql.ARRAY(sa.String)),
        sa.Column('last_used_at', sa.DateTime(timezone=True)),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('token_jti', sa.String(255), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False),
        sa.Column('is_revoked', sa.Boolean, default=False),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'password_reset_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_used', sa.Boolean, default=False),
        sa.Column('requested_by', postgresql.UUID(as_uuid=True)),
        sa.Column('approved_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'blacklisted_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('token_jti', sa.String(255), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('users.id'), nullable=True, index=True),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('resource_type', sa.String(150), nullable=False),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('details', sa.JSON, nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('status', sa.String(50), default='success'),
        sa.Column('severity', sa.String(50), default='info'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, index=True),
    )

    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])

    op.create_table(
        'detection_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('description', sa.String(2000)),
        sa.Column('rule_type', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(50)),
        sa.Column('status', sa.String(50), default='active'),
        sa.Column('rule_content', sa.JSON),
        sa.Column('mitre_tactics', postgresql.ARRAY(sa.String)),
        sa.Column('mitre_techniques', postgresql.ARRAY(sa.String)),
        sa.Column('risk_score', sa.Float),
        sa.Column('false_positive_rate', sa.Float),
        sa.Column('alert_count', sa.Integer, default=0),
        sa.Column('last_triggered', sa.DateTime(timezone=True)),
        sa.Column('version', sa.Integer, default=1),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'ioc_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('ioc_type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(1000), nullable=False),
        sa.Column('description', sa.String(2000)),
        sa.Column('severity', sa.String(50)),
        sa.Column('source', sa.String(255)),
        sa.Column('confidence', sa.Float),
        sa.Column('tags', postgresql.ARRAY(sa.String)),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'assets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('type', sa.String(50)),
        sa.Column('hostname', sa.String(255)),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('os', sa.String(100)),
        sa.Column('os_version', sa.String(100)),
        sa.Column('cpu', sa.String(100)),
        sa.Column('memory_gb', sa.Float),
        sa.Column('disk_gb', sa.Float),
        sa.Column('criticality', sa.String(50)),
        sa.Column('department', sa.String(255)),
        sa.Column('owner', sa.String(255)),
        sa.Column('tags', postgresql.ARRAY(sa.String)),
        sa.Column('metadata', sa.JSON),
        sa.Column('is_deleted', sa.Boolean, default=False),
        sa.Column('last_seen', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'agents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('asset_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('assets.id'), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('agent_key', sa.String(255)),
        sa.Column('version', sa.String(20)),
        sa.Column('platform', sa.String(50)),
        sa.Column('hostname', sa.String(255)),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('status', sa.String(50), default='offline'),
        sa.Column('last_heartbeat', sa.DateTime(timezone=True)),
        sa.Column('config', sa.JSON),
        sa.Column('capabilities', postgresql.ARRAY(sa.String)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('title', sa.String(1000), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.String(50)),
        sa.Column('status', sa.String(50)),
        sa.Column('assignee_id', postgresql.UUID(as_uuid=True)),
        sa.Column('assignee_name', sa.String(255)),
        sa.Column('source_alert_ids', sa.JSON),
        sa.Column('mitre_tactics', postgresql.ARRAY(sa.String)),
        sa.Column('mitre_techniques', postgresql.ARRAY(sa.String)),
        sa.Column('resolution', sa.Text),
        sa.Column('risk_score', sa.Float),
        sa.Column('sla_deadline', sa.DateTime(timezone=True)),
        sa.Column('closed_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'incident_notes',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('incidents.id'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('users.id'), nullable=False),
        sa.Column('content', sa.Text, nullable=False),
        sa.Column('note_type', sa.String(50)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('title', sa.String(1000), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.String(50)),
        sa.Column('status', sa.String(50)),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True)),
        sa.Column('rule_name', sa.String(500)),
        sa.Column('source_asset_id', postgresql.UUID(as_uuid=True)),
        sa.Column('source_ip', sa.String(45)),
        sa.Column('destination_ip', sa.String(45)),
        sa.Column('indicator_type', sa.String(50)),
        sa.Column('indicator_value', sa.String(1000)),
        sa.Column('confidence', sa.Float),
        sa.Column('raw_event', sa.JSON),
        sa.Column('promoted_to_incident_id', postgresql.UUID(as_uuid=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'playbooks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('trigger_type', sa.String(50)),
        sa.Column('status', sa.String(50)),
        sa.Column('steps', sa.JSON),
        sa.Column('conditions', sa.JSON),
        sa.Column('execution_count', sa.Integer, default=0),
        sa.Column('success_count', sa.Integer, default=0),
        sa.Column('last_executed_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'playbook_executions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('playbook_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('playbooks.id'), nullable=False),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True)),
        sa.Column('status', sa.String(50)),
        sa.Column('trigger_reason', sa.Text),
        sa.Column('current_step', sa.Integer),
        sa.Column('result', sa.JSON),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('error_message', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'integration_configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('integration_type', sa.String(50)),
        sa.Column('config', sa.JSON),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('last_tested_at', sa.DateTime(timezone=True)),
        sa.Column('test_status', sa.String(50)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'threat_indicators',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('value', sa.String(1000), nullable=False),
        sa.Column('confidence', sa.Float),
        sa.Column('source', sa.String(255)),
        sa.Column('description', sa.Text),
        sa.Column('tags', postgresql.ARRAY(sa.String)),
        sa.Column('tlp', sa.String(20)),
        sa.Column('first_seen', sa.DateTime(timezone=True)),
        sa.Column('last_seen', sa.DateTime(timezone=True)),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('raw_data', sa.JSON),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_index('ix_threat_indicators_type_value', 'threat_indicators', ['type', 'value'])

    op.create_table(
        'threat_feeds',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('source_type', sa.String(50)),
        sa.Column('url', sa.String(1000)),
        sa.Column('api_key_encrypted', sa.String(500)),
        sa.Column('config', sa.JSON),
        sa.Column('is_active', sa.Boolean, default=True),
        sa.Column('sync_interval', sa.Integer, default=3600),
        sa.Column('last_sync_at', sa.DateTime(timezone=True)),
        sa.Column('indicator_count', sa.Integer, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'notifications_template',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('channel_type', sa.String(50)),
        sa.Column('subject_template', sa.String(500)),
        sa.Column('body_template', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True)),
    )

    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('name', sa.String(500), nullable=False),
        sa.Column('report_type', sa.String(50)),
        sa.Column('format', sa.String(20)),
        sa.Column('status', sa.String(50)),
        sa.Column('parameters', sa.JSON),
        sa.Column('file_url', sa.String(1000)),
        sa.Column('created_by', postgresql.UUID(as_uuid=True)),
        sa.Column('created_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('error_message', sa.Text),
    )


def downgrade() -> None:
    op.drop_table('reports')
    op.drop_table('notifications_template')
    op.drop_table('threat_feeds')
    op.drop_table('threat_indicators')
    op.drop_table('integration_configs')
    op.drop_table('playbook_executions')
    op.drop_table('playbooks')
    op.drop_table('alerts')
    op.drop_table('incident_notes')
    op.drop_table('incidents')
    op.drop_table('agents')
    op.drop_table('assets')
    op.drop_table('ioc_rules')
    op.drop_table('detection_rules')
    op.drop_table('audit_logs')
    op.drop_table('blacklisted_tokens')
    op.drop_table('password_reset_tokens')
    op.drop_table('refresh_tokens')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('departments')
    op.drop_table('roles')
    op.drop_table('tenants')
