"""
AEGISX - Operational Domain Models
Asset, Incident, Alert, DetectionRule, Playbook, Vulnerability,
ThreatIndicator, Report, Notification, Compliance, ScanResult
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.base import TenantMixin, TimestampMixin


# ═════════════════════════════════════════════════════════════════
# ASSET
# ═════════════════════════════════════════════════════════════════

class AssetGroup(TenantMixin, TimestampMixin, Base):
    __tablename__ = "asset_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parent_group_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("asset_groups.id"), nullable=True)

    parent_group: Mapped[Optional["AssetGroup"]] = relationship("AssetGroup", back_populates="child_groups", remote_side="AssetGroup.id")
    child_groups: Mapped[list["AssetGroup"]] = relationship("AssetGroup", back_populates="parent_group")
    assets: Mapped[list["Asset"]] = relationship("Asset", back_populates="group")


class Asset(TenantMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    type: Mapped[str] = mapped_column(String(50), default="endpoint", nullable=False)
    os: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    group_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("asset_groups.id"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    hardware_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    software_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    network_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    cloud_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    meta_data: Mapped[Optional[dict]] = mapped_column("metadata_", JSON, nullable=True)

    group: Mapped[Optional["AssetGroup"]] = relationship("AssetGroup", back_populates="assets")
    incidents: Mapped[list["IncidentAsset"]] = relationship("IncidentAsset", back_populates="asset")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="source_asset")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship("Vulnerability", back_populates="affected_asset")


class Agent(TenantMixin, TimestampMixin, Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    version: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    platform: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="offline", nullable=False)
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    capabilities: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)

    asset: Mapped[Optional["Asset"]] = relationship("Asset", foreign_keys=[asset_id])


# ═════════════════════════════════════════════════════════════════
# INCIDENT & ALERT
# ═════════════════════════════════════════════════════════════════

class Incident(TenantMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="new", nullable=False)
    assignee_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assignee_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    mitre_tactics: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    mitre_techniques: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    source_alert_ids: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    merged_into_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    assignee: Mapped[Optional["app.models.user.User"]] = relationship("User", foreign_keys=[assignee_id])
    assets: Mapped[list["IncidentAsset"]] = relationship("IncidentAsset", back_populates="incident", cascade="all, delete-orphan")
    timeline_entries: Mapped[list["IncidentTimeline"]] = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    notes: Mapped[list["IncidentNote"]] = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
    evidence_items: Mapped[list["IncidentEvidence"]] = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    playbook_executions: Mapped[list["PlaybookExecution"]] = relationship("PlaybookExecution", back_populates="incident")


class IncidentAsset(Base):
    __tablename__ = "incident_assets"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="assets")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="incidents")


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline_entries")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    note_type: Mapped[str] = mapped_column(String(50), default="analyst_note", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="notes")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    file_type: Mapped[str] = mapped_column(String(50), nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    chain_of_custody: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence_items")


class Alert(TenantMixin, Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="new", nullable=False)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id"), nullable=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    indicator_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    indicator_value: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    ueba_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    raw_event: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    promoted_to_incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)

    rule: Mapped[Optional["DetectionRule"]] = relationship("DetectionRule", back_populates="alerts", foreign_keys=[rule_id])
    source_asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="alerts", foreign_keys=[source_asset_id])


# ═════════════════════════════════════════════════════════════════
# DETECTION RULES
# ═════════════════════════════════════════════════════════════════

class DetectionRule(TenantMixin, TimestampMixin, Base):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)  # sigma, yara, suricata, ioc, behavioral, custom
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="disabled", nullable=False)
    rule_content: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    query: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_tactics: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    mitre_techniques: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    risk_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    false_positive_rate: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="rule", foreign_keys="Alert.rule_id")


class IOCRule(TenantMixin, TimestampMixin, Base):
    __tablename__ = "ioc_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip, domain, url, hash, email
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="high", nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    valid_from: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# ═════════════════════════════════════════════════════════════════
# SOAR - PLAYBOOKS
# ═════════════════════════════════════════════════════════════════

class Playbook(TenantMixin, TimestampMixin, Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), default="manual", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="draft", nullable=False)
    steps: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    conditions: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    execution_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    success_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    executions: Mapped[list["PlaybookExecution"]] = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(TenantMixin, Base):
    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("playbooks.id"), nullable=False)
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    trigger: Mapped[str] = mapped_column(String(50), default="manual", nullable=False)
    triggered_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    steps_results: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    current_step: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    playbook: Mapped["Playbook"] = relationship("Playbook", back_populates="executions")
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="playbook_executions")


class IntegrationConfig(TenantMixin, TimestampMixin, Base):
    __tablename__ = "integration_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    integration_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    test_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)


# ═════════════════════════════════════════════════════════════════
# VULNERABILITY MANAGEMENT
# ═════════════════════════════════════════════════════════════════

class VulnerabilityScan(TenantMixin, TimestampMixin, Base):
    __tablename__ = "vulnerability_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="asset", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    template_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    target_assets: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class Vulnerability(TenantMixin, TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    affected_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    affected_software: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    affected_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_references: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerability_scans.id"), nullable=True)
    assignee_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)

    affected_asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="vulnerabilities", foreign_keys=[affected_asset_id])


class ScanSchedule(TenantMixin, TimestampMixin, Base):
    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_template_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    target_assets: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanTemplate(TenantMixin, TimestampMixin, Base):
    __tablename__ = "scan_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_type: Mapped[str] = mapped_column(String(50), default="full", nullable=False)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    compliance_framework: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


# ═════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═════════════════════════════════════════════════════════════════

class ThreatFeed(TenantMixin, TimestampMixin, Base):
    __tablename__ = "threat_feeds"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # misp, opencti, taxii, custom
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    api_key_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_interval: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ThreatIndicator(TenantMixin, Base):
    __tablename__ = "threat_indicators"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # ip, domain, url, hash, email
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    tlp: Mapped[str] = mapped_column(String(20), default="amber", nullable=False)
    mitre_techniques: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)


# ═════════════════════════════════════════════════════════════════
# COMPLIANCE & REPORTING
# ═════════════════════════════════════════════════════════════════

class ComplianceAssessment(TenantMixin, TimestampMixin, Base):
    __tablename__ = "compliance_assessments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    framework: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="in_progress", nullable=False)
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    passed_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_controls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    controls_data: Mapped[Optional[list]] = mapped_column(JSON, default=[])
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Report(TenantMixin, Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(20), default="pdf", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    file_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ReportSchedule(TenantMixin, TimestampMixin, Base):
    __tablename__ = "report_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    format: Mapped[str] = mapped_column(String(20), default="pdf", nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    recipients: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportTemplate(TenantMixin, TimestampMixin, Base):
    __tablename__ = "report_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    template_content: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


# ═════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═════════════════════════════════════════════════════════════════

class NotificationChannel(TenantMixin, TimestampMixin, Base):
    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(50), nullable=False)  # email, sms, slack, teams, discord, telegram, webhook
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_tested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationHistory(TenantMixin, Base):
    __tablename__ = "notification_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    channel_type: Mapped[str] = mapped_column(String(50), nullable=False)
    recipient: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="sent", nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    template_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    triggered_by: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)


class NotificationTemplate(TenantMixin, TimestampMixin, Base):
    __tablename__ = "notification_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), default="system", nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    variables: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=[])
    channels: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=["email"])
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class NotificationPreference(TenantMixin, Base):
    __tablename__ = "notification_preferences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, unique=True)
    enabled_channels: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=["email"])
    alert_severity_filter: Mapped[str] = mapped_column(String(20), default="high", nullable=False)
    incident_updates: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    report_ready: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    daily_digest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    quiet_hours_start: Mapped[Optional[str]] = mapped_column(String(5), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)


class AgentCommand(Base):
    """Commands queued for agent execution (kill process, isolate, scan, etc)."""
    __tablename__ = "agent_commands"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True)
    command: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now(), nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
