import pytest
import uuid
from datetime import datetime, timezone
from app.models import (
    Tenant, User, Role, Department, AuditLog, ApiKey,
    RefreshToken, PasswordResetToken, BlacklistedToken,
    Asset, AssetGroup, Agent,
    Incident, IncidentTimeline, IncidentNote, IncidentEvidence, Alert,
    DetectionRule, IOCRule,
    Playbook, PlaybookExecution, IntegrationConfig,
    VulnerabilityScan, Vulnerability, ScanSchedule, ScanTemplate,
    ThreatFeed, ThreatIndicator,
    ComplianceAssessment,
    Report, ReportSchedule, ReportTemplate,
    NotificationChannel, NotificationHistory, NotificationPreference,
)


class TestTenantModel:
    def test_create_tenant(self):
        tenant = Tenant(
            id=uuid.uuid4(),
            name="test-tenant",
            display_name="Test Tenant",
            subscription_tier="pro",
            quota_assets=500,
            domain="test.AEGIS.com",
            contact_email="admin@test.com",
        )
        assert tenant.name == "test-tenant"
        assert tenant.display_name == "Test Tenant"
        assert tenant.subscription_tier == "pro"
        assert tenant.quota_assets == 500
        assert tenant.domain == "test.AEGIS.com"
        assert tenant.contact_email == "admin@test.com"

    def test_tenant_defaults(self):
        tenant = Tenant(name="default-tenant")
        assert tenant.subscription_tier == "free"
        assert tenant.status == "active"
        assert tenant.quota_assets == 1000
        assert tenant.quota_users == 50
        assert tenant.quota_storage_gb == 10

    def test_tenant_to_dict(self):
        tid = uuid.uuid4()
        tenant = Tenant(
            id=tid,
            name="dict-tenant",
            display_name="Dict Tenant",
            subscription_tier="enterprise",
            quota_assets=10000,
            quota_users=500,
            quota_storage_gb=100,
        )
        d = {c.key: getattr(tenant, c.key) for c in tenant.__table__.columns}
        assert d["name"] == "dict-tenant"
        assert d["id"] == tid
        assert d["subscription_tier"] == "enterprise"
        assert d["quota_assets"] == 10000

    def test_tenant_status_values(self):
        for status in ["active", "suspended", "trial", "expired"]:
            tenant = Tenant(name=f"tenant-{status}", status=status)
            assert tenant.status == status


class TestUserModel:
    def test_create_user(self):
        user = User(
            tenant_id=uuid.uuid4(),
            username="jdoe",
            email="jdoe@AEGIS.com",
            hashed_password="hashed_pw_123",
            full_name="John Doe",
            phone="+1234567890",
            title="Security Analyst",
        )
        assert user.username == "jdoe"
        assert user.email == "jdoe@AEGIS.com"
        assert user.hashed_password == "hashed_pw_123"
        assert user.full_name == "John Doe"
        assert user.phone == "+1234567890"
        assert user.title == "Security Analyst"

    def test_user_defaults(self):
        user = User(
            tenant_id=uuid.uuid4(),
            username="default-user",
            email="default@test.com",
            hashed_password="pw",
        )
        assert user.status == "active"
        assert user.failed_login_attempts == 0
        assert user.mfa_enabled is False
        assert user.must_change_password is False

    def test_user_unique_constraint_annotation(self):
        assert hasattr(User, "__table_args__")
        constraint = User.__table_args__
        assert constraint is not None

    def test_user_roles_list(self):
        user = User(
            tenant_id=uuid.uuid4(),
            username="role-user",
            email="role@test.com",
            hashed_password="pw",
            roles=[{"name": "soc_analyst_l1"}, {"name": "threat_hunter"}],
        )
        assert len(user.roles) == 2
        assert user.roles[0]["name"] == "soc_analyst_l1"
        assert user.roles[1]["name"] == "threat_hunter"

    def test_user_optional_fields_none(self):
        user = User(
            tenant_id=uuid.uuid4(),
            username="minimal-user",
            email="minimal@test.com",
            hashed_password="pw",
        )
        assert user.department_id is None
        assert user.locked_until is None
        assert user.last_login_at is None
        assert user.mfa_secret is None


class TestRoleModel:
    def test_create_role(self):
        role = Role(
            tenant_id=uuid.uuid4(),
            name="soc_analyst_l1",
            display_name="SOC Analyst L1",
            description="Level 1 SOC Analyst with basic triage permissions",
        )
        assert role.name == "soc_analyst_l1"
        assert role.display_name == "SOC Analyst L1"
        assert "triage" in role.description

    def test_role_defaults(self):
        role = Role(tenant_id=uuid.uuid4(), name="custom-role")
        assert role.is_system is False

    def test_role_permissions(self):
        permissions = ["read:alerts", "read:incidents", "create:incident_notes"]
        role = Role(
            tenant_id=uuid.uuid4(),
            name="analyst",
            permissions=permissions,
        )
        assert role.permissions == permissions
        assert "read:alerts" in role.permissions

    def test_system_role(self):
        role = Role(
            tenant_id=uuid.uuid4(),
            name="super_admin",
            display_name="Super Admin",
            is_system=True,
        )
        assert role.is_system is True
        assert role.name == "super_admin"


class TestDepartmentModel:
    def test_create_department(self):
        dept = Department(
            tenant_id=uuid.uuid4(),
            name="SOC",
            description="Security Operations Center",
        )
        assert dept.name == "SOC"
        assert dept.description == "Security Operations Center"

    def test_department_hierarchy(self):
        parent_id = uuid.uuid4()
        parent = Department(tenant_id=uuid.uuid4(), name="IT", id=parent_id)
        child = Department(
            tenant_id=uuid.uuid4(),
            name="Security",
            parent_department_id=parent_id,
        )
        assert parent.name == "IT"
        assert child.name == "Security"
        assert child.parent_department_id == parent_id

    def test_department_manager(self):
        manager_id = uuid.uuid4()
        dept = Department(
            tenant_id=uuid.uuid4(),
            name="Engineering",
            manager_id=manager_id,
        )
        assert dept.manager_id == manager_id


class TestAuditLogModel:
    def test_create_audit_log(self):
        log = AuditLog(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            action="user.login",
            resource_type="user",
            resource_id=uuid.uuid4(),
            details={"ip": "192.168.1.1", "method": "password"},
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            status="success",
            severity="info",
        )
        assert log.action == "user.login"
        assert log.resource_type == "user"
        assert log.status == "success"
        assert log.severity == "info"
        assert log.details["ip"] == "192.168.1.1"
        assert log.ip_address == "192.168.1.1"

    def test_audit_log_defaults(self):
        log = AuditLog(
            tenant_id=uuid.uuid4(),
            action="entity.create",
            resource_type="asset",
        )
        assert log.status == "success"
        assert log.severity == "info"

    def test_audit_log_severity_levels(self):
        for severity in ["info", "warning", "error", "critical"]:
            log = AuditLog(
                tenant_id=uuid.uuid4(),
                action="test.action",
                resource_type="test",
                severity=severity,
            )
            assert log.severity == severity


class TestApiKeyModel:
    def test_create_api_key(self):
        key = ApiKey(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            name="Integration Key",
            key_hash="sha256hashvalue",
            prefix="AEGIS_abc123",
            scopes=["read:assets", "read:incidents"],
        )
        assert key.name == "Integration Key"
        assert key.key_hash == "sha256hashvalue"
        assert key.prefix == "AEGIS_abc123"
        assert len(key.scopes) == 2
        assert "read:assets" in key.scopes

    def test_api_key_defaults(self):
        key = ApiKey(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            name="Default Key",
            key_hash="hash",
            prefix="pref",
        )
        assert key.is_active is True

    def test_api_key_expiration(self):
        expiry = datetime(2026, 12, 31, tzinfo=timezone.utc)
        key = ApiKey(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            name="Expiring Key",
            key_hash="hash",
            prefix="pref",
            expires_at=expiry,
            is_active=False,
        )
        assert key.expires_at == expiry
        assert key.is_active is False


class TestTokenModels:
    def test_refresh_token(self):
        now = datetime.now(timezone.utc)
        token = RefreshToken(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            token_jti="jti-unique-value-123",
            token_hash="hashvalue",
            expires_at=now,
            is_revoked=False,
        )
        assert token.token_jti == "jti-unique-value-123"
        assert token.token_hash == "hashvalue"
        assert token.is_revoked is False

    def test_password_reset_token(self):
        now = datetime.now(timezone.utc)
        token = PasswordResetToken(
            user_id=uuid.uuid4(),
            token_hash="reset-hash-value",
            expires_at=now,
            is_used=False,
            requested_by=uuid.uuid4(),
        )
        assert token.token_hash == "reset-hash-value"
        assert token.is_used is False
        assert token.requested_by is not None

    def test_password_reset_token_defaults(self):
        token = PasswordResetToken(
            user_id=uuid.uuid4(),
            token_hash="phash",
            expires_at=datetime.now(timezone.utc),
        )
        assert token.is_used is False

    def test_blacklisted_token(self):
        now = datetime.now(timezone.utc)
        token = BlacklistedToken(
            token_jti="blocked-jti-value",
            expires_at=now,
        )
        assert token.token_jti == "blocked-jti-value"
        assert token.expires_at == now


class TestAssetModels:
    def test_create_asset_server(self):
        asset = Asset(
            tenant_id=uuid.uuid4(),
            name="web-server-01",
            hostname="ws01.prod.local",
            ip_address="10.0.1.10",
            type="server",
            os="linux",
            os_version="Ubuntu 22.04",
            status="online",
            risk_level="low",
            tags=["production", "web"],
        )
        assert asset.name == "web-server-01"
        assert asset.hostname == "ws01.prod.local"
        assert asset.type == "server"

    def test_create_asset_endpoint(self):
        asset = Asset(
            tenant_id=uuid.uuid4(),
            name="workstation-05",
            hostname="ws05.corp.local",
            ip_address="192.168.1.50",
            mac_address="AA:BB:CC:DD:EE:FF",
            type="endpoint",
            os="windows",
            os_version="Windows 11",
        )
        assert asset.type == "endpoint"
        assert asset.os == "windows"
        assert asset.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_create_asset_container(self):
        asset = Asset(
            tenant_id=uuid.uuid4(),
            name="k8s-node-pool-1",
            type="container",
            cloud_info={"provider": "aws", "region": "us-east-1"},
        )
        assert asset.type == "container"
        assert asset.cloud_info["provider"] == "aws"

    def test_create_asset_cloud(self):
        asset = Asset(
            tenant_id=uuid.uuid4(),
            name="aws-ec2-prod",
            type="cloud",
            cloud_info={"provider": "aws", "instance_id": "i-abc123"},
        )
        assert asset.type == "cloud"

    def test_create_asset_network(self):
        asset = Asset(
            tenant_id=uuid.uuid4(),
            name="core-switch-01",
            type="network",
            ip_address="10.0.0.1",
            network_info={"model": "Catalyst", "vendor": "Cisco"},
        )
        assert asset.type == "network"

    def test_asset_defaults(self):
        asset = Asset(tenant_id=uuid.uuid4(), name="default-asset")
        assert asset.type == "endpoint"
        assert asset.status == "unknown"
        assert asset.risk_level == "info"

    def test_asset_group(self):
        group = AssetGroup(
            tenant_id=uuid.uuid4(),
            name="Production Servers",
            description="All production server assets",
        )
        assert group.name == "Production Servers"
        assert group.description == "All production server assets"

    def test_asset_group_hierarchy(self):
        parent_id = uuid.uuid4()
        child = AssetGroup(
            tenant_id=uuid.uuid4(),
            name="Web Tier",
            parent_group_id=parent_id,
        )
        assert child.parent_group_id == parent_id

    def test_agent(self):
        agent = Agent(
            tenant_id=uuid.uuid4(),
            name="agent-win-01",
            agent_key="agent-key-unique-value",
            version="2.1.0",
            platform="windows",
            hostname="win-host-01",
            ip_address="10.0.1.50",
            status="online",
            capabilities=["file_integrity", "process_monitoring"],
        )
        assert agent.name == "agent-win-01"
        assert agent.agent_key == "agent-key-unique-value"
        assert agent.version == "2.1.0"
        assert agent.platform == "windows"
        assert "file_integrity" in agent.capabilities

    def test_agent_defaults(self):
        agent = Agent(
            tenant_id=uuid.uuid4(),
            name="default-agent",
            agent_key="some-key",
        )
        assert agent.status == "offline"


class TestIncidentModels:
    def test_create_incident(self):
        incident = Incident(
            tenant_id=uuid.uuid4(),
            title="Suspicious Login Activity",
            description="Multiple failed login attempts detected",
            severity="high",
            status="investigating",
            assignee_id=uuid.uuid4(),
            assignee_name="Jane Smith",
            mitre_tactics=["TA0006"],
            mitre_techniques=["T1110.001"],
            risk_score=7.5,
        )
        assert incident.title == "Suspicious Login Activity"
        assert incident.severity == "high"
        assert incident.status == "investigating"
        assert incident.assignee_name == "Jane Smith"
        assert "TA0006" in incident.mitre_tactics
        assert incident.risk_score == 7.5

    def test_incident_defaults(self):
        incident = Incident(tenant_id=uuid.uuid4(), title="Default Incident")
        assert incident.severity == "medium"
        assert incident.status == "new"

    def test_incident_timeline(self):
        entry = IncidentTimeline(
            incident_id=uuid.uuid4(),
            event_type="status_change",
            title="Status changed to investigating",
            description="Incident escalated by SOC manager",
            user_id=uuid.uuid4(),
            data={"previous_status": "new", "new_status": "investigating"},
        )
        assert entry.event_type == "status_change"
        assert entry.title == "Status changed to investigating"
        assert entry.data["new_status"] == "investigating"

    def test_incident_note(self):
        note = IncidentNote(
            incident_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            content="Found evidence of credential stuffing attack",
            note_type="investigation",
        )
        assert note.content == "Found evidence of credential stuffing attack"
        assert note.note_type == "investigation"

    def test_incident_note_default_type(self):
        note = IncidentNote(
            incident_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            content="General note",
        )
        assert note.note_type == "analyst_note"

    def test_incident_evidence(self):
        evidence = IncidentEvidence(
            incident_id=uuid.uuid4(),
            filename="screenshot.png",
            file_path="/evidence/inc-123/screenshot.png",
            file_size=102400,
            file_type="image/png",
            file_hash="sha256:abc123",
            uploaded_by=uuid.uuid4(),
            description="Screenshot of suspicious process",
            chain_of_custody=[{"action": "collected", "timestamp": "2025-01-01T00:00:00Z"}],
        )
        assert evidence.filename == "screenshot.png"
        assert evidence.file_path == "/evidence/inc-123/screenshot.png"
        assert evidence.file_size == 102400
        assert evidence.file_type == "image/png"
        assert evidence.file_hash == "sha256:abc123"

    def test_alert(self):
        alert = Alert(
            tenant_id=uuid.uuid4(),
            title="Brute Force Attack Detected",
            description="Multiple failed SSH login attempts",
            severity="critical",
            status="new",
            rule_id=uuid.uuid4(),
            rule_name="SSH Brute Force Detection",
            source_ip="203.0.113.50",
            destination_ip="10.0.1.10",
            confidence=0.95,
        )
        assert alert.title == "Brute Force Attack Detected"
        assert alert.severity == "critical"
        assert alert.confidence == 0.95
        assert alert.source_ip == "203.0.113.50"

    def test_alert_defaults(self):
        alert = Alert(tenant_id=uuid.uuid4(), title="Test Alert")
        assert alert.severity == "medium"
        assert alert.status == "new"
        assert alert.confidence == 0.5


class TestDetectionModels:
    def test_create_detection_rule_sigma(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="Suspicious PowerShell Execution",
            description="Detects suspicious PowerShell commands",
            rule_type="sigma",
            severity="high",
            status="enabled",
            rule_content={"logsource": {"product": "windows"}, "detection": {"selection": {}}},
            mitre_tactics=["TA0002"],
            mitre_techniques=["T1059.001"],
            tags=["powershell", "execution"],
            risk_score=85,
            version=2,
        )
        assert rule.rule_type == "sigma"
        assert rule.severity == "high"
        assert rule.status == "enabled"
        assert rule.risk_score == 85
        assert rule.version == 2

    def test_create_detection_rule_yara(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="Ransomware Detection",
            rule_type="yara",
            severity="critical",
            status="enabled",
            tags=["ransomware", "malware"],
            risk_score=95,
        )
        assert rule.rule_type == "yara"
        assert rule.severity == "critical"

    def test_create_detection_rule_suricata(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="C2 Communication",
            rule_type="suricata",
            severity="high",
            status="enabled",
            query="alert tcp any any -> any any (msg:\"C2 Beacon\"; flow:established; content:\"|16 03|\";)",
        )
        assert rule.rule_type == "suricata"
        assert "alert tcp" in rule.query

    def test_create_detection_rule_ioc(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="IOC-Based Detection",
            rule_type="ioc",
            severity="medium",
            status="enabled",
        )
        assert rule.rule_type == "ioc"

    def test_create_detection_rule_behavioral(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="Anomalous Process Creation",
            rule_type="behavioral",
            severity="medium",
            status="enabled",
            false_positive_rate=0.02,
        )
        assert rule.rule_type == "behavioral"
        assert rule.false_positive_rate == 0.02

    def test_detection_rule_defaults(self):
        rule = DetectionRule(
            tenant_id=uuid.uuid4(),
            name="Default Rule",
            rule_type="custom",
        )
        assert rule.severity == "medium"
        assert rule.status == "disabled"
        assert rule.risk_score == 50
        assert rule.version == 1
        assert rule.alert_count == 0

    def test_ioc_rule(self):
        now = datetime.now(timezone.utc)
        ioc = IOCRule(
            tenant_id=uuid.uuid4(),
            ioc_type="ip",
            value="203.0.113.100",
            description="Known malicious IP from threat intel feed",
            severity="high",
            source="AlienVault OTX",
            confidence=0.9,
            valid_from=now,
            tags=["c2", "malicious"],
        )
        assert ioc.ioc_type == "ip"
        assert ioc.value == "203.0.113.100"
        assert ioc.severity == "high"
        assert ioc.source == "AlienVault OTX"
        assert ioc.confidence == 0.9

    def test_ioc_rule_defaults(self):
        ioc = IOCRule(
            tenant_id=uuid.uuid4(),
            ioc_type="domain",
            value="evil-domain.com",
        )
        assert ioc.severity == "high"
        assert ioc.confidence == 1.0
        assert ioc.is_active is True


class TestSOARModels:
    def test_create_playbook(self):
        playbook = Playbook(
            tenant_id=uuid.uuid4(),
            name="Phishing Response",
            description="Automated phishing incident response workflow",
            trigger_type="alert",
            status="active",
            steps=[
                {"step": 1, "action": "quarantine_email", "description": "Quarantine suspicious email"},
                {"step": 2, "action": "block_sender", "description": "Block sender domain"},
                {"step": 3, "action": "notify_user", "description": "Notify affected user"},
            ],
            conditions=[{"field": "alert.severity", "operator": "gte", "value": "high"}],
            tags=["phishing", "email"],
            version=3,
        )
        assert playbook.name == "Phishing Response"
        assert playbook.trigger_type == "alert"
        assert playbook.status == "active"
        assert len(playbook.steps) == 3
        assert playbook.version == 3

    def test_playbook_defaults(self):
        playbook = Playbook(tenant_id=uuid.uuid4(), name="Default Playbook")
        assert playbook.trigger_type == "manual"
        assert playbook.status == "draft"
        assert playbook.version == 1
        assert playbook.execution_count == 0
        assert playbook.success_count == 0

    def test_playbook_execution(self):
        execution = PlaybookExecution(
            tenant_id=uuid.uuid4(),
            playbook_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            status="running",
            trigger="alert",
            triggered_by=uuid.uuid4(),
            current_step=2,
        )
        assert execution.status == "running"
        assert execution.trigger == "alert"
        assert execution.current_step == 2

    def test_playbook_execution_defaults(self):
        execution = PlaybookExecution(
            tenant_id=uuid.uuid4(),
            playbook_id=uuid.uuid4(),
        )
        assert execution.status == "pending"
        assert execution.trigger == "manual"

    def test_integration_config(self):
        config = IntegrationConfig(
            tenant_id=uuid.uuid4(),
            name="Slack Notification",
            integration_type="slack",
            config={"webhook_url": "https://hooks.slack.com/services/xxx", "channel": "#alerts"},
            is_active=True,
        )
        assert config.name == "Slack Notification"
        assert config.integration_type == "slack"
        assert config.config["channel"] == "#alerts"
        assert config.is_active is True

    def test_integration_config_defaults(self):
        config = IntegrationConfig(
            tenant_id=uuid.uuid4(),
            name="Default Integration",
            integration_type="webhook",
        )
        assert config.is_active is True


class TestVulnerabilityModels:
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            tenant_id=uuid.uuid4(),
            cve_id="CVE-2024-1234",
            title="Remote Code Execution in Apache Log4j",
            description="Critical RCE vulnerability in Log4j 2.x",
            severity="critical",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            affected_asset_id=uuid.uuid4(),
            affected_software="Apache Log4j",
            affected_version="2.14.1",
            fixed_version="2.17.0",
            status="open",
            exploit_available=True,
            remediation="Upgrade to Log4j 2.17.0 or later",
        )
        assert vuln.cve_id == "CVE-2024-1234"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 10.0
        assert vuln.affected_software == "Apache Log4j"
        assert vuln.exploit_available is True

    def test_vulnerability_defaults(self):
        vuln = Vulnerability(tenant_id=uuid.uuid4(), title="Default Vuln")
        assert vuln.severity == "medium"
        assert vuln.status == "open"
        assert vuln.exploit_available is False

    def test_vulnerability_scan(self):
        scan = VulnerabilityScan(
            tenant_id=uuid.uuid4(),
            name="Monthly Network Scan",
            scan_type="network",
            status="in_progress",
            target_assets=[{"id": "asset-123"}, {"id": "asset-456"}],
            findings_count=15,
            critical_count=2,
            high_count=5,
            medium_count=8,
        )
        assert scan.scan_type == "network"
        assert scan.status == "in_progress"
        assert scan.findings_count == 15
        assert scan.critical_count == 2

    def test_scan_schedule(self):
        schedule = ScanSchedule(
            tenant_id=uuid.uuid4(),
            name="Weekly Vulnerability Scan",
            scan_template_id=uuid.uuid4(),
            cron_expression="0 2 * * 0",
            is_active=True,
        )
        assert schedule.name == "Weekly Vulnerability Scan"
        assert schedule.cron_expression == "0 2 * * 0"
        assert schedule.is_active is True

    def test_scan_template(self):
        template = ScanTemplate(
            tenant_id=uuid.uuid4(),
            name="Full Audit Scan",
            description="Comprehensive vulnerability audit",
            scan_type="full",
            config={"plugins": ["all"], "timeout": 3600},
            compliance_framework="PCI DSS",
        )
        assert template.name == "Full Audit Scan"
        assert template.scan_type == "full"
        assert template.compliance_framework == "PCI DSS"


class TestThreatIntelModels:
    def test_create_threat_indicator_ip(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="ip",
            value="198.51.100.50",
            confidence=0.85,
            source="MISP Feed",
            tlp="amber",
        )
        assert indicator.type == "ip"
        assert indicator.value == "198.51.100.50"
        assert indicator.source == "MISP Feed"

    def test_create_threat_indicator_domain(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="domain",
            value="evil-c2.example.com",
            confidence=0.92,
            source="OpenCTI",
            description="C2 domain observed in ransomware campaign",
            threat_actor="APT29",
            tags=["c2", "ransomware"],
        )
        assert indicator.type == "domain"
        assert indicator.description == "C2 domain observed in ransomware campaign"
        assert indicator.threat_actor == "APT29"

    def test_create_threat_indicator_url(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="url",
            value="https://phish.example.com/login",
            confidence=0.75,
            source="PhishTank",
        )
        assert indicator.type == "url"

    def test_create_threat_indicator_hash(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="hash",
            value="d41d8cd98f00b204e9800998ecf8427e",
            confidence=0.99,
            source="VirusTotal",
        )
        assert indicator.type == "hash"

    def test_create_threat_indicator_email(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="email",
            value="phisher@evil.com",
            confidence=0.88,
            source="AbuseIPDB",
        )
        assert indicator.type == "email"

    def test_threat_indicator_defaults(self):
        indicator = ThreatIndicator(
            tenant_id=uuid.uuid4(),
            type="ip",
            value="10.0.0.1",
            source="test",
        )
        assert indicator.confidence == 0.5
        assert indicator.tlp == "amber"
        assert indicator.is_active is True

    def test_threat_feed(self):
        feed = ThreatFeed(
            tenant_id=uuid.uuid4(),
            name="MISP Community Feed",
            source_type="misp",
            url="https://misp.example.com",
            api_key_encrypted="encrypted_key_value",
            is_active=True,
            sync_interval=3600,
            indicator_count=5000,
        )
        assert feed.name == "MISP Community Feed"
        assert feed.source_type == "misp"
        assert feed.sync_interval == 3600
        assert feed.indicator_count == 5000

    def test_threat_feed_defaults(self):
        feed = ThreatFeed(
            tenant_id=uuid.uuid4(),
            name="Default Feed",
            source_type="custom",
        )
        assert feed.is_active is True
        assert feed.indicator_count == 0


class TestComplianceModels:
    def test_create_compliance_assessment(self):
        assessment = ComplianceAssessment(
            tenant_id=uuid.uuid4(),
            framework="ISO 27001:2022",
            name="Annual ISO 27001 Assessment",
            status="in_progress",
            score=78.5,
            total_controls=114,
            passed_controls=89,
            failed_controls=25,
            assigned_to=uuid.uuid4(),
        )
        assert assessment.framework == "ISO 27001:2022"
        assert assessment.name == "Annual ISO 27001 Assessment"
        assert assessment.status == "in_progress"
        assert assessment.score == 78.5
        assert assessment.total_controls == 114
        assert assessment.passed_controls == 89
        assert assessment.failed_controls == 25

    def test_compliance_defaults(self):
        assessment = ComplianceAssessment(
            tenant_id=uuid.uuid4(),
            framework="NIST CSF",
            name="NIST Assessment",
        )
        assert assessment.status == "in_progress"
        assert assessment.total_controls == 0
        assert assessment.passed_controls == 0
        assert assessment.failed_controls == 0

    def test_compliance_frameworks(self):
        for framework in ["PCI DSS", "SOC 2", "HIPAA", "GDPR", "NIST CSF", "ISO 27001:2022"]:
            assessment = ComplianceAssessment(
                tenant_id=uuid.uuid4(),
                framework=framework,
                name=f"{framework} Assessment",
            )
            assert assessment.framework == framework


class TestReportModels:
    def test_create_report(self):
        report = Report(
            tenant_id=uuid.uuid4(),
            name="Monthly Security Report",
            report_type="monthly",
            format="pdf",
            status="completed",
            parameters={"date_range": "2025-01"},
            file_url="/reports/monthly-security-2025-01.pdf",
            file_size=2048000,
            created_by=uuid.uuid4(),
        )
        assert report.name == "Monthly Security Report"
        assert report.report_type == "monthly"
        assert report.format == "pdf"
        assert report.status == "completed"
        assert report.file_size == 2048000

    def test_report_defaults(self):
        report = Report(
            tenant_id=uuid.uuid4(),
            name="Default Report",
            report_type="executive",
            created_by=uuid.uuid4(),
        )
        assert report.format == "pdf"
        assert report.status == "pending"

    def test_report_schedule(self):
        schedule = ReportSchedule(
            tenant_id=uuid.uuid4(),
            name="Weekly Executive Summary",
            report_type="executive",
            format="pdf",
            cron_expression="0 8 * * 1",
            recipients=["admin@company.com", "cso@company.com"],
            is_active=True,
        )
        assert schedule.name == "Weekly Executive Summary"
        assert schedule.report_type == "executive"
        assert schedule.cron_expression == "0 8 * * 1"
        assert "admin@company.com" in schedule.recipients

    def test_report_template(self):
        template = ReportTemplate(
            tenant_id=uuid.uuid4(),
            name="Executive Summary Template",
            report_type="executive",
            description="Standard executive summary with risk metrics",
            is_system=True,
        )
        assert template.name == "Executive Summary Template"
        assert template.report_type == "executive"
        assert template.is_system is True

    def test_report_template_defaults(self):
        template = ReportTemplate(
            tenant_id=uuid.uuid4(),
            name="Custom Template",
            report_type="incident",
        )
        assert template.is_system is False


class TestNotificationModels:
    def test_create_notification_channel(self):
        channel = NotificationChannel(
            tenant_id=uuid.uuid4(),
            name="Critical Alerts Slack",
            channel_type="slack",
            config={"webhook_url": "https://hooks.slack.com/services/xxx", "channel": "#critical-alerts"},
            is_active=True,
            is_default=True,
        )
        assert channel.name == "Critical Alerts Slack"
        assert channel.channel_type == "slack"
        assert channel.is_active is True
        assert channel.is_default is True

    def test_notification_preference(self):
        pref = NotificationPreference(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            enabled_channels=["email", "slack"],
            alert_severity_filter="medium",
            incident_updates=True,
            report_ready=True,
            daily_digest=False,
            quiet_hours_start="22:00",
            quiet_hours_end="07:00",
        )
        assert pref.user_id is not None
        assert "email" in pref.enabled_channels
        assert "slack" in pref.enabled_channels
        assert pref.alert_severity_filter == "medium"
        assert pref.incident_updates is True
        assert pref.daily_digest is False
        assert pref.quiet_hours_start == "22:00"

    def test_notification_preference_defaults(self):
        pref = NotificationPreference(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
        )
        assert pref.enabled_channels == ["email"]
        assert pref.alert_severity_filter == "high"
        assert pref.incident_updates is True
        assert pref.report_ready is True
        assert pref.daily_digest is False

    def test_notification_history(self):
        history = NotificationHistory(
            tenant_id=uuid.uuid4(),
            channel_type="email",
            recipient="analyst@AEGIS.com",
            subject="Critical Alert: Brute Force Attack",
            content="A brute force attack has been detected on host 10.0.1.10",
            status="sent",
            triggered_by="detection_engine",
        )
        assert history.channel_type == "email"
        assert history.recipient == "analyst@AEGIS.com"
        assert history.status == "sent"
        assert history.triggered_by == "detection_engine"

    def test_notification_history_defaults(self):
        history = NotificationHistory(
            tenant_id=uuid.uuid4(),
            channel_type="sms",
            recipient="+1234567890",
            subject="Alert",
        )
        assert history.status == "sent"

    def test_notification_channel_types(self):
        for ch_type in ["email", "sms", "slack", "teams", "discord", "telegram", "webhook"]:
            channel = NotificationChannel(
                tenant_id=uuid.uuid4(),
                name=f"{ch_type.capitalize()} Channel",
                channel_type=ch_type,
            )
            assert channel.channel_type == ch_type
