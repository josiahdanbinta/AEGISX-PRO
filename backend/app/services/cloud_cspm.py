"""Cloud Security Posture Management - AWS, Azure, GCP resource discovery and compliance."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class CloudResource:
    resource_id: str
    resource_type: str
    name: str
    provider: str
    region: str
    status: str
    properties: Dict[str, Any] = field(default_factory=dict)
    compliance_issues: List[Dict[str, Any]] = field(default_factory=list)


class CloudCSPM:

    def get_aws_resources(self) -> List[CloudResource]:
        """Get AWS resource inventory (simulated until real AWS SDK integration)."""
        now = datetime.now(timezone.utc).isoformat()
        return [
            CloudResource("i-ec2-" + uuid.uuid4().hex[:8], "ec2_instance", "web-server-01", "aws", "us-east-1",
                          "running", {"instance_type": "t3.medium", "vpc_id": "vpc-default", "ami": "ami-ubuntu-22.04",
                                      "public_ip": f"54.{i}.{j}.{k}", "launch_time": now})
            for i, j, k in [(1,2,3), (4,5,6), (7,8,9)]
        ] + [
            CloudResource("s3-" + uuid.uuid4().hex[:6], "s3_bucket", f"data-bucket-{i}", "aws", "us-east-1", "active",
                          {"encryption": True, "versioning": True, "public_access_blocked": True, "size_gb": 150 * i})
            for i in range(1, 4)
        ] + [
            CloudResource("iam-" + uuid.uuid4().hex[:6], "iam_role", f"role-{name}", "aws", "global", "active",
                          {"attached_policies": 3, "last_used": now})
            for name in ["admin", "readonly", "lambda-exec"]
        ] + [
            CloudResource("rds-" + uuid.uuid4().hex[:6], "rds_instance", "primary-db", "aws", "us-east-1", "available",
                          {"engine": "postgresql", "version": "15.4", "storage_encrypted": True, "multi_az": True, "backup_retention_days": 30}),
            CloudResource("vpc-" + uuid.uuid4().hex[:6], "vpc", "main-vpc", "aws", "us-east-1", "active",
                          {"cidr": "10.0.0.0/16", "flow_logs_enabled": True, "subnets": 4}),
        ]

    def get_azure_resources(self) -> List[CloudResource]:
        """Get Azure resource inventory (simulated)."""
        now = datetime.now(timezone.utc).isoformat()
        return [
            CloudResource("vm-" + uuid.uuid4().hex[:6], "virtual_machine", f"vm-{name}", "azure", "eastus", "running",
                          {"size": "Standard_D2s_v3", "os": "Windows Server 2022", "disk_encryption": True})
            for name in ["app-01", "app-02"]
        ] + [
            CloudResource("st-" + uuid.uuid4().hex[:6], "storage_account", f"storage{i}", "azure", "eastus", "active",
                          {"tls_version": "1.2", "encryption": True, "access_tier": "Hot", "containers": ["logs", "data"]})
            for i in range(1, 3)
        ] + [
            CloudResource("sql-" + uuid.uuid4().hex[:6], "sql_database", "app-db", "azure", "eastus", "online",
                          {"tier": "GeneralPurpose", "encryption": True, "auditing_enabled": True, "firewall_rules": 5}),
            CloudResource("kv-" + uuid.uuid4().hex[:6], "key_vault", "secrets-vault", "azure", "eastus", "active",
                          {"soft_delete_enabled": True, "purge_protection": True, "secrets_count": 24}),
            CloudResource("nsg-" + uuid.uuid4().hex[:6], "network_security_group", "main-nsg", "azure", "eastus", "active",
                          {"rules_count": 12, "deny_all_inbound": False}),
            CloudResource("app-" + uuid.uuid4().hex[:6], "app_service", "web-api", "azure", "eastus", "running",
                          {"https_only": True, "tls_version": "1.2", "auth_enabled": True}),
        ]

    def get_gcp_resources(self) -> List[CloudResource]:
        """Get GCP resource inventory (simulated)."""
        return [
            CloudResource("gce-" + uuid.uuid4().hex[:6], "compute_instance", f"instance-{i}", "gcp", "us-central1",
                          "RUNNING", {"machine_type": "e2-medium", "disk_encryption": True, "shielded_vm": True})
            for i in range(1, 3)
        ] + [
            CloudResource("gcs-" + uuid.uuid4().hex[:6], "storage_bucket", f"bucket-{i}", "gcp", "us", "active",
                          {"encryption": True, "versioning": True, "public_access": False})
            for i in range(1, 4)
        ] + [
            CloudResource("sqlg-" + uuid.uuid4().hex[:6], "cloud_sql", "prod-db", "gcp", "us-central1", "RUNNABLE",
                          {"type": "CLOUD_SQL", "version": "POSTGRES_15", "encryption": True, "backup_enabled": True}),
            CloudResource("iamg-" + uuid.uuid4().hex[:6], "service_account", "app-sa", "gcp", "global", "active",
                          {"roles": ["roles/editor"], "keys_count": 0}),
            CloudResource("lbg-" + uuid.uuid4().hex[:6], "load_balancer", "frontend-lb", "gcp", "global", "active",
                          {"type": "EXTERNAL_HTTP", "ssl_policy": "MODERN", "backend_services": 2}),
        ]

    def get_aws_findings(self) -> List[Dict[str, Any]]:
        """Get simulated AWS Security Hub findings."""
        return [
            {"id": "finding-001", "severity": "HIGH", "title": "S3 bucket allows public read access",
             "resource": "arn:aws:s3:::data-bucket-2", "standard": "CIS AWS Foundations",
             "remediation": "Enable Block Public Access on S3 bucket"},
            {"id": "finding-002", "severity": "MEDIUM", "title": "Security group allows unrestricted inbound SSH",
             "resource": "arn:aws:ec2:us-east-1:sg-abc123", "standard": "PCI DSS",
             "remediation": "Restrict SSH access to known IP ranges"},
            {"id": "finding-003", "severity": "CRITICAL", "title": "IAM user with console access has no MFA",
             "resource": "arn:aws:iam::user/developer1", "standard": "CIS AWS Foundations",
             "remediation": "Enable MFA for all IAM users with console access"},
            {"id": "finding-004", "severity": "LOW", "title": "CloudTrail not enabled in all regions",
             "resource": "arn:aws:cloudtrail:us-east-1:trail/main", "standard": "SOC 2",
             "remediation": "Enable multi-region CloudTrail"},
            {"id": "finding-005", "severity": "HIGH", "title": "RDS instance not encrypted at rest",
             "resource": "arn:aws:rds:us-east-1:db/dev-db", "standard": "NIST 800-53",
             "remediation": "Enable storage encryption on RDS instance"},
        ]

    def run_compliance_scan(self, provider: str, framework: str = "cis") -> List[Dict[str, Any]]:
        """Run compliance scan against cloud provider (simulated)."""
        if provider == "aws":
            return self.get_aws_findings()
        return [
            {"id": f"cs-{provider}-001", "severity": "MEDIUM", "title": f"Default network rules too permissive",
             "resource": f"{provider}://network/default-nsg", "standard": framework.upper(),
             "remediation": f"Review {provider} network security group rules"},
            {"id": f"cs-{provider}-002", "severity": "HIGH", "title": "Admin accounts without MFA",
             "resource": f"{provider}://iam/accounts", "standard": framework.upper(),
             "remediation": "Enable MFA for all privileged accounts"},
        ]

    def sync_all(self) -> Dict[str, Any]:
        """Sync all cloud providers and return consolidated resource inventory."""
        aws = self.get_aws_resources()
        azure = self.get_azure_resources()
        gcp = self.get_gcp_resources()

        return {
            "aws": {"total": len(aws), "resources": [self._resource_to_dict(r) for r in aws]},
            "azure": {"total": len(azure), "resources": [self._resource_to_dict(r) for r in azure]},
            "gcp": {"total": len(gcp), "resources": [self._resource_to_dict(r) for r in gcp]},
            "total": len(aws) + len(azure) + len(gcp),
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

    def _resource_to_dict(self, r: CloudResource) -> Dict[str, Any]:
        return {
            "resource_id": r.resource_id, "resource_type": r.resource_type,
            "name": r.name, "provider": r.provider, "region": r.region,
            "status": r.status, "properties": r.properties,
            "compliance_issues": r.compliance_issues,
        }
