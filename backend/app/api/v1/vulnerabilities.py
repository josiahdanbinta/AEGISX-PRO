"""
AEGIS - Vulnerability Management API Router
Scans, vulnerabilities, CVEs, misconfigurations, scan templates, scheduled scans
"""
import math
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, update as sql_update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import VulnerabilityScan, Vulnerability, ScanSchedule, ScanTemplate, Asset, AuditLog
from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireComplianceOfficer,
    RequireSOCManager,
    RequireSOCAnalyst,
)

router = APIRouter()


async def _audit(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: Optional[uuid.UUID] = None,
    details: Optional[dict] = None,
    severity: str = "info",
):
    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        severity=severity,
    )
    db.add(entry)


def _paginated_response(items: list, total: int, page: int, page_size: int) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)),
    }


def _to_iso(dt) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat()


def _model_to_dict(instance, fields: List[str]) -> dict:
    result = {}
    for f in fields:
        val = getattr(instance, f, None)
        if isinstance(val, uuid.UUID):
            result[f] = str(val)
        elif isinstance(val, datetime):
            result[f] = _to_iso(val)
        else:
            result[f] = val
    return result


def _model_to_dict_ext(instance, overrides: Optional[dict] = None) -> dict:
    result = {}
    for col in instance.__table__.columns:
        val = getattr(instance, col.name)
        if isinstance(val, uuid.UUID):
            result[col.name] = str(val)
        elif isinstance(val, datetime):
            result[col.name] = _to_iso(val)
        else:
            result[col.name] = val
    if overrides:
        result.update(overrides)
    return result


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Enums
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ScanType(str, Enum):
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    WEB_APP = "web_app"
    API = "api"
    CONTAINER = "container"
    CLOUD = "cloud"
    DATABASE = "database"
    NETWORK = "network"
    OS = "os"
    COMPLIANCE = "compliance"
    CONFIGURATION = "configuration"

class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"

class VulnerabilitySeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    MITIGATED = "mitigated"

class MisconfigSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MisconfigStatus(str, Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    IN_PROGRESS = "in_progress"

class ScheduleFrequency(str, Enum):
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

class TemplateCategory(str, Enum):
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    CUSTOM = "custom"
    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"

class ScanReportFormat(str, Enum):
    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"

class CVESeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Request / Response Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class ScanTarget(BaseModel):
    target_type: str = Field(description="host, ip_range, cidr, url, container_image, repo")
    target_value: str
    port_range: Optional[str] = None
    credentials_id: Optional[str] = None


class ScanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scan_type: ScanType
    targets: List[ScanTarget] = Field(..., min_length=1)
    template_id: Optional[str] = None
    priority: int = Field(default=5, ge=1, le=10)
    max_duration_minutes: Optional[int] = Field(default=None, ge=1)
    tags: List[str] = Field(default_factory=list)


class VulnerabilityUpdate(BaseModel):
    status: Optional[VulnerabilityStatus] = None
    assignee_id: Optional[str] = None
    notes: Optional[str] = None
    sla_deadline: Optional[datetime] = None


class VulnerabilityBulkAction(BaseModel):
    id: str
    action: str = Field(description="resolve, in_progress, false_positive, wont_fix")


class VulnerabilityBulkUpdate(BaseModel):
    vulnerabilities: List[VulnerabilityBulkAction] = Field(..., min_length=1)


class VulnerabilityBulkUpdateResponse(BaseModel):
    total: int
    updated: int
    failed: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)


class ScanTemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: TemplateCategory
    scan_type: ScanType
    config: Dict[str, Any] = Field(default_factory=dict)
    compliance_framework: Optional[str] = None


class ScanTemplateUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    compliance_framework: Optional[str] = None


class ScanScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scan_template_id: Optional[str] = None
    target_assets: List[str] = Field(default_factory=list)
    cron_expression: str = Field(..., min_length=1, max_length=100)
    is_active: bool = True


class MisconfigRemediateRequest(BaseModel):
    misconfig_id: str


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Hardcoded CVE Database
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

CVE_DATABASE = {
    "CVE-2023-23397": {
        "cve_id": "CVE-2023-23397",
        "description": "Microsoft Outlook Elevation of Privilege Vulnerability. An attacker who successfully exploited this vulnerability could access a user's Net-NTLMv2 hash which could be used to authenticate as the user via NTLM Relay.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2023-03-14T00:00:00Z",
        "last_modified_date": "2024-11-15T00:00:00Z",
        "cwe_ids": ["CWE-294"],
        "affected_vendors": ["Microsoft"],
        "affected_products": ["Microsoft Outlook 2013", "Microsoft Outlook 2016", "Microsoft 365 Apps for Enterprise"],
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397", "source": "Microsoft", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-23397", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397", "type": "Security Update"}],
    },
    "CVE-2023-44487": {
        "cve_id": "CVE-2023-44487",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "base_score": 7.5,
            "exploitability_score": 3.9,
            "impact_score": 3.6,
            "base_severity": "HIGH",
        },
        "published_date": "2023-10-10T00:00:00Z",
        "last_modified_date": "2024-08-20T00:00:00Z",
        "cwe_ids": ["CWE-400"],
        "affected_vendors": ["Apache", "Nginx", "Microsoft", "Google", "Amazon", "Cloudflare"],
        "affected_products": ["HTTP/2 Protocol Implementations", "Apache httpd", "nginx", "IIS", "Envoy", "Netty"],
        "references": [
            {"url": "https://www.cve.org/CVERecord?id=CVE-2023-44487", "source": "CVE", "tags": ["Third Party Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Multiple", "url": "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/", "type": "Mitigation"}],
    },
    "CVE-2024-3094": {
        "cve_id": "CVE-2024-3094",
        "description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. The malicious code may allow an attacker to bypass sshd authentication and gain unauthorized access to affected systems.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 10.0,
            "exploitability_score": 3.9,
            "impact_score": 6.0,
            "base_severity": "CRITICAL",
        },
        "published_date": "2024-03-29T00:00:00Z",
        "last_modified_date": "2024-06-12T00:00:00Z",
        "cwe_ids": ["CWE-506"],
        "affected_vendors": ["Tukaani Project", "Red Hat", "Debian", "Kali"],
        "affected_products": ["xz Utils 5.6.0", "xz Utils 5.6.1", "liblzma"],
        "references": [
            {"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4", "source": "oss-security", "tags": ["Mailing List"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Tukaani Project", "url": "https://tukaani.org/xz/", "type": "Version Downgrade to 5.4.x"}],
    },
    "CVE-2024-4577": {
        "cve_id": "CVE-2024-4577",
        "description": "In PHP versions prior to 8.3.8, when using Apache and PHP-CGI on Windows, the system may use the 'Best Fit' behavior in code page conversion, allowing argument injection to PHP-CGI which can lead to remote code execution.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2024-06-06T00:00:00Z",
        "last_modified_date": "2024-08-14T00:00:00Z",
        "cwe_ids": ["CWE-78"],
        "affected_vendors": ["PHP Group"],
        "affected_products": ["PHP 8.0.x", "PHP 8.1.x", "PHP 8.2.x", "PHP 8.3.x (prior to 8.3.8)"],
        "references": [
            {"url": "https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html", "source": "Orange Tsai", "tags": ["Technical Analysis"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4577", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "PHP Group", "url": "https://www.php.net/downloads.php", "type": "Update to 8.3.8+"}],
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "base_score": 10.0,
            "exploitability_score": 3.9,
            "impact_score": 6.0,
            "base_severity": "CRITICAL",
        },
        "published_date": "2021-12-10T00:00:00Z",
        "last_modified_date": "2024-06-04T00:00:00Z",
        "cwe_ids": ["CWE-502", "CWE-20"],
        "affected_vendors": ["Apache", "Oracle", "VMware", "Cisco", "IBM", "Amazon", "Red Hat"],
        "affected_products": ["Apache Log4j 2.0-beta9 to 2.17.0", "Apache Log4j 2.0 to 2.14.1"],
        "references": [
            {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "Apache", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": True,
        "patches": [{"vendor": "Apache", "url": "https://logging.apache.org/log4j/2.x/download.html", "type": "Update to 2.17.1+"}],
    },
    "CVE-2023-34362": {
        "cve_id": "CVE-2023-34362",
        "description": "In Progress MOVEit Transfer before 2023.0.1, a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain unauthorized access to MOVEit Transfer's database.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2023-05-31T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-89"],
        "affected_vendors": ["Progress Software"],
        "affected_products": ["MOVEit Transfer before 2023.0.1", "MOVEit Cloud"],
        "references": [
            {"url": "https://www.progress.com/security/moveit-transfer-and-moveit-cloud-vulnerability", "source": "Progress", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-34362", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": True,
        "patches": [{"vendor": "Progress", "url": "https://community.progress.com/s/products/moveit/product-lifecycle", "type": "Security Patch"}],
    },
    "CVE-2024-24919": {
        "cve_id": "CVE-2024-24919",
        "description": "A security vulnerability in Check Point Quantum Security Gateways allows an attacker to access information on internet-connected Gateways configured with IPSec VPN, Remote Access VPN, or Mobile Access.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "base_score": 8.6,
            "exploitability_score": 3.9,
            "impact_score": 4.0,
            "base_severity": "HIGH",
        },
        "published_date": "2024-05-28T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-200"],
        "affected_vendors": ["Check Point"],
        "affected_products": ["Check Point Quantum Security Gateways with IPSec VPN", "Remote Access VPN", "Mobile Access"],
        "references": [
            {"url": "https://support.checkpoint.com/results/sk/sk182336", "source": "Check Point", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-24919", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Check Point", "url": "https://support.checkpoint.com/", "type": "Hotfix"}],
    },
    "CVE-2023-3519": {
        "cve_id": "CVE-2023-3519",
        "description": "Unauthenticated remote code execution vulnerability in NetScaler ADC and NetScaler Gateway formerly known as Citrix ADC and Citrix Gateway.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2023-07-18T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-94"],
        "affected_vendors": ["Citrix", "Cloud Software Group"],
        "affected_products": ["NetScaler ADC 13.1 before 13.1-49.13", "NetScaler Gateway 13.1 before 13.1-49.13"],
        "references": [
            {"url": "https://support.citrix.com/article/CTX561482", "source": "Citrix", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-3519", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Citrix", "url": "https://www.citrix.com/downloads/", "type": "Security Update"}],
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 10.0,
            "exploitability_score": 3.9,
            "impact_score": 6.0,
            "base_severity": "CRITICAL",
        },
        "published_date": "2024-04-12T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-77"],
        "affected_vendors": ["Palo Alto Networks"],
        "affected_products": ["PAN-OS 10.2.x before 10.2.9-h1", "PAN-OS 11.0.x before 11.0.4-h1", "PAN-OS 11.1.x before 11.1.2-h3"],
        "references": [
            {"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "source": "Palo Alto Networks", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Palo Alto Networks", "url": "https://live.paloaltonetworks.com/", "type": "Hotfix"}],
    },
    "CVE-2023-27997": {
        "cve_id": "CVE-2023-27997",
        "description": "A heap-based buffer overflow vulnerability in FortiOS SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2023-06-13T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-787"],
        "affected_vendors": ["Fortinet"],
        "affected_products": ["FortiOS 6.0.x", "FortiOS 6.2.x", "FortiOS 6.4.x", "FortiOS 7.0.x", "FortiOS 7.2.x"],
        "references": [
            {"url": "https://www.fortiguard.com/psirt/FG-IR-23-097", "source": "Fortinet", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-27997", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Fortinet", "url": "https://www.fortiguard.com/psirt", "type": "Security Update"}],
    },
    "CVE-2022-41040": {
        "cve_id": "CVE-2022-41040",
        "description": "Microsoft Exchange Server Elevation of Privilege Vulnerability. An authenticated attacker can attempt to trigger malicious code in the context of the server's account through a network call (ProxyNotShell).",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 8.8,
            "exploitability_score": 2.8,
            "impact_score": 5.9,
            "base_severity": "HIGH",
        },
        "published_date": "2022-09-30T00:00:00Z",
        "last_modified_date": "2024-06-04T00:00:00Z",
        "cwe_ids": ["CWE-918"],
        "affected_vendors": ["Microsoft"],
        "affected_products": ["Microsoft Exchange Server 2013", "Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"],
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040", "source": "Microsoft", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-41040", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/", "type": "Security Update"}],
    },
    "CVE-2024-38021": {
        "cve_id": "CVE-2024-38021",
        "description": "Microsoft Outlook Remote Code Execution Vulnerability. A remote, unauthenticated attacker could access and modify data or cause a denial-of-service condition by sending a specially crafted email.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            "base_score": 8.8,
            "exploitability_score": 2.8,
            "impact_score": 5.2,
            "base_severity": "HIGH",
        },
        "published_date": "2024-07-09T00:00:00Z",
        "last_modified_date": "2024-08-14T00:00:00Z",
        "cwe_ids": ["CWE-20"],
        "affected_vendors": ["Microsoft"],
        "affected_products": ["Microsoft Outlook 2016", "Microsoft 365 Apps for Enterprise"],
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021", "source": "Microsoft", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-38021", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": False,
        "in_cisa_kev": False,
        "ransomware_known": False,
        "patches": [{"vendor": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/", "type": "Security Update"}],
    },
    "CVE-2024-1709": {
        "cve_id": "CVE-2024-1709",
        "description": "ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel vulnerability, which may allow an attacker direct, confidential access to confidential information or critical systems.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 10.0,
            "exploitability_score": 3.9,
            "impact_score": 6.0,
            "base_severity": "CRITICAL",
        },
        "published_date": "2024-02-19T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-288"],
        "affected_vendors": ["ConnectWise"],
        "affected_products": ["ScreenConnect 23.9.7 and prior"],
        "references": [
            {"url": "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8", "source": "ConnectWise", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1709", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": True,
        "patches": [{"vendor": "ConnectWise", "url": "https://www.connectwise.com/", "type": "Update to 23.9.8+"}],
    },
    "CVE-2023-2868": {
        "cve_id": "CVE-2023-2868",
        "description": "A remote command injection vulnerability exists in the Barracuda Email Security Gateway (appliance form factor only) affecting versions 5.1.3.001-9.2.0.006. The vulnerability arises out of a failure to comprehensively sanitize the processing of .tar files.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2023-05-24T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-77"],
        "affected_vendors": ["Barracuda"],
        "affected_products": ["Barracuda Email Security Gateway 5.1.3.001 through 9.2.0.006"],
        "references": [
            {"url": "https://www.barracuda.com/company/legal/esg-vulnerability", "source": "Barracuda", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-2868", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Barracuda", "url": "https://www.barracuda.com/support", "type": "Security Patch"}],
    },
    "CVE-2024-0044": {
        "cve_id": "CVE-2024-0044",
        "description": "In Android 12, 13, and 14, there is a possible way to bypass a permissions policy due to a confusion in content provider access control. This could lead to local escalation of privilege with no additional execution privileges needed.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 7.8,
            "exploitability_score": 2.5,
            "impact_score": 5.9,
            "base_severity": "HIGH",
        },
        "published_date": "2024-03-11T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-863"],
        "affected_vendors": ["Google"],
        "affected_products": ["Android 12", "Android 13", "Android 14"],
        "references": [
            {"url": "https://source.android.com/docs/security/bulletin/2024-03-01", "source": "Android", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0044", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": False,
        "in_cisa_kev": False,
        "ransomware_known": False,
        "patches": [{"vendor": "Google", "url": "https://source.android.com/docs/security/bulletin/", "type": "Security Update"}],
    },
    "CVE-2023-36884": {
        "cve_id": "CVE-2023-36884",
        "description": "Office and Windows HTML Remote Code Execution Vulnerability. An attacker could create a specially crafted Microsoft Office document that enables them to perform remote code execution.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "base_score": 8.8,
            "exploitability_score": 2.8,
            "impact_score": 5.9,
            "base_severity": "HIGH",
        },
        "published_date": "2023-07-11T00:00:00Z",
        "last_modified_date": "2024-06-04T00:00:00Z",
        "cwe_ids": ["CWE-94"],
        "affected_vendors": ["Microsoft"],
        "affected_products": ["Microsoft Office 2019", "Microsoft 365 Apps for Enterprise", "Microsoft Windows"],
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884", "source": "Microsoft", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-36884", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/", "type": "Security Update"}],
    },
    "CVE-2024-20399": {
        "cve_id": "CVE-2024-20399",
        "description": "A vulnerability in the CLI of Cisco NX-OS Software could allow an authenticated, local attacker to execute arbitrary commands as root on the underlying operating system of an affected device.",
        "severity": "MEDIUM",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 6.7,
            "exploitability_score": 0.8,
            "impact_score": 5.9,
            "base_severity": "MEDIUM",
        },
        "published_date": "2024-07-17T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-78"],
        "affected_vendors": ["Cisco"],
        "affected_products": ["Cisco NX-OS Software"],
        "references": [
            {"url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmd-inject-0e6sHdlD", "source": "Cisco", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-20399", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": False,
        "in_cisa_kev": False,
        "ransomware_known": False,
        "patches": [{"vendor": "Cisco", "url": "https://www.cisco.com/c/en/us/support/index.html", "type": "Software Update"}],
    },
    "CVE-2021-34527": {
        "cve_id": "CVE-2021-34527",
        "description": "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare). A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations.",
        "severity": "CRITICAL",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 8.8,
            "exploitability_score": 2.8,
            "impact_score": 5.9,
            "base_severity": "HIGH",
        },
        "published_date": "2021-07-01T00:00:00Z",
        "last_modified_date": "2024-06-04T00:00:00Z",
        "cwe_ids": ["CWE-269"],
        "affected_vendors": ["Microsoft"],
        "affected_products": ["Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows 10", "Windows 11"],
        "references": [
            {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527", "source": "Microsoft", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": True,
        "patches": [{"vendor": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/", "type": "Security Update"}],
    },
    "CVE-2024-6387": {
        "cve_id": "CVE-2024-6387",
        "description": "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds (120 by default). The sshd SIGALRM handler is called asynchronously and calls various functions not designed to be called asynchronously (regreSSHion).",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 8.1,
            "exploitability_score": 2.2,
            "impact_score": 5.9,
            "base_severity": "HIGH",
        },
        "published_date": "2024-07-01T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-362"],
        "affected_vendors": ["OpenBSD", "Red Hat", "Debian", "Ubuntu"],
        "affected_products": ["OpenSSH < 9.8p1"],
        "references": [
            {"url": "https://www.openssh.com/security.html", "source": "OpenSSH", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "OpenSSH", "url": "https://www.openssh.com/portable.html", "type": "Update to 9.8p1+"}],
    },
    "CVE-2024-23897": {
        "cve_id": "CVE-2024-23897",
        "description": "Jenkins has a built-in command line interface (CLI) to access Jenkins from a script or shell environment. Jenkins uses the args4j library to parse command arguments and options on the Jenkins controller when processing CLI commands. This command parser has a feature that replaces an @ character followed by a file path in an argument with the file's contents.",
        "severity": "HIGH",
        "cvss": {
            "version": "3.1",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "exploitability_score": 3.9,
            "impact_score": 5.9,
            "base_severity": "CRITICAL",
        },
        "published_date": "2024-01-24T00:00:00Z",
        "last_modified_date": "2024-08-01T00:00:00Z",
        "cwe_ids": ["CWE-20"],
        "affected_vendors": ["Jenkins Project"],
        "affected_products": ["Jenkins 2.441 and earlier", "Jenkins LTS 2.426.2 and earlier"],
        "references": [
            {"url": "https://www.jenkins.io/security/advisory/2024-01-24/", "source": "Jenkins", "tags": ["Vendor Advisory"]},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-23897", "source": "NVD", "tags": ["Third Party Advisory"]},
        ],
        "exploit_available": True,
        "in_cisa_kev": True,
        "ransomware_known": False,
        "patches": [{"vendor": "Jenkins", "url": "https://www.jenkins.io/download/", "type": "Update to 2.442+"}],
    },
}

CVE_LIST = sorted(CVE_DATABASE.keys())


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Hardcoded Misconfigurations
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

MISCONFIGURATIONS = [
    {
        "id": "misconfig-001",
        "name": "Weak Password Policy",
        "description": "The domain password policy allows passwords shorter than 12 characters and does not enforce complexity requirements, making accounts susceptible to brute-force and dictionary attacks.",
        "severity": "high",
        "status": "open",
        "category": "Authentication",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-5.1",
        "rule_name": "Establish and Maintain a Secure Password Policy",
        "current_value": "Minimum password length: 8, Complexity: disabled, History: 3 passwords remembered",
        "expected_value": "Minimum password length: 14, Complexity: enabled, History: 24 passwords remembered",
        "affected_asset_count": 245,
        "discovered_at": "2025-06-01T00:00:00Z",
        "remediation_script": "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 24",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "IA-5"}, {"framework": "PCI DSS", "control": "8.3"}],
        "references": [{"title": "CIS Password Policy Guide", "url": "https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide"}],
    },
    {
        "id": "misconfig-002",
        "name": "SMBv1 Protocol Enabled",
        "description": "SMBv1 is enabled on multiple domain controllers and file servers. SMBv1 is an obsolete, unencrypted protocol with known vulnerabilities including EternalBlue (CVE-2017-0144) used in WannaCry ransomware.",
        "severity": "critical",
        "status": "open",
        "category": "Network Services",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-4.8",
        "rule_name": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
        "current_value": "SMBv1 enabled on 12 servers",
        "expected_value": "SMBv1 disabled on all servers",
        "affected_asset_count": 12,
        "discovered_at": "2025-05-20T00:00:00Z",
        "remediation_script": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "CM-7"}, {"framework": "CIS v8", "control": "4.8"}],
        "references": [{"title": "Microsoft SMBv1 Disable Guidance", "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"}],
    },
    {
        "id": "misconfig-003",
        "name": "TLS 1.0/1.1 Enabled on Web Servers",
        "description": "Multiple web servers still support deprecated TLS 1.0 and TLS 1.1 protocols, which are susceptible to downgrade attacks and do not meet PCI DSS compliance requirements.",
        "severity": "high",
        "status": "open",
        "category": "Encryption",
        "framework": "PCI DSS v4.0",
        "rule_id": "PCI-4.1",
        "rule_name": "Encrypt transmission of cardholder data across open, public networks",
        "current_value": "TLS 1.0, 1.1, 1.2, 1.3 enabled",
        "expected_value": "TLS 1.2 and 1.3 only",
        "affected_asset_count": 8,
        "discovered_at": "2025-06-10T00:00:00Z",
        "remediation_script": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0",
        "compliance_mappings": [{"framework": "PCI DSS", "control": "4.1"}, {"framework": "NIST 800-53", "control": "SC-13"}],
        "references": [{"title": "NIST SP 800-52 Rev 2", "url": "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"}],
    },
    {
        "id": "misconfig-004",
        "name": "Default SNMP Community Strings",
        "description": "SNMP services on network devices are configured with default community strings (public/private), allowing unauthorized read/write access to device configuration and operational data.",
        "severity": "critical",
        "status": "open",
        "category": "Network Devices",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-4.1",
        "rule_name": "Establish and Maintain a Secure Configuration Process",
        "current_value": "SNMP community: public (RO), private (RW)",
        "expected_value": "SNMP v3 with strong authentication and encryption",
        "affected_asset_count": 23,
        "discovered_at": "2025-05-15T00:00:00Z",
        "remediation_script": "snmp-server group AESGROUP v3 priv\nsnmp-server user admin AESGROUP v3 auth sha STRONGPASS priv aes 128 ENCRYPTKEY",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "CM-6"}, {"framework": "CIS v8", "control": "4.1"}],
        "references": [{"title": "Cisco SNMP Configuration Guide", "url": "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/xe-16/snmp-xe-16-book.html"}],
    },
    {
        "id": "misconfig-005",
        "name": "Unencrypted Database Backups",
        "description": "Database backup files for production SQL servers are stored on network shares without encryption, exposing sensitive data including PII and credentials if the backup files are compromised.",
        "severity": "critical",
        "status": "open",
        "category": "Data Protection",
        "framework": "NIST 800-53",
        "rule_id": "NIST-SC-28",
        "rule_name": "Protection of Information at Rest",
        "current_value": "Backups stored in plaintext on \\\\backup\\sql\\",
        "expected_value": "Backups encrypted with AES-256 and stored in secure, access-controlled location",
        "affected_asset_count": 5,
        "discovered_at": "2025-06-05T00:00:00Z",
        "remediation_script": "BACKUP DATABASE [ProductionDB] TO DISK = N'\\\\backup\\sql\\prod.bak' WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = BackupCert)",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "SC-28"}, {"framework": "GDPR", "control": "Art. 32"}],
        "references": [{"title": "SQL Server Backup Encryption", "url": "https://learn.microsoft.com/en-us/sql/relational-databases/backup-restore/backup-encryption"}],
    },
    {
        "id": "misconfig-006",
        "name": "Anonymous FTP Access Enabled",
        "description": "Anonymous FTP access is enabled on internal file servers, allowing unauthenticated users to read and in some cases write files to the FTP server, bypassing access controls.",
        "severity": "high",
        "status": "open",
        "category": "Network Services",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-4.6",
        "rule_name": "Securely Manage Enterprise Assets and Software",
        "current_value": "Anonymous FTP: Enabled, Read/Write: Enabled",
        "expected_value": "Anonymous FTP: Disabled; authenticated access only via SFTP/FTPS",
        "affected_asset_count": 3,
        "discovered_at": "2025-06-08T00:00:00Z",
        "remediation_script": "Set-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -Name 'Enabled' -Value $false",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "IA-2"}, {"framework": "PCI DSS", "control": "7.2"}],
        "references": [{"title": "IIS FTP Security", "url": "https://learn.microsoft.com/en-us/iis/configuration/system.ftpserver/security/authentication/anonymousauthentication"}],
    },
    {
        "id": "misconfig-007",
        "name": "Windows Defender Disabled",
        "description": "Windows Defender real-time protection is disabled on 45 endpoints through Group Policy, leaving these systems without endpoint protection against malware and ransomware.",
        "severity": "critical",
        "status": "open",
        "category": "Endpoint Security",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-10.1",
        "rule_name": "Deploy and Maintain Anti-Malware Software",
        "current_value": "Windows Defender Real-time Protection: Disabled via GPO",
        "expected_value": "Windows Defender Real-time Protection: Enabled, Cloud-delivered protection: Enabled",
        "affected_asset_count": 45,
        "discovered_at": "2025-05-25T00:00:00Z",
        "remediation_script": "Set-MpPreference -DisableRealtimeMonitoring $false\nSet-MpPreference -MAPSReporting Advanced",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "SI-3"}, {"framework": "CIS v8", "control": "10.1"}],
        "references": [{"title": "Windows Defender GPO Configuration", "url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-endpoints-gp"}],
    },
    {
        "id": "misconfig-008",
        "name": "Excessive Local Admin Rights",
        "description": "Over 150 users have local administrator rights on their workstations, violating the principle of least privilege. This significantly increases the attack surface for privilege escalation and lateral movement.",
        "severity": "high",
        "status": "open",
        "category": "Access Control",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-5.4",
        "rule_name": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
        "current_value": "152 standard users have local admin rights",
        "expected_value": "Only IT support staff and designated administrators have local admin; LAPS implemented for break-glass",
        "affected_asset_count": 152,
        "discovered_at": "2025-06-12T00:00:00Z",
        "remediation_script": "Remove-LocalGroupMember -Group 'Administrators' -Member 'DOMAIN\\username'\n# Deploy LAPS: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "AC-6"}, {"framework": "PCI DSS", "control": "7.1"}],
        "references": [{"title": "Microsoft LAPS", "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"}],
    },
    {
        "id": "misconfig-009",
        "name": "RDP Exposed to Internet",
        "description": "Remote Desktop Protocol (RDP) port 3389 is open to the internet on 3 servers without any additional protection such as VPN, RD Gateway, or Network Level Authentication enforcement.",
        "severity": "critical",
        "status": "open",
        "category": "Network Security",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-4.4",
        "rule_name": "Implement and Manage a Firewall on Servers",
        "current_value": "TCP 3389 open to 0.0.0.0/0",
        "expected_value": "RDP access restricted to internal IPs or VPN ranges only; NLA enforced",
        "affected_asset_count": 3,
        "discovered_at": "2025-06-15T00:00:00Z",
        "remediation_script": "Set-NetFirewallRule -DisplayName 'Remote Desktop' -RemoteAddress '10.0.0.0/8'",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "AC-17"}, {"framework": "CIS v8", "control": "4.4"}],
        "references": [{"title": "Secure RDP Best Practices", "url": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/secure-rdp"}],
    },
    {
        "id": "misconfig-010",
        "name": "Unrestricted Outbound Internet from DMZ",
        "description": "DMZ servers have unrestricted outbound internet access, which could allow compromised servers to exfiltrate data to attacker-controlled C2 servers through protocols like DNS, HTTPS, or obscure ports.",
        "severity": "high",
        "status": "open",
        "category": "Network Security",
        "framework": "NIST 800-53",
        "rule_id": "NIST-SC-7",
        "rule_name": "Boundary Protection",
        "current_value": "Outbound traffic: ANY allowed from DMZ subnet",
        "expected_value": "Outbound restricted to required services only (e.g., NTP, specific update servers)",
        "affected_asset_count": 18,
        "discovered_at": "2025-06-18T00:00:00Z",
        "remediation_script": "# Configure egress filtering on DMZ firewall/NSG\n# Allow only required outbound ports and destinations",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "SC-7"}, {"framework": "PCI DSS", "control": "1.3"}],
        "references": [{"title": "NIST DMZ Security Guide", "url": "https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final"}],
    },
    {
        "id": "misconfig-011",
        "name": "Missing Security Patches (30-Day SLA)",
        "description": "Critical and high severity security patches have not been applied within the 30-day SLA. 12 patches are overdue by more than 45 days, including patches for actively exploited vulnerabilities.",
        "severity": "critical",
        "status": "open",
        "category": "Patch Management",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-7.3",
        "rule_name": "Perform Automated Operating System Patch Management",
        "current_value": "12 critical patches overdue > 45 days",
        "expected_value": "Critical patches applied within 15 days, high within 30 days",
        "affected_asset_count": 34,
        "discovered_at": "2025-06-20T00:00:00Z",
        "remediation_script": "Get-WindowsUpdate -Install -AcceptAll -AutoReboot",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "SI-2"}, {"framework": "CIS v8", "control": "7.3"}],
        "references": [{"title": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
    },
    {
        "id": "misconfig-012",
        "name": "LLMNR and NBT-NS Enabled",
        "description": "Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are enabled across the domain, making the environment susceptible to name resolution poisoning attacks that can lead to credential theft.",
        "severity": "medium",
        "status": "open",
        "category": "Network Security",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-4.8",
        "rule_name": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
        "current_value": "LLMNR: Enabled, NBT-NS: Enabled via DHCP",
        "expected_value": "LLMNR: Disabled, NBT-NS: Disabled",
        "affected_asset_count": 320,
        "discovered_at": "2025-05-10T00:00:00Z",
        "remediation_script": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "CM-7"}, {"framework": "CIS v8", "control": "4.8"}],
        "references": [{"title": "MITRE ATT&CK T1557 LLMNR/NBT-NS Poisoning", "url": "https://attack.mitre.org/techniques/T1557/001/"}],
    },
    {
        "id": "misconfig-013",
        "name": "Azure Storage Account Public Access",
        "description": "Azure Blob Storage accounts are configured with public access enabled, allowing anonymous access to blob containers that may contain sensitive configuration files and data exports.",
        "severity": "critical",
        "status": "open",
        "category": "Cloud Security",
        "framework": "CIS Microsoft Azure Foundations",
        "rule_id": "CIS-Azure-3.1",
        "rule_name": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "current_value": "Allow Blob public access: Enabled, Secure transfer: Disabled",
        "expected_value": "Allow Blob public access: Disabled, Secure transfer: Enabled, Minimum TLS 1.2",
        "affected_asset_count": 4,
        "discovered_at": "2025-06-22T00:00:00Z",
        "remediation_script": "az storage account update --name $storageAccount --allow-blob-public-access false --min-tls-version TLS1_2",
        "compliance_mappings": [{"framework": "CIS Azure", "control": "3.1"}, {"framework": "NIST 800-53", "control": "AC-3"}],
        "references": [{"title": "CIS Microsoft Azure Foundations Benchmark", "url": "https://www.cisecurity.org/benchmark/azure"}],
    },
    {
        "id": "misconfig-014",
        "name": "Docker Socket Exposed",
        "description": "The Docker daemon socket (/var/run/docker.sock) is mounted inside containers and exposed without TLS authentication, allowing container breakout to the host and privilege escalation.",
        "severity": "critical",
        "status": "open",
        "category": "Container Security",
        "framework": "CIS Docker Benchmark",
        "rule_id": "CIS-Docker-2.1",
        "rule_name": "Ensure network traffic is restricted between containers on the default bridge",
        "current_value": "docker.sock mounted as volume in 8 containers",
        "expected_value": "docker.sock not mounted in containers; Docker API protected by TLS",
        "affected_asset_count": 8,
        "discovered_at": "2025-06-25T00:00:00Z",
        "remediation_script": "# Remove docker.sock mounts from container definitions\n# Use docker socket proxy instead: https://github.com/Tecnativa/docker-socket-proxy",
        "compliance_mappings": [{"framework": "CIS Docker", "control": "2.1"}, {"framework": "NIST 800-53", "control": "CM-7"}],
        "references": [{"title": "CIS Docker Benchmark", "url": "https://www.cisecurity.org/benchmark/docker"}],
    },
    {
        "id": "misconfig-015",
        "name": "Logging Disabled on Critical Servers",
        "description": "Audit logging and PowerShell script block logging are disabled on 28 critical servers, preventing SOC analysts from detecting and investigating security incidents on these systems.",
        "severity": "high",
        "status": "open",
        "category": "Logging and Monitoring",
        "framework": "CIS Controls v8",
        "rule_id": "CIS-8.2",
        "rule_name": "Collect Audit Logs",
        "current_value": "Advanced Audit Policy: Not Configured, PowerShell Logging: Disabled",
        "expected_value": "Advanced Audit Policy: Configured per CIS baseline, PowerShell Logging: ScriptBlock, Module, and Transcription enabled",
        "affected_asset_count": 28,
        "discovered_at": "2025-06-28T00:00:00Z",
        "remediation_script": "auditpol /set /category:'Account Logon' /success:enable /failure:enable\nSet-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
        "compliance_mappings": [{"framework": "NIST 800-53", "control": "AU-2"}, {"framework": "CIS v8", "control": "8.2"}],
        "references": [{"title": "Windows Audit Policy CIS", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server"}],
    },
]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Helper: Validate Cron Expression
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _validate_cron(expr: str) -> bool:
    pattern = r'^(\*|\d+(-\d+)?(/\d+)?)(\s+(\*|\d+(-\d+)?(/\d+)?)){4}$'
    parts = expr.strip().split()
    if len(parts) != 5:
        return False
    for part in parts:
        if not re.match(r'^(\*|\d+(-\d+)?(/\d+)?)$', part):
            return False
        if part != "*":
            nums = part.replace("/", "-").split("-")
            for n in nums:
                if n and int(n) < 0:
                    return False
    return True


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SCANS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post("/scans", dependencies=[Depends(RequireSOCManager)])
async def create_scan(
    body: ScanCreate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None
    now = datetime.now(timezone.utc)

    template_id = uuid.UUID(body.template_id) if body.template_id else None

    scan_config = {
        "description": body.description,
        "priority": body.priority,
        "max_duration_minutes": body.max_duration_minutes,
        "tags": body.tags,
    }
    targets_json = [t.model_dump() for t in body.targets]

    scan = VulnerabilityScan(
        tenant_id=tid,
        name=body.name,
        scan_type=body.scan_type.value,
        status="pending",
        template_id=template_id,
        target_assets=targets_json,
        config=scan_config,
    )
    db.add(scan)
    await db.flush()

    await _audit(
        db,
        action="scan_created",
        resource_type="vulnerability_scan",
        resource_id=scan.id,
        tenant_id=tid,
        user_id=uid,
        details={"name": body.name, "scan_type": body.scan_type.value, "targets_count": len(body.targets)},
    )
    await db.commit()
    await db.refresh(scan)

    return {
        "id": str(scan.id),
        "tenant_id": str(scan.tenant_id),
        "name": scan.name,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "template_id": str(scan.template_id) if scan.template_id else None,
        "target_assets": scan.target_assets,
        "config": scan.config,
        "started_at": _to_iso(scan.started_at),
        "completed_at": _to_iso(scan.completed_at),
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "created_at": _to_iso(scan.created_at),
        "updated_at": _to_iso(scan.updated_at),
    }


@router.get("/scans", dependencies=[Depends(RequireSOCAnalyst)])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_order: str = Query("desc"),
):
    tid = uuid.UUID(tenant_id)
    conditions = [VulnerabilityScan.tenant_id == tid]

    if status:
        conditions.append(VulnerabilityScan.status == status)
    if scan_type:
        conditions.append(VulnerabilityScan.scan_type == scan_type)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            conditions.append(VulnerabilityScan.created_at >= dt_from)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_from format")
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            conditions.append(VulnerabilityScan.created_at <= dt_to)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_to format")

    count_q = select(func.count()).select_from(VulnerabilityScan).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar()

    offset = (page - 1) * page_size
    order_func = desc if sort_order == "desc" else asc
    sort_col = VulnerabilityScan.created_at
    if sort_by == "name":
        sort_col = VulnerabilityScan.name
    elif sort_by == "status":
        sort_col = VulnerabilityScan.status
    elif sort_by == "findings_count":
        sort_col = VulnerabilityScan.findings_count

    q = select(VulnerabilityScan).where(and_(*conditions)).order_by(order_func(sort_col)).offset(offset).limit(page_size)
    result = await db.execute(q)
    scans = result.scalars().all()

    items = []
    scan_fields = ["id", "tenant_id", "name", "scan_type", "status", "template_id", "target_assets",
                    "started_at", "completed_at", "findings_count", "critical_count", "high_count",
                    "medium_count", "config", "created_at", "updated_at"]
    for s in scans:
        items.append(_model_to_dict(s, scan_fields))

    return _paginated_response(items, total, page, page_size)


@router.get("/scans/{scan_id}", dependencies=[Depends(RequireSOCAnalyst)])
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)

    q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_fields = ["id", "tenant_id", "name", "scan_type", "status", "template_id", "target_assets",
                    "started_at", "completed_at", "findings_count", "critical_count", "high_count",
                    "medium_count", "config", "created_at", "updated_at"]
    return _model_to_dict(scan, scan_fields)


@router.post("/scans/{scan_id}/start", dependencies=[Depends(RequireSOCManager)])
async def start_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("pending", "paused"):
        raise HTTPException(status_code=400, detail=f"Cannot start scan in status '{scan.status}'")

    now = datetime.now(timezone.utc)
    scan.status = "running"
    scan.started_at = now

    await _audit(
        db,
        action="scan_started",
        resource_type="vulnerability_scan",
        resource_id=scan.id,
        tenant_id=tid,
        user_id=uid,
        details={"previous_status": "pending" if scan.started_at is None else "paused"},
    )
    await db.commit()
    await db.refresh(scan)

    return {"id": str(scan.id), "status": scan.status, "started_at": _to_iso(scan.started_at), "message": "Scan started"}


@router.post("/scans/{scan_id}/stop", dependencies=[Depends(RequireSOCManager)])
async def stop_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("running", "paused"):
        raise HTTPException(status_code=400, detail=f"Cannot stop scan in status '{scan.status}'")

    now = datetime.now(timezone.utc)

    findings_total = (await db.execute(select(func.count()).select_from(Vulnerability).where(Vulnerability.scan_id == sid))).scalar()
    critical_count = (await db.execute(select(func.count()).select_from(Vulnerability).where(and_(Vulnerability.scan_id == sid, Vulnerability.severity == "critical")))).scalar()
    high_count = (await db.execute(select(func.count()).select_from(Vulnerability).where(and_(Vulnerability.scan_id == sid, Vulnerability.severity == "high")))).scalar()
    medium_count = (await db.execute(select(func.count()).select_from(Vulnerability).where(and_(Vulnerability.scan_id == sid, Vulnerability.severity == "medium")))).scalar()

    scan.status = "completed"
    scan.completed_at = now
    scan.findings_count = findings_total or 0
    scan.critical_count = critical_count or 0
    scan.high_count = high_count or 0
    scan.medium_count = medium_count or 0

    await _audit(
        db,
        action="scan_completed",
        resource_type="vulnerability_scan",
        resource_id=scan.id,
        tenant_id=tid,
        user_id=uid,
        details={"findings_count": scan.findings_count, "critical": scan.critical_count, "high": scan.high_count, "medium": scan.medium_count},
    )
    await db.commit()
    await db.refresh(scan)

    return {
        "id": str(scan.id),
        "status": scan.status,
        "completed_at": _to_iso(scan.completed_at),
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "message": "Scan completed",
    }


@router.post("/scans/{scan_id}/pause", dependencies=[Depends(RequireSOCManager)])
async def pause_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(status_code=400, detail=f"Cannot pause scan in status '{scan.status}'")

    scan.status = "paused"
    await _audit(
        db,
        action="scan_paused",
        resource_type="vulnerability_scan",
        resource_id=scan.id,
        tenant_id=tid,
        user_id=uid,
    )
    await db.commit()
    await db.refresh(scan)

    return {"id": str(scan.id), "status": scan.status, "message": "Scan paused"}


@router.post("/scans/{scan_id}/resume", dependencies=[Depends(RequireSOCManager)])
async def resume_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    result = await db.execute(q)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "paused":
        raise HTTPException(status_code=400, detail=f"Cannot resume scan in status '{scan.status}'")

    scan.status = "running"
    await _audit(
        db,
        action="scan_resumed",
        resource_type="vulnerability_scan",
        resource_id=scan.id,
        tenant_id=tid,
        user_id=uid,
    )
    await db.commit()
    await db.refresh(scan)

    return {"id": str(scan.id), "status": scan.status, "message": "Scan resumed"}


@router.get("/scans/{scan_id}/results", dependencies=[Depends(RequireSOCAnalyst)])
async def get_scan_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)

    scan_q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    scan_result = await db.execute(scan_q)
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    count_q = select(func.count()).select_from(Vulnerability).where(and_(Vulnerability.tenant_id == tid, Vulnerability.scan_id == sid))
    total = (await db.execute(count_q)).scalar()

    offset = (page - 1) * page_size
    q = select(Vulnerability).options(selectinload(Vulnerability.affected_asset)).where(
        and_(Vulnerability.tenant_id == tid, Vulnerability.scan_id == sid)
    ).offset(offset).limit(page_size).order_by(desc(Vulnerability.detected_at))
    result = await db.execute(q)
    vulns = result.scalars().all()

    items = []
    for v in vulns:
        d = _model_to_dict(v, [
            "id", "tenant_id", "cve_id", "title", "description", "severity", "cvss_score",
            "cvss_vector", "affected_asset_id", "affected_software", "affected_version",
            "fixed_version", "status", "exploit_available", "exploit_references",
            "remediation", "remediation_url", "mitre_techniques", "scan_id",
            "assignee_id", "sla_deadline", "published_at", "detected_at", "created_at", "updated_at",
        ])
        if v.affected_asset:
            d["affected_asset"] = {
                "id": str(v.affected_asset.id),
                "name": v.affected_asset.name,
                "hostname": v.affected_asset.hostname,
                "ip_address": v.affected_asset.ip_address,
                "type": v.affected_asset.type,
                "os": v.affected_asset.os,
            }
        else:
            d["affected_asset"] = None
        items.append(d)

    return _paginated_response(items, total, page, page_size)


@router.get("/scans/{scan_id}/report", dependencies=[Depends(RequireSOCAnalyst)])
async def get_scan_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    sid = uuid.UUID(scan_id)

    scan_q = select(VulnerabilityScan).where(and_(VulnerabilityScan.id == sid, VulnerabilityScan.tenant_id == tid))
    scan_result = await db.execute(scan_q)
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    severity_q = select(
        Vulnerability.severity,
        func.count(Vulnerability.id).label("cnt")
    ).where(
        and_(Vulnerability.tenant_id == tid, Vulnerability.scan_id == sid)
    ).group_by(Vulnerability.severity)
    sev_result = await db.execute(severity_q)
    severity_counts = {row.severity: row.cnt for row in sev_result}

    status_q = select(
        Vulnerability.status,
        func.count(Vulnerability.id).label("cnt")
    ).where(
        and_(Vulnerability.tenant_id == tid, Vulnerability.scan_id == sid)
    ).group_by(Vulnerability.status)
    stat_result = await db.execute(status_q)
    status_counts = {row.status: row.cnt for row in stat_result}

    now = datetime.now(timezone.utc)
    return {
        "scan_id": str(scan.id),
        "scan_name": scan.name,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "started_at": _to_iso(scan.started_at),
        "completed_at": _to_iso(scan.completed_at),
        "generated_at": _to_iso(now),
        "summary": {
            "total_findings": scan.findings_count,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "findings_by_severity": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "none": severity_counts.get("none", 0),
            },
            "findings_by_status": {
                "open": status_counts.get("open", 0),
                "in_progress": status_counts.get("in_progress", 0),
                "resolved": status_counts.get("resolved", 0),
                "false_positive": status_counts.get("false_positive", 0),
                "wont_fix": status_counts.get("wont_fix", 0),
                "mitigated": status_counts.get("mitigated", 0),
            },
        },
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# VULNERABILITIES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/", dependencies=[Depends(RequireSOCAnalyst)])
async def list_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    severity: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    vuln_status: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_order: str = Query("desc"),
):
    tid = uuid.UUID(tenant_id)
    conditions = [Vulnerability.tenant_id == tid]

    if severity:
        conditions.append(Vulnerability.severity == severity)
    if cve_id:
        conditions.append(Vulnerability.cve_id == cve_id)
    if vuln_status:
        conditions.append(Vulnerability.status == vuln_status)
    if asset_id:
        conditions.append(Vulnerability.affected_asset_id == uuid.UUID(asset_id))
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            conditions.append(Vulnerability.detected_at >= dt_from)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_from format")
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            conditions.append(Vulnerability.detected_at <= dt_to)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_to format")
    if search:
        search_pattern = f"%{search}%"
        conditions.append(
            or_(
                Vulnerability.title.ilike(search_pattern),
                Vulnerability.cve_id.ilike(search_pattern),
                Vulnerability.description.ilike(search_pattern),
                Vulnerability.affected_software.ilike(search_pattern),
            )
        )

    count_q = select(func.count()).select_from(Vulnerability).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar()

    offset = (page - 1) * page_size
    order_func = desc if sort_order == "desc" else asc
    sort_col = Vulnerability.detected_at
    if sort_by == "severity":
        sort_col = Vulnerability.severity
    elif sort_by == "cvss_score":
        sort_col = Vulnerability.cvss_score
    elif sort_by == "title":
        sort_col = Vulnerability.title
    elif sort_by == "status":
        sort_col = Vulnerability.status

    q = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_asset))
        .where(and_(*conditions))
        .order_by(order_func(sort_col))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(q)
    vulns = result.unique().scalars().all()

    items = []
    for v in vulns:
        d = {
            "id": str(v.id),
            "tenant_id": str(v.tenant_id),
            "cve_id": v.cve_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "cvss_vector": v.cvss_vector,
            "affected_asset_id": str(v.affected_asset_id) if v.affected_asset_id else None,
            "affected_software": v.affected_software,
            "affected_version": v.affected_version,
            "fixed_version": v.fixed_version,
            "status": v.status,
            "exploit_available": v.exploit_available,
            "exploit_references": v.exploit_references,
            "remediation": v.remediation,
            "remediation_url": v.remediation_url,
            "mitre_techniques": v.mitre_techniques,
            "scan_id": str(v.scan_id) if v.scan_id else None,
            "assignee_id": str(v.assignee_id) if v.assignee_id else None,
            "sla_deadline": _to_iso(v.sla_deadline),
            "published_at": _to_iso(v.published_at),
            "detected_at": _to_iso(v.detected_at),
            "created_at": _to_iso(v.created_at),
            "updated_at": _to_iso(v.updated_at),
        }
        if v.affected_asset:
            d["affected_asset"] = {
                "id": str(v.affected_asset.id),
                "name": v.affected_asset.name,
                "hostname": v.affected_asset.hostname,
                "ip_address": v.affected_asset.ip_address,
                "type": v.affected_asset.type,
                "os": v.affected_asset.os,
            }
        else:
            d["affected_asset"] = None
        items.append(d)

    return _paginated_response(items, total, page, page_size)


@router.get("/stats", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability_stats(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    now = datetime.now(timezone.utc)

    by_severity_q = select(
        Vulnerability.severity,
        func.count(Vulnerability.id).label("cnt")
    ).where(Vulnerability.tenant_id == tid).group_by(Vulnerability.severity)
    sev_result = await db.execute(by_severity_q)
    by_severity = {row.severity: row.cnt for row in sev_result}

    by_status_q = select(
        Vulnerability.status,
        func.count(Vulnerability.id).label("cnt")
    ).where(Vulnerability.tenant_id == tid).group_by(Vulnerability.status)
    stat_result = await db.execute(by_status_q)
    by_status = {row.status: row.cnt for row in stat_result}

    avg_age_q = select(
        func.avg(
            func.extract("epoch", now - Vulnerability.detected_at) / 86400.0
        )
    ).where(and_(Vulnerability.tenant_id == tid, Vulnerability.status.in_(["open", "in_progress"])))
    avg_age_result = await db.execute(avg_age_q)
    avg_age_days = avg_age_result.scalar()

    top_software_q = (
        select(
            Vulnerability.affected_software,
            func.count(Vulnerability.id).label("cnt")
        )
        .where(and_(Vulnerability.tenant_id == tid, Vulnerability.affected_software.isnot(None)))
        .group_by(Vulnerability.affected_software)
        .order_by(desc("cnt"))
        .limit(5)
    )
    sw_result = await db.execute(top_software_q)
    top_affected_software = [{"software": row.affected_software, "count": row.cnt} for row in sw_result]

    total_q = select(func.count()).select_from(Vulnerability).where(Vulnerability.tenant_id == tid)
    total = (await db.execute(total_q)).scalar()

    return {
        "total_vulnerabilities": total,
        "by_severity": {
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "none": by_severity.get("none", 0),
        },
        "by_status": {
            "open": by_status.get("open", 0),
            "in_progress": by_status.get("in_progress", 0),
            "resolved": by_status.get("resolved", 0),
            "false_positive": by_status.get("false_positive", 0),
            "wont_fix": by_status.get("wont_fix", 0),
            "mitigated": by_status.get("mitigated", 0),
        },
        "avg_age_days": round(avg_age_days, 1) if avg_age_days else None,
        "top_affected_software": top_affected_software,
    }


@router.get("/{vulnerability_id}", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)

    q = select(Vulnerability).options(selectinload(Vulnerability.affected_asset)).where(
        and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid)
    )
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    d = {
        "id": str(vuln.id),
        "tenant_id": str(vuln.tenant_id),
        "cve_id": vuln.cve_id,
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector,
        "affected_asset_id": str(vuln.affected_asset_id) if vuln.affected_asset_id else None,
        "affected_software": vuln.affected_software,
        "affected_version": vuln.affected_version,
        "fixed_version": vuln.fixed_version,
        "status": vuln.status,
        "exploit_available": vuln.exploit_available,
        "exploit_references": vuln.exploit_references,
        "remediation": vuln.remediation,
        "remediation_url": vuln.remediation_url,
        "mitre_techniques": vuln.mitre_techniques,
        "scan_id": str(vuln.scan_id) if vuln.scan_id else None,
        "assignee_id": str(vuln.assignee_id) if vuln.assignee_id else None,
        "sla_deadline": _to_iso(vuln.sla_deadline),
        "published_at": _to_iso(vuln.published_at),
        "detected_at": _to_iso(vuln.detected_at),
        "created_at": _to_iso(vuln.created_at),
        "updated_at": _to_iso(vuln.updated_at),
    }
    if vuln.affected_asset:
        d["affected_asset"] = {
            "id": str(vuln.affected_asset.id),
            "name": vuln.affected_asset.name,
            "hostname": vuln.affected_asset.hostname,
            "ip_address": vuln.affected_asset.ip_address,
            "type": vuln.affected_asset.type,
            "os": vuln.affected_asset.os,
            "risk_level": vuln.affected_asset.risk_level,
            "last_seen": _to_iso(vuln.affected_asset.last_seen),
        }
    else:
        d["affected_asset"] = None
    return d


@router.patch("/{vulnerability_id}", dependencies=[Depends(RequireSOCAnalyst)])
async def update_vulnerability(
    vulnerability_id: str,
    body: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(Vulnerability).where(and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid))
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    changes = {}
    if body.status is not None and body.status.value != vuln.status:
        changes["status"] = {"old": vuln.status, "new": body.status.value}
        vuln.status = body.status.value
    if body.assignee_id is not None:
        new_assignee = uuid.UUID(body.assignee_id) if body.assignee_id else None
        old_assignee = str(vuln.assignee_id) if vuln.assignee_id else None
        if str(new_assignee) != old_assignee:
            changes["assignee_id"] = {"old": old_assignee, "new": str(new_assignee) if new_assignee else None}
            vuln.assignee_id = new_assignee
    if body.sla_deadline is not None:
        old_sla = _to_iso(vuln.sla_deadline)
        new_sla = _to_iso(body.sla_deadline)
        if new_sla != old_sla:
            changes["sla_deadline"] = {"old": old_sla, "new": new_sla}
            vuln.sla_deadline = body.sla_deadline
    if body.notes is not None:
        changes["notes"] = body.notes

    if changes:
        await _audit(
            db,
            action="vulnerability_updated",
            resource_type="vulnerability",
            resource_id=vid,
            tenant_id=tid,
            user_id=uid,
            details=changes,
        )
        await db.commit()
        await db.refresh(vuln)

    return {
        "id": str(vuln.id),
        "status": vuln.status,
        "assignee_id": str(vuln.assignee_id) if vuln.assignee_id else None,
        "sla_deadline": _to_iso(vuln.sla_deadline),
        "updated_at": _to_iso(vuln.updated_at),
        "message": "Vulnerability updated",
    }


@router.post("/bulk", dependencies=[Depends(RequireSOCManager)])
async def bulk_update_vulnerabilities(
    body: VulnerabilityBulkUpdate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    updated = 0
    failed = 0
    errors = []

    valid_actions = {"resolve": "resolved", "in_progress": "in_progress", "false_positive": "false_positive", "wont_fix": "wont_fix"}

    for item in body.vulnerabilities:
        action_status = valid_actions.get(item.action)
        if not action_status:
            failed += 1
            errors.append({"id": item.id, "error": f"Invalid action: {item.action}"})
            continue
        try:
            vid = uuid.UUID(item.id)
            q = select(Vulnerability).where(and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid))
            result = await db.execute(q)
            vuln = result.scalar_one_or_none()
            if not vuln:
                failed += 1
                errors.append({"id": item.id, "error": "Not found"})
                continue
            old_status = vuln.status
            vuln.status = action_status
            await _audit(
                db,
                action="vulnerability_bulk_update",
                resource_type="vulnerability",
                resource_id=vid,
                tenant_id=tid,
                user_id=uid,
                details={"old_status": old_status, "new_status": action_status, "action": item.action},
            )
            updated += 1
        except ValueError:
            failed += 1
            errors.append({"id": item.id, "error": "Invalid UUID"})

    await db.commit()

    return VulnerabilityBulkUpdateResponse(
        total=len(body.vulnerabilities),
        updated=updated,
        failed=failed,
        errors=errors,
    )


@router.get("/{vulnerability_id}/affected-assets", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability_affected_assets(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)

    q = select(Vulnerability).options(selectinload(Vulnerability.affected_asset)).where(
        and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid)
    )
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not vuln.affected_asset:
        return {"vulnerability_id": str(vid), "affected_assets": []}

    asset = vuln.affected_asset
    return {
        "vulnerability_id": str(vid),
        "affected_assets": [
            {
                "id": str(asset.id),
                "name": asset.name,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "type": asset.type,
                "os": asset.os,
                "os_version": asset.os_version,
                "risk_level": asset.risk_level,
                "status": asset.status,
                "last_seen": _to_iso(asset.last_seen),
                "tags": asset.tags,
            }
        ],
    }


@router.get("/{vulnerability_id}/exploits", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability_exploits(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)

    q = select(Vulnerability).where(and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid))
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    exploits = vuln.exploit_references or []
    return {
        "vulnerability_id": str(vid),
        "cve_id": vuln.cve_id,
        "exploit_available": vuln.exploit_available,
        "total_exploits": len(exploits),
        "exploits": exploits,
    }


@router.get("/{vulnerability_id}/mitre", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability_mitre(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)

    q = select(Vulnerability).where(and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid))
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    techniques = vuln.mitre_techniques or []
    return {
        "vulnerability_id": str(vid),
        "cve_id": vuln.cve_id,
        "total_mappings": len(techniques),
        "techniques": [{"technique_id": t} for t in techniques],
    }


@router.get("/{vulnerability_id}/remediation", dependencies=[Depends(RequireSOCAnalyst)])
async def get_vulnerability_remediation(
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
):
    tid = uuid.UUID(tenant_id)
    vid = uuid.UUID(vulnerability_id)

    q = select(Vulnerability).where(and_(Vulnerability.id == vid, Vulnerability.tenant_id == tid))
    result = await db.execute(q)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    return {
        "vulnerability_id": str(vid),
        "cve_id": vuln.cve_id,
        "remediation": vuln.remediation,
        "remediation_url": vuln.remediation_url,
        "fixed_version": vuln.fixed_version,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CVE LOOKUPS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/cve/search", dependencies=[Depends(RequireSOCAnalyst)])
async def search_cves(
    query: str = Query("", description="Search query for CVE ID or description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    query_lower = query.lower().strip()
    matches = []
    for cve_id, details in CVE_DATABASE.items():
        if query_lower in cve_id.lower() or query_lower in details["description"].lower():
            matches.append({
                "cve_id": details["cve_id"],
                "description": details["description"],
                "severity": details["severity"],
                "cvss_score": details["cvss"]["base_score"],
                "exploit_available": details["exploit_available"],
                "published_date": details["published_date"],
            })

    total = len(matches)
    offset = (page - 1) * page_size
    paged = matches[offset:offset + page_size]

    return _paginated_response(paged, total, page, page_size)


@router.get("/cve/{cve_id}", dependencies=[Depends(RequireSOCAnalyst)])
async def get_cve_detail(cve_id: str):
    cve_upper = cve_id.upper()
    if cve_upper not in CVE_DATABASE:
        raise HTTPException(status_code=404, detail=f"CVE {cve_upper} not found")

    details = CVE_DATABASE[cve_upper]
    return {
        "cve_id": details["cve_id"],
        "description": details["description"],
        "severity": details["severity"],
        "cvss": details["cvss"],
        "published_date": details["published_date"],
        "last_modified_date": details["last_modified_date"],
        "cwe_ids": details["cwe_ids"],
        "affected_vendors": details["affected_vendors"],
        "affected_products": details["affected_products"],
        "references": details["references"],
        "patches": details["patches"],
        "exploit_available": details["exploit_available"],
        "in_cisa_kev": details["in_cisa_kev"],
        "ransomware_known": details["ransomware_known"],
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SCAN TEMPLATES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/scans/templates", dependencies=[Depends(RequireSOCAnalyst)])
async def list_scan_templates(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    tid = uuid.UUID(tenant_id)

    count_q = select(func.count()).select_from(ScanTemplate).where(ScanTemplate.tenant_id == tid)
    total = (await db.execute(count_q)).scalar()

    offset = (page - 1) * page_size
    q = select(ScanTemplate).where(ScanTemplate.tenant_id == tid).offset(offset).limit(page_size).order_by(asc(ScanTemplate.name))
    result = await db.execute(q)
    templates = result.scalars().all()

    items = []
    for t in templates:
        items.append({
            "id": str(t.id),
            "tenant_id": str(t.tenant_id),
            "name": t.name,
            "description": t.description,
            "scan_type": t.scan_type,
            "config": t.config,
            "compliance_framework": t.compliance_framework,
            "created_at": _to_iso(t.created_at),
            "updated_at": _to_iso(t.updated_at),
        })

    return _paginated_response(items, total, page, page_size)


@router.post("/scans/templates", dependencies=[Depends(RequireSOCManager)])
async def create_scan_template(
    body: ScanTemplateCreate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    existing_q = select(ScanTemplate).where(and_(ScanTemplate.tenant_id == tid, ScanTemplate.name == body.name))
    existing = (await db.execute(existing_q)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"Template '{body.name}' already exists")

    template = ScanTemplate(
        tenant_id=tid,
        name=body.name,
        description=body.description,
        scan_type=body.scan_type.value if hasattr(body.scan_type, 'value') else body.scan_type,
        config=body.config,
        compliance_framework=body.compliance_framework,
    )
    db.add(template)
    await db.flush()

    await _audit(
        db,
        action="scan_template_created",
        resource_type="scan_template",
        resource_id=template.id,
        tenant_id=tid,
        user_id=uid,
        details={"name": body.name, "scan_type": body.scan_type.value if hasattr(body.scan_type, 'value') else str(body.scan_type)},
    )
    await db.commit()
    await db.refresh(template)

    return {
        "id": str(template.id),
        "tenant_id": str(template.tenant_id),
        "name": template.name,
        "description": template.description,
        "scan_type": template.scan_type,
        "config": template.config,
        "compliance_framework": template.compliance_framework,
        "created_at": _to_iso(template.created_at),
        "updated_at": _to_iso(template.updated_at),
    }


@router.patch("/scans/templates/{template_id}", dependencies=[Depends(RequireSOCManager)])
async def update_scan_template(
    template_id: str,
    body: ScanTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    tpl_id = uuid.UUID(template_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(ScanTemplate).where(and_(ScanTemplate.id == tpl_id, ScanTemplate.tenant_id == tid))
    result = await db.execute(q)
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Scan template not found")

    changes = {}
    if body.name is not None:
        existing_q = select(ScanTemplate).where(and_(ScanTemplate.tenant_id == tid, ScanTemplate.name == body.name, ScanTemplate.id != tpl_id))
        if (await db.execute(existing_q)).scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"Template '{body.name}' already exists")
        if body.name != template.name:
            changes["name"] = {"old": template.name, "new": body.name}
            template.name = body.name
    if body.description is not None:
        changes["description"] = body.description
        template.description = body.description
    if body.config is not None:
        changes["config"] = body.config
        template.config = body.config
    if body.compliance_framework is not None:
        changes["compliance_framework"] = {"old": template.compliance_framework, "new": body.compliance_framework}
        template.compliance_framework = body.compliance_framework

    if changes:
        await _audit(
            db,
            action="scan_template_updated",
            resource_type="scan_template",
            resource_id=tpl_id,
            tenant_id=tid,
            user_id=uid,
            details=changes,
        )
        await db.commit()
        await db.refresh(template)

    return {
        "id": str(template.id),
        "name": template.name,
        "description": template.description,
        "scan_type": template.scan_type,
        "config": template.config,
        "compliance_framework": template.compliance_framework,
        "updated_at": _to_iso(template.updated_at),
    }


@router.delete("/scans/templates/{template_id}", dependencies=[Depends(RequireSOCManager)])
async def delete_scan_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    tpl_id = uuid.UUID(template_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(ScanTemplate).where(and_(ScanTemplate.id == tpl_id, ScanTemplate.tenant_id == tid))
    result = await db.execute(q)
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Scan template not found")

    schedule_q = select(func.count()).select_from(ScanSchedule).where(
        and_(ScanSchedule.tenant_id == tid, ScanSchedule.scan_template_id == tpl_id)
    )
    schedule_count = (await db.execute(schedule_q)).scalar()
    if schedule_count and schedule_count > 0:
        raise HTTPException(status_code=409, detail=f"Cannot delete template: it is referenced by {schedule_count} schedule(s)")

    await db.delete(template)
    await _audit(
        db,
        action="scan_template_deleted",
        resource_type="scan_template",
        resource_id=tpl_id,
        tenant_id=tid,
        user_id=uid,
        details={"name": template.name},
    )
    await db.commit()

    return {"message": "Scan template deleted", "id": str(tpl_id)}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SCAN SCHEDULES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.post("/scans/schedule", dependencies=[Depends(RequireSOCManager)])
async def create_scan_schedule(
    body: ScanScheduleCreate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    if not _validate_cron(body.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    template_uid = uuid.UUID(body.scan_template_id) if body.scan_template_id else None

    schedule = ScanSchedule(
        tenant_id=tid,
        name=body.name,
        scan_template_id=template_uid,
        target_assets=body.target_assets,
        cron_expression=body.cron_expression,
        is_active=body.is_active,
    )
    db.add(schedule)
    await db.flush()

    await _audit(
        db,
        action="scan_schedule_created",
        resource_type="scan_schedule",
        resource_id=schedule.id,
        tenant_id=tid,
        user_id=uid,
        details={"name": body.name, "cron_expression": body.cron_expression},
    )
    await db.commit()
    await db.refresh(schedule)

    return {
        "id": str(schedule.id),
        "tenant_id": str(schedule.tenant_id),
        "name": schedule.name,
        "scan_template_id": str(schedule.scan_template_id) if schedule.scan_template_id else None,
        "target_assets": schedule.target_assets,
        "cron_expression": schedule.cron_expression,
        "is_active": schedule.is_active,
        "last_run_at": _to_iso(schedule.last_run_at),
        "next_run_at": _to_iso(schedule.next_run_at),
        "created_at": _to_iso(schedule.created_at),
        "updated_at": _to_iso(schedule.updated_at),
    }


@router.get("/scans/schedules", dependencies=[Depends(RequireSOCAnalyst)])
async def list_scan_schedules(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    tid = uuid.UUID(tenant_id)

    count_q = select(func.count()).select_from(ScanSchedule).where(ScanSchedule.tenant_id == tid)
    total = (await db.execute(count_q)).scalar()

    offset = (page - 1) * page_size
    q = select(ScanSchedule).where(ScanSchedule.tenant_id == tid).offset(offset).limit(page_size).order_by(desc(ScanSchedule.created_at))
    result = await db.execute(q)
    schedules = result.scalars().all()

    items = []
    for s in schedules:
        items.append({
            "id": str(s.id),
            "tenant_id": str(s.tenant_id),
            "name": s.name,
            "scan_template_id": str(s.scan_template_id) if s.scan_template_id else None,
            "target_assets": s.target_assets,
            "cron_expression": s.cron_expression,
            "is_active": s.is_active,
            "last_run_at": _to_iso(s.last_run_at),
            "next_run_at": _to_iso(s.next_run_at),
            "created_at": _to_iso(s.created_at),
            "updated_at": _to_iso(s.updated_at),
        })

    return _paginated_response(items, total, page, page_size)


@router.delete("/scans/schedules/{schedule_id}", dependencies=[Depends(RequireSOCManager)])
async def delete_scan_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    sch_id = uuid.UUID(schedule_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    q = select(ScanSchedule).where(and_(ScanSchedule.id == sch_id, ScanSchedule.tenant_id == tid))
    result = await db.execute(q)
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Scan schedule not found")

    await db.delete(schedule)
    await _audit(
        db,
        action="scan_schedule_deleted",
        resource_type="scan_schedule",
        resource_id=sch_id,
        tenant_id=tid,
        user_id=uid,
        details={"name": schedule.name},
    )
    await db.commit()

    return {"message": "Scan schedule deleted", "id": str(sch_id)}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MISCONFIGURATIONS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get("/misconfigurations", dependencies=[Depends(RequireComplianceOfficer)])
async def list_misconfigurations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    filtered = list(MISCONFIGURATIONS)

    if severity:
        filtered = [m for m in filtered if m["severity"] == severity]
    if category:
        filtered = [m for m in filtered if m.get("category", "").lower() == category.lower()]
    if search:
        search_lower = search.lower()
        filtered = [
            m for m in filtered
            if search_lower in m["name"].lower()
            or search_lower in m["description"].lower()
            or search_lower in m.get("category", "").lower()
        ]

    total = len(filtered)
    offset = (page - 1) * page_size
    paged = filtered[offset:offset + page_size]

    return _paginated_response(paged, total, page, page_size)


@router.get("/misconfigurations/{misconfig_id}", dependencies=[Depends(RequireComplianceOfficer)])
async def get_misconfiguration(misconfig_id: str):
    for m in MISCONFIGURATIONS:
        if m["id"] == misconfig_id:
            return m
    raise HTTPException(status_code=404, detail="Misconfiguration not found")


@router.post("/misconfigurations/{misconfig_id}/remediate", dependencies=[Depends(RequireComplianceOfficer)])
async def remediate_misconfiguration(
    misconfig_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    misconfig = None
    for m in MISCONFIGURATIONS:
        if m["id"] == misconfig_id:
            misconfig = m
            break

    if not misconfig:
        raise HTTPException(status_code=404, detail="Misconfiguration not found")

    now = datetime.now(timezone.utc)
    await _audit(
        db,
        action="misconfig_remediated",
        resource_type="misconfiguration",
        resource_id=uuid.uuid4(),
        tenant_id=tid,
        user_id=uid,
        details={
            "misconfig_id": misconfig_id,
            "name": misconfig["name"],
            "severity": misconfig["severity"],
            "remediation_script": misconfig.get("remediation_script"),
        },
    )
    await db.commit()

    remediation_steps = []
    if misconfig.get("remediation_script"):
        remediation_steps.append({
            "step": 1,
            "action": "Execute remediation script",
            "script": misconfig["remediation_script"],
            "description": f"Run the remediation command to fix: {misconfig['name']}",
        })
    remediation_steps.append({
        "step": len(remediation_steps) + 1,
        "action": "Verify remediation",
        "description": f"Re-scan to verify {misconfig['name']} has been resolved",
    })

    return {
        "misconfig_id": misconfig_id,
        "status": "remediated",
        "remediation_applied": True,
        "output": f"Remediation initiated at {_to_iso(now)}",
        "applied_at": _to_iso(now),
        "steps": remediation_steps,
        "name": misconfig["name"],
        "severity": misconfig["severity"],
        "expected_value": misconfig.get("expected_value"),
    }
