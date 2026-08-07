"""
AEGIS - Compliance API Router
Framework management, assessments, controls, evidence, policies, gaps, and remediation
"""
import json
import math
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    RequireComplianceOfficer,
    RequireSOCAnalyst,
    RequireSOCManager,
    get_current_user,
    require_tenant,
)
from app.core.database import get_db
from app.models import ComplianceAssessment, AuditLog

router = APIRouter()

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Enums
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AssessmentStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ARCHIVED = "archived"


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class GapSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    OVERDUE = "overdue"


class EvidenceType(str, Enum):
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    LOG = "log"
    CONFIG = "config"
    REPORT = "report"
    OTHER = "other"


class ExportFormat(str, Enum):
    PDF = "pdf"
    EXCEL = "excel"
    CSV = "csv"


class PolicyStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Common Response Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Framework Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class FrameworkDetail(BaseModel):
    id: str
    name: str
    abbreviation: str
    description: str
    version: str
    category: str
    total_controls: int
    total_requirements: int
    domains: List[Dict[str, Any]] = []
    last_updated: Optional[datetime] = None


class ControlItem(BaseModel):
    id: str
    control_id: str
    title: str
    description: str
    domain: Optional[str] = None
    subdomain: Optional[str] = None
    guidance: Optional[str] = None
    assessment_procedure: Optional[str] = None
    related_controls: List[str] = []
    mappings: Dict[str, List[str]] = {}
    risk_level: Optional[str] = None


class ControlDetail(ControlItem):
    evidence_required: List[str] = []
    remediation_guidance: Optional[str] = None
    references: List[str] = []
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Assessment Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AssessmentRequest(BaseModel):
    name: Optional[str] = Field(None, description="Assessment name")
    scope: Optional[str] = Field(None, description="Assessment scope description")
    assessor_id: Optional[str] = Field(None, description="User ID of lead assessor")
    target_date: Optional[datetime] = None
    include_controls: Optional[List[str]] = Field(None, description="Specific control IDs, omit for all")
    metadata: Optional[Dict[str, Any]] = None


class AssessmentResponse(BaseModel):
    id: str
    framework_id: str
    framework_name: str
    name: Optional[str] = None
    status: AssessmentStatus
    scope: Optional[str] = None
    assessor_id: Optional[str] = None
    assessor_name: Optional[str] = None
    target_date: Optional[datetime] = None
    total_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    partial_controls: int = 0
    not_assessed_controls: int = 0
    completion_percentage: float = 0.0
    overall_score: Optional[float] = None
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ControlAssessmentResult(BaseModel):
    control_id: str
    title: str
    domain: Optional[str] = None
    status: ControlStatus
    score: Optional[float] = None
    notes: Optional[str] = None
    evidence_count: int = 0
    assessed_by: Optional[str] = None
    assessed_at: Optional[datetime] = None


class ControlStatusUpdate(BaseModel):
    status: ControlStatus
    score: Optional[float] = Field(None, ge=0.0, le=100.0)
    notes: Optional[str] = Field(None, max_length=5000)
    evidence_ids: Optional[List[str]] = None


class EvidenceUpload(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    evidence_type: EvidenceType
    description: Optional[str] = Field(None, max_length=2000)
    control_ids: List[str] = Field(..., min_length=1)
    file_name: Optional[str] = None
    file_size_bytes: Optional[int] = Field(None, ge=0)
    content_type: Optional[str] = None
    storage_path: Optional[str] = None
    tags: List[str] = []
    metadata: Optional[Dict[str, Any]] = None


class EvidenceResponse(BaseModel):
    id: str
    name: str
    evidence_type: EvidenceType
    description: Optional[str] = None
    control_ids: List[str] = []
    file_name: Optional[str] = None
    file_size_bytes: Optional[int] = None
    content_type: Optional[str] = None
    storage_path: Optional[str] = None
    uploaded_by: Optional[str] = None
    tags: List[str] = []
    tenant_id: str
    created_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class ComplianceReport(BaseModel):
    assessment_id: str
    framework_name: str
    generated_at: datetime
    overall_score: float
    control_summary: Dict[str, int]
    domain_scores: Dict[str, float] = {}
    findings: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []


class ExportRequest(BaseModel):
    format: ExportFormat
    include_evidence: bool = True
    include_recommendations: bool = True
    sections: Optional[List[str]] = Field(None, description="Specific report sections to include")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Gap & Remediation Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class GapResponse(BaseModel):
    id: str
    assessment_id: str
    control_id: str
    control_title: Optional[str] = None
    framework_id: Optional[str] = None
    framework_name: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: GapSeverity
    status: str
    domain: Optional[str] = None
    detected_at: Optional[datetime] = None
    tenant_id: str


class RemediationPlanRequest(BaseModel):
    gap_id: str
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    assignee_id: Optional[str] = None
    priority: str = "medium"
    target_date: Optional[datetime] = None
    estimated_effort_hours: Optional[float] = Field(None, ge=0)
    steps: List[Dict[str, Any]] = []
    metadata: Optional[Dict[str, Any]] = None


class RemediationPlanResponse(BaseModel):
    id: str
    gap_id: str
    title: str
    description: Optional[str] = None
    assignee_id: Optional[str] = None
    assignee_name: Optional[str] = None
    priority: str
    status: RemediationStatus
    target_date: Optional[datetime] = None
    estimated_effort_hours: Optional[float] = None
    actual_effort_hours: Optional[float] = None
    steps: List[Dict[str, Any]] = []
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None


class RemediationUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=5000)
    status: Optional[RemediationStatus] = None
    assignee_id: Optional[str] = None
    priority: Optional[str] = None
    target_date: Optional[datetime] = None
    actual_effort_hours: Optional[float] = Field(None, ge=0)
    steps: Optional[List[Dict[str, Any]]] = None
    verification_notes: Optional[str] = None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Policy Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PolicyCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    policy_number: Optional[str] = Field(None, max_length=100)
    category: str = Field(..., description="e.g. security, privacy, acceptable_use")
    description: Optional[str] = Field(None, max_length=5000)
    content: str = Field(..., description="Policy document content")
    version: Optional[str] = "1.0"
    status: PolicyStatus = PolicyStatus.DRAFT
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    owner_id: Optional[str] = None
    framework_mappings: Dict[str, List[str]] = {}
    tags: List[str] = []
    metadata: Optional[Dict[str, Any]] = None


class PolicyResponse(BaseModel):
    id: str
    title: str
    policy_number: Optional[str] = None
    category: str
    description: Optional[str] = None
    content: Optional[str] = None
    version: str
    status: PolicyStatus
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    owner_id: Optional[str] = None
    framework_mappings: Dict[str, List[str]] = {}
    tags: List[str] = []
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_reviewed_at: Optional[datetime] = None
    last_reviewed_by: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class PolicyUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    policy_number: Optional[str] = Field(None, max_length=100)
    category: Optional[str] = None
    description: Optional[str] = Field(None, max_length=5000)
    content: Optional[str] = None
    version: Optional[str] = None
    status: Optional[PolicyStatus] = None
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    owner_id: Optional[str] = None
    framework_mappings: Optional[Dict[str, List[str]]] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class PolicyReviewResponse(BaseModel):
    policy_id: str
    policy_title: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    attestation: Optional[str] = None
    review_cycle: Optional[str] = None
    next_review_date: Optional[datetime] = None
    review_history: List[Dict[str, Any]] = []


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Dashboard Models
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ComplianceDashboardResponse(BaseModel):
    overall_score: float = 0.0
    framework_breakdown: List[Dict[str, Any]] = []
    control_pass_rate: float = 0.0
    total_controls: int = 0
    assessed_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    partial_controls: int = 0
    top_gaps: List[Dict[str, Any]] = []
    active_remediation_plans: int = 0
    overdue_remediation_plans: int = 0
    assessments_in_progress: int = 0
    trends: Dict[str, Any] = {}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Framework Data
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

FRAMEWORKS = {
    "pci_dss_v4": {
        "id": "pci_dss_v4",
        "name": "PCI DSS",
        "abbreviation": "PCI DSS",
        "description": "Payment Card Industry Data Security Standard v4.0 â€” protecting cardholder data through technical and operational controls.",
        "version": "4.0",
        "category": "regulatory",
        "domains": [
            {
                "domain_id": "req1",
                "name": "Requirement 1: Install and Maintain Network Security Controls",
                "controls": [
                    {"id": "pci-1.1", "title": "Network Security Controls (NSCs) defined and implemented", "description": "Define, document, and implement NSCs at all network boundaries between trusted and untrusted networks.", "category": "req1", "implementation_guidance": "Deploy and configure firewalls between CDE and untrusted networks."},
                    {"id": "pci-1.2", "title": "Network topology diagram maintained", "description": "Maintain an up-to-date network diagram documenting all connections between CDE and other networks.", "category": "req1", "implementation_guidance": "Review and update diagrams at least annually or upon significant changes."},
                    {"id": "pci-1.3", "title": "All NSC configurations reviewed every six months", "description": "Review firewall and router rule sets at least every six months.", "category": "req1", "implementation_guidance": "Document review process and retain evidence of review."},
                    {"id": "pci-1.4", "title": "No direct public access to CDE", "description": "Prohibit direct public access between the Internet and any system in the CDE.", "category": "req1", "implementation_guidance": "Implement DMZ or network segmentation."},
                    {"id": "pci-1.5", "title": "Personal firewall software on mobile devices", "description": "Ensure mobile/employee-owned devices with access to CDE have personal firewall software.", "category": "req1", "implementation_guidance": "Deploy host-based firewalls on all mobile endpoints."},
                ],
            },
            {
                "domain_id": "req2",
                "name": "Requirement 2: Apply Secure Configurations to All System Components",
                "controls": [
                    {"id": "pci-2.1", "title": "Secure configuration standards defined", "description": "Develop, document, and maintain secure configuration standards for all system components.", "category": "req2", "implementation_guidance": "Create hardening baselines aligned with CIS benchmarks."},
                    {"id": "pci-2.2", "title": "All unnecessary services disabled", "description": "Disable all unnecessary services, protocols, daemons, and functions.", "category": "req2", "implementation_guidance": "Perform service audits on all CDE systems and remove unused software."},
                    {"id": "pci-2.3", "title": "System security parameters configured", "description": "Configure system security parameters to prevent misuse.", "category": "req2", "implementation_guidance": "Use Group Policy, Ansible, or similar tools to enforce configurations."},
                    {"id": "pci-2.4", "title": "Security configuration monitoring", "description": "Implement automated mechanisms to monitor and alert on configuration drift.", "category": "req2", "implementation_guidance": "Deploy configuration monitoring tools such as AWS Config, Tripwire, or Chef InSpec."},
                ],
            },
            {
                "domain_id": "req3",
                "name": "Requirement 3: Protect Stored Account Data",
                "controls": [
                    {"id": "pci-3.1", "title": "Data retention and disposal policy", "description": "Define and implement policies for storage and secure deletion of cardholder data.", "category": "req3", "implementation_guidance": "Implement quarterly data discovery and purging process."},
                    {"id": "pci-3.2", "title": "Sensitive authentication data not stored after authorization", "description": "Do not store CVV, full track data, or PIN blocks post-authorization.", "category": "req3", "implementation_guidance": "Validate payment processing workflows strip sensitive data."},
                    {"id": "pci-3.3", "title": "PAN masked when displayed", "description": "Mask PAN such that only the first six and last four digits are visible.", "category": "req3", "implementation_guidance": "Enforce masking in all applications and reports."},
                    {"id": "pci-3.4", "title": "PAN rendered unreadable at rest", "description": "Render PAN unreadable using encryption, tokenization, or one-way hashing.", "category": "req3", "implementation_guidance": "Use AES-256 encryption or FPE tokenization for stored PAN."},
                    {"id": "pci-3.5", "title": "Cryptographic keys securely stored", "description": "Document and implement procedures to protect cryptographic keys.", "category": "req3", "implementation_guidance": "Use HSMs or key management services with split knowledge and dual control."},
                ],
            },
            {
                "domain_id": "req4",
                "name": "Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission",
                "controls": [
                    {"id": "pci-4.1", "title": "Strong cryptography for transmission over open networks", "description": "Use strong cryptography and security protocols to protect PAN during transmission over open, public networks.", "category": "req4", "implementation_guidance": "Enforce TLS 1.2+ for all payment data transmissions."},
                    {"id": "pci-4.2", "title": "Wireless transmissions encrypted", "description": "Encrypt PAN transmitted over end-user messaging technologies.", "category": "req4", "implementation_guidance": "Prohibit transmitting PAN via email, chat, SMS without encryption."},
                ],
            },
            {
                "domain_id": "req5",
                "name": "Requirement 5: Protect All Systems and Networks from Malicious Software",
                "controls": [
                    {"id": "pci-5.1", "title": "Anti-malware solution deployed", "description": "Deploy and maintain anti-malware solution(s) on all systems commonly affected by malicious software.", "category": "req5", "implementation_guidance": "Deploy EDR/XDR across all endpoints and servers."},
                    {"id": "pci-5.2", "title": "Anti-malware kept current and running", "description": "Ensure anti-malware mechanisms are kept current with automatic updates and active scanning.", "category": "req5", "implementation_guidance": "Centralized management console with auto-update policy."},
                    {"id": "pci-5.3", "title": "Anti-malware cannot be disabled by users", "description": "Ensure anti-malware solutions cannot be disabled or altered by end users.", "category": "req5", "implementation_guidance": "Use administrative controls preventing user modification."},
                ],
            },
            {
                "domain_id": "req6",
                "name": "Requirement 6: Develop and Maintain Secure Systems and Software",
                "controls": [
                    {"id": "pci-6.1", "title": "Security patches installed timely", "description": "Install applicable vendor-supplied security patches within one month of release.", "category": "req6", "implementation_guidance": "Implement automated patch management with risk-based SLAs."},
                    {"id": "pci-6.2", "title": "Secure software development lifecycle", "description": "Develop and maintain secure systems and applications following SDL practices.", "category": "req6", "implementation_guidance": "Integrate SAST, DAST, and SCA into CI/CD pipeline."},
                    {"id": "pci-6.3", "title": "Security vulnerabilities identified", "description": "Identify and rank new security vulnerabilities using a risk-based approach.", "category": "req6", "implementation_guidance": "Subscribe to vulnerability notification services and CVE databases."},
                    {"id": "pci-6.4", "title": "Change control procedures for all changes", "description": "Follow change control procedures for all changes to system components.", "category": "req6", "implementation_guidance": "Document and approve changes with backout plans."},
                    {"id": "pci-6.5", "title": "Web applications protected", "description": "Address common web application vulnerabilities through secure coding and WAF.", "category": "req6", "implementation_guidance": "Deploy WAF and perform annual penetration testing."},
                ],
            },
            {
                "domain_id": "req7",
                "name": "Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need-to-Know",
                "controls": [
                    {"id": "pci-7.1", "title": "Access control system for all system components", "description": "Limit access to system components and cardholder data to only those with a business need-to-know.", "category": "req7", "implementation_guidance": "Implement RBAC and document access justification."},
                    {"id": "pci-7.2", "title": "Access control system with deny-all default", "description": "Establish an access control system that denies all access unless explicitly authorized.", "category": "req7", "implementation_guidance": "Default-deny firewall and application access policies."},
                    {"id": "pci-7.3", "title": "Least privilege principle enforced", "description": "Ensure security policies and operational procedures follow least privilege.", "category": "req7", "implementation_guidance": "Regular access reviews and privilege audits."},
                ],
            },
            {
                "domain_id": "req8",
                "name": "Requirement 8: Identify Users and Authenticate Access to System Components",
                "controls": [
                    {"id": "pci-8.1", "title": "Unique user IDs assigned", "description": "Assign a unique ID to each person with access before allowing them to access system components or cardholder data.", "category": "req8", "implementation_guidance": "No shared/generic accounts in the CDE."},
                    {"id": "pci-8.2", "title": "User authentication methods", "description": "Secure authentication through proper user identity management and strong authentication.", "category": "req8", "implementation_guidance": "Enforce MFA for all CDE access, remote and non-console admin."},
                    {"id": "pci-8.3", "title": "Strong passwords required", "description": "Require strong passwords with minimum 12 characters, complexity, and expiration.", "category": "req8", "implementation_guidance": "Enforce password policies via IAM and directory services."},
                    {"id": "pci-8.4", "title": "MFA for all access into CDE", "description": "Multi-factor authentication is implemented for all access into the CDE.", "category": "req8", "implementation_guidance": "Deploy MFA solution for all users with CDE access."},
                    {"id": "pci-8.5", "title": "Group, shared, and generic accounts prohibited", "description": "Do not use group, shared, or generic IDs, passwords, or other authentication methods.", "category": "req8", "implementation_guidance": "Audit account inventory quarterly for shared accounts."},
                ],
            },
            {
                "domain_id": "req9",
                "name": "Requirement 9: Restrict Physical Access to Cardholder Data",
                "controls": [
                    {"id": "pci-9.1", "title": "Physical access controls implemented", "description": "Use appropriate facility entry controls to limit and monitor physical access to systems in the CDE.", "category": "req9", "implementation_guidance": "Badge readers, mantrap, CCTV at all CDE facility entrances."},
                    {"id": "pci-9.2", "title": "Physical access authorized and reviewed", "description": "Develop procedures to distinguish between onsite personnel and visitors.", "category": "req9", "implementation_guidance": "Visitor logbook, escort policy, badge differentiation."},
                ],
            },
            {
                "domain_id": "req10",
                "name": "Requirement 10: Log and Monitor All Access to System Components and Cardholder Data",
                "controls": [
                    {"id": "pci-10.1", "title": "Audit trails implemented", "description": "Implement audit trails to link all access to system components to individual users.", "category": "req10", "implementation_guidance": "Enable detailed audit logging on all CDE systems."},
                    {"id": "pci-10.2", "title": "Automated audit trails for system events", "description": "Implement automated audit trails for all system components to reconstruct events.", "category": "req10", "implementation_guidance": "Centralize logs to a SIEM with real-time correlation."},
                    {"id": "pci-10.3", "title": "Audit trail entries contain required fields", "description": "Record at minimum: user ID, type of event, date/time, success/failure, origination, identity of affected data/system.", "category": "req10", "implementation_guidance": "Standardize log format across all CDE components."},
                    {"id": "pci-10.4", "title": "Time synchronization for all systems", "description": "Use time-synchronization technology to synchronize system clocks.", "category": "req10", "implementation_guidance": "Deploy NTP with at least two internal time sources."},
                    {"id": "pci-10.5", "title": "Audit trail security", "description": "Secure audit trails so they cannot be altered.", "category": "req10", "implementation_guidance": "Immutable log storage, write-once media, or append-only log collectors."},
                    {"id": "pci-10.6", "title": "Log reviews performed daily", "description": "Review logs and security events for all system components daily.", "category": "req10", "implementation_guidance": "Automated alerting from SIEM with daily review by security team."},
                ],
            },
            {
                "domain_id": "req11",
                "name": "Requirement 11: Test Security of Systems and Networks Regularly",
                "controls": [
                    {"id": "pci-11.1", "title": "Wireless access points identified and tested", "description": "Test for the presence of wireless access points quarterly.", "category": "req11", "implementation_guidance": "Conduct quarterly WAP scans and rogue AP detection."},
                    {"id": "pci-11.2", "title": "Internal and external vulnerability scans", "description": "Run internal and external network vulnerability scans at least quarterly and after significant changes.", "category": "req11", "implementation_guidance": "Use ASV for external scans and authenticated scanning internally."},
                    {"id": "pci-11.3", "title": "Penetration testing performed annually", "description": "Perform external and internal penetration testing at least annually based on industry-accepted approaches.", "category": "req11", "implementation_guidance": "Engage qualified third-party pentesting firm annually."},
                    {"id": "pci-11.4", "title": "Intrusion detection/prevention techniques", "description": "Use intrusion-detection and/or intrusion-prevention techniques to detect and/or prevent intrusions.", "category": "req11", "implementation_guidance": "Deploy IDS/IPS at the network perimeter and critical internal points."},
                    {"id": "pci-11.5", "title": "Change detection on critical files", "description": "Deploy a change-detection mechanism to alert on unauthorized modification of critical system files.", "category": "req11", "implementation_guidance": "Install file integrity monitoring (FIM) on critical servers."},
                ],
            },
            {
                "domain_id": "req12",
                "name": "Requirement 12: Support Information Security with Organizational Policies and Programs",
                "controls": [
                    {"id": "pci-12.1", "title": "Comprehensive information security policy", "description": "Establish, publish, maintain, and disseminate a security policy.", "category": "req12", "implementation_guidance": "Annual policy review and employee acknowledgement."},
                    {"id": "pci-12.2", "title": "Risk assessment process implemented", "description": "Implement a risk assessment process performed at least annually.", "category": "req12", "implementation_guidance": "Formal risk assessment methodology with risk register."},
                    {"id": "pci-12.3", "title": "Security awareness training", "description": "Implement a formal security awareness program for all personnel.", "category": "req12", "implementation_guidance": "Annual security training with phishing simulations."},
                    {"id": "pci-12.4", "title": "Third-party service provider management", "description": "Manage and monitor all third-party service providers with access to cardholder data.", "category": "req12", "implementation_guidance": "Annual TPSP due diligence and compliance attestations."},
                    {"id": "pci-12.5", "title": "Incident response plan tested", "description": "Establish and maintain an incident response plan, tested at least annually.", "category": "req12", "implementation_guidance": "Conduct annual tabletop exercises and update IR plan."},
                ],
            },
        ],
    },
    "soc2": {
        "id": "soc2",
        "name": "SOC 2",
        "abbreviation": "SOC 2",
        "description": "System and Organization Controls 2 â€” Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy.",
        "version": "2022",
        "category": "audit",
        "domains": [
            {
                "domain_id": "cc1",
                "name": "CC1: Control Environment",
                "controls": [
                    {"id": "soc2-cc1.1", "title": "Integrity and ethical values demonstrated", "description": "The board and management demonstrate a commitment to integrity and ethical values.", "category": "cc1", "implementation_guidance": "Code of conduct, ethics hotline, tone from the top."},
                    {"id": "soc2-cc1.2", "title": "Board independence and oversight", "description": "Board of directors demonstrates independence from management and exercises oversight.", "category": "cc1", "implementation_guidance": "Independent board members, regular risk review meetings."},
                    {"id": "soc2-cc1.3", "title": "Organizational structure and authority", "description": "Management establishes structures and reporting lines to achieve objectives.", "category": "cc1", "implementation_guidance": "Clear org chart, defined roles and responsibilities."},
                    {"id": "soc2-cc1.4", "title": "Commitment to competence", "description": "Demonstrates commitment to attract, develop, and retain competent individuals.", "category": "cc1", "implementation_guidance": "Job descriptions, training programs, performance reviews."},
                    {"id": "soc2-cc1.5", "title": "Accountability established", "description": "Individuals are held accountable for their internal control responsibilities.", "category": "cc1", "implementation_guidance": "Performance metrics tied to security objectives."},
                ],
            },
            {
                "domain_id": "cc2",
                "name": "CC2: Communication and Information",
                "controls": [
                    {"id": "soc2-cc2.1", "title": "Internal communication of information", "description": "Internal communication supporting internal control functioning.", "category": "cc2", "implementation_guidance": "Regular security bulletins, Slack channels, intranet."},
                    {"id": "soc2-cc2.2", "title": "External communication of information", "description": "Communicating with external parties regarding matters affecting internal controls.", "category": "cc2", "implementation_guidance": "Vendor risk assessments, customer security portals."},
                ],
            },
            {
                "domain_id": "cc3",
                "name": "CC3: Risk Assessment",
                "controls": [
                    {"id": "soc2-cc3.1", "title": "Risk identification process", "description": "Specifies objectives with sufficient clarity to identify and assess risks.", "category": "cc3", "implementation_guidance": "Annual risk assessment workshop with stakeholders."},
                    {"id": "soc2-cc3.2", "title": "Fraud risk assessment", "description": "Considers the potential for fraud in assessing risks.", "category": "cc3", "implementation_guidance": "Fraud risk matrix, segregation of duties."},
                    {"id": "soc2-cc3.3", "title": "Risk response", "description": "Identifies and assesses changes that could significantly impact internal controls.", "category": "cc3", "implementation_guidance": "Change management process with risk impact assessment."},
                ],
            },
            {
                "domain_id": "cc4",
                "name": "CC4: Monitoring Activities",
                "controls": [
                    {"id": "soc2-cc4.1", "title": "Ongoing monitoring", "description": "Selects, develops and performs ongoing evaluations of controls.", "category": "cc4", "implementation_guidance": "Continuous control monitoring with automated testing."},
                    {"id": "soc2-cc4.2", "title": "Control deficiency communication", "description": "Communicates control deficiencies timely to responsible parties.", "category": "cc4", "implementation_guidance": "Deficiency escalation matrix and tracking system."},
                ],
            },
            {
                "domain_id": "cc5",
                "name": "CC5: Control Activities",
                "controls": [
                    {"id": "soc2-cc5.1", "title": "Control activities selection and development", "description": "Selects and develops control activities", "category": "cc5", "implementation_guidance": "Control framework mapping (NIST, CIS), control matrix documentation."},
                    {"id": "soc2-cc5.2", "title": "Technology general controls", "description": "Selects and develops general control activities over technology.", "category": "cc5", "implementation_guidance": "Access reviews, change management, backup testing."},
                    {"id": "soc2-cc5.3", "title": "Policies and procedures deployed", "description": "Deploys control activities through policies and procedures.", "category": "cc5", "implementation_guidance": "Policy management lifecycle, acknowledgment tracking."},
                ],
            },
            {
                "domain_id": "security",
                "name": "Security (Common Criteria)",
                "controls": [
                    {"id": "soc2-sec-1", "title": "Logical and physical access controls", "description": "Logical and physical access is restricted to authorized users.", "category": "security", "implementation_guidance": "RBAC, MFA, biometric physical access."},
                    {"id": "soc2-sec-2", "title": "System operations managed", "description": "System operations are monitored and managed.", "category": "security", "implementation_guidance": "24x7 SOC, alerting, incident management."},
                    {"id": "soc2-sec-3", "title": "Change management", "description": "Changes to infrastructure, data, and software are authorized and tested.", "category": "security", "implementation_guidance": "Formal change advisory board, CAB process."},
                    {"id": "soc2-sec-4", "title": "Risk mitigation implemented", "description": "Risks are identified and mitigated.", "category": "security", "implementation_guidance": "Risk register with ownership and remediation tracking."},
                ],
            },
            {
                "domain_id": "availability",
                "name": "Availability (Additional Criteria)",
                "controls": [
                    {"id": "soc2-avail-1", "title": "Availability monitoring", "description": "System availability is monitored and maintained.", "category": "availability", "implementation_guidance": "Uptime monitoring, SLA tracking, incident response."},
                    {"id": "soc2-avail-2", "title": "Disaster recovery and business continuity", "description": "DR/BCP plans are in place and tested.", "category": "availability", "implementation_guidance": "Annual DR test, RPO/RTO defined and validated."},
                    {"id": "soc2-avail-3", "title": "Capacity management", "description": "System capacity is monitored and planned.", "category": "availability", "implementation_guidance": "Capacity forecasting, auto-scaling, load testing."},
                ],
            },
            {
                "domain_id": "confidentiality",
                "name": "Confidentiality (Additional Criteria)",
                "controls": [
                    {"id": "soc2-conf-1", "title": "Confidential information identification", "description": "Confidential information is identified and classified.", "category": "confidentiality", "implementation_guidance": "Data classification policy, labeling, DLP."},
                    {"id": "soc2-conf-2", "title": "Confidential information protection", "description": "Confidential information is protected through encryption and access controls.", "category": "confidentiality", "implementation_guidance": "Encryption at rest and in transit, data loss prevention."},
                    {"id": "soc2-conf-3", "title": "Confidential information disposal", "description": "Confidential information is securely disposed when no longer needed.", "category": "confidentiality", "implementation_guidance": "Media sanitization, secure document shredding."},
                ],
            },
            {
                "domain_id": "processing_integrity",
                "name": "Processing Integrity (Additional Criteria)",
                "controls": [
                    {"id": "soc2-pi-1", "title": "Processing inputs are complete and accurate", "description": "Inputs to the system are complete, accurate, and authorized.", "category": "processing_integrity", "implementation_guidance": "Input validation, data quality checks."},
                    {"id": "soc2-pi-2", "title": "Processing is complete and accurate", "description": "Processing is complete, accurate, and timely.", "category": "processing_integrity", "implementation_guidance": "Process monitoring, error handling, reconciliation."},
                    {"id": "soc2-pi-3", "title": "Outputs are complete and accurate", "description": "Outputs are complete, accurate, and distributed appropriately.", "category": "processing_integrity", "implementation_guidance": "Output validation, access controls on reports."},
                ],
            },
            {
                "domain_id": "privacy",
                "name": "Privacy (Additional Criteria)",
                "controls": [
                    {"id": "soc2-priv-1", "title": "Privacy notice communicated", "description": "Privacy notice is provided to data subjects.", "category": "privacy", "implementation_guidance": "Privacy policy on website, consent management."},
                    {"id": "soc2-priv-2", "title": "Choice and consent", "description": "Data subject choices regarding their information are communicated and respected.", "category": "privacy", "implementation_guidance": "Cookie consent, opt-in/opt-out mechanisms."},
                    {"id": "soc2-priv-3", "title": "Collection of personal information", "description": "Collection is limited to identified purposes.", "category": "privacy", "implementation_guidance": "Data minimization, purpose specification."},
                ],
            },
        ],
    },
    "iso27001": {
        "id": "iso27001",
        "name": "ISO 27001:2022",
        "abbreviation": "ISO 27001",
        "description": "ISO/IEC 27001:2022 Information Security Management System â€” internationally recognized standard for information security management.",
        "version": "2022",
        "category": "framework",
        "domains": [
            {
                "domain_id": "a5",
                "name": "A.5 Organizational Controls",
                "controls": [
                    {"id": "iso-a5.1", "title": "Policies for information security", "description": "A set of policies for information security shall be defined, approved, published, and communicated.", "category": "a5", "implementation_guidance": "ISMS policy suite covering all domains."},
                    {"id": "iso-a5.2", "title": "Information security roles and responsibilities", "description": "Information security roles and responsibilities shall be defined and allocated.", "category": "a5", "implementation_guidance": "Defined RACI matrix for security functions."},
                    {"id": "iso-a5.3", "title": "Segregation of duties", "description": "Conflicting duties and conflicting areas of responsibility shall be segregated.", "category": "a5", "implementation_guidance": "No single person controls all stages of a sensitive process."},
                    {"id": "iso-a5.4", "title": "Management responsibilities", "description": "Management shall require all personnel to apply information security.", "category": "a5", "implementation_guidance": "Annual security objective setting and review."},
                ],
            },
            {
                "domain_id": "a6",
                "name": "A.6 People Controls",
                "controls": [
                    {"id": "iso-a6.1", "title": "Screening", "description": "Background verification checks on all candidates shall be carried out.", "category": "a6", "implementation_guidance": "Pre-employment checks per local laws."},
                    {"id": "iso-a6.2", "title": "Terms and conditions of employment", "description": "Contracts shall state personnel and organization responsibilities.", "category": "a6", "implementation_guidance": "Confidentiality and security clauses in contracts."},
                    {"id": "iso-a6.3", "title": "Information security awareness, education and training", "description": "Personnel shall receive appropriate awareness education and training.", "category": "a6", "implementation_guidance": "Annual security awareness training program."},
                ],
            },
            {
                "domain_id": "a7",
                "name": "A.7 Physical Controls",
                "controls": [
                    {"id": "iso-a7.1", "title": "Physical security perimeter", "description": "Security perimeters shall be defined and used to protect areas.", "category": "a7", "implementation_guidance": "Fencing, walls, card access at facility boundaries."},
                    {"id": "iso-a7.2", "title": "Physical entry controls", "description": "Secure areas shall be protected by appropriate entry controls.", "category": "a7", "implementation_guidance": "Badge access, mantrap, visitor management."},
                    {"id": "iso-a7.3", "title": "Securing offices, rooms and facilities", "description": "Physical security for offices, rooms, and facilities shall be designed and implemented.", "category": "a7", "implementation_guidance": "Locked server rooms, camera surveillance."},
                ],
            },
            {
                "domain_id": "a8",
                "name": "A.8 Technological Controls",
                "controls": [
                    {"id": "iso-a8.1", "title": "User endpoint devices", "description": "Rules for acceptable use of endpoint devices shall be defined.", "category": "a8", "implementation_guidance": "MDM for mobile, endpoint hardening standards."},
                    {"id": "iso-a8.2", "title": "Privileged access rights", "description": "The allocation and use of privileged access rights shall be restricted and managed.", "category": "a8", "implementation_guidance": "PAM solution, just-in-time access."},
                    {"id": "iso-a8.3", "title": "Information access restriction", "description": "Access to information shall be restricted in accordance with access control policy.", "category": "a8", "implementation_guidance": "RBAC, ABAC policies."},
                    {"id": "iso-a8.4", "title": "Access to source code", "description": "Read and write access to source code shall be restricted.", "category": "a8", "implementation_guidance": "Code repository access controls, branch restrictions."},
                    {"id": "iso-a8.5", "title": "Secure authentication", "description": "Secure authentication technologies and procedures shall be implemented.", "category": "a8", "implementation_guidance": "MFA, passwordless, FIDO2."},
                    {"id": "iso-a8.6", "title": "Capacity management", "description": "The use of resources shall be monitored, tuned, and projections made of future capacity.", "category": "a8", "implementation_guidance": "Capacity dashboards with alert thresholds."},
                    {"id": "iso-a8.7", "title": "Protection against malware", "description": "Protection against malware shall be implemented.", "category": "a8", "implementation_guidance": "EDR/XDR with central management."},
                    {"id": "iso-a8.8", "title": "Management of technical vulnerabilities", "description": "Information about technical vulnerabilities shall be obtained and evaluated.", "category": "a8", "implementation_guidance": "Vulnerability management process with SLAs."},
                    {"id": "iso-a8.9", "title": "Configuration management", "description": "Configurations of hardware, software, services and networks shall be established and maintained.", "category": "a8", "implementation_guidance": "IaC, configuration drift detection."},
                ],
            },
        ],
    },
    "nist_csf": {
        "id": "nist_csf",
        "name": "NIST Cybersecurity Framework 2.0",
        "abbreviation": "NIST CSF 2.0",
        "description": "NIST Cybersecurity Framework 2.0 â€” a comprehensive framework for managing and reducing cybersecurity risk.",
        "version": "2.0",
        "category": "framework",
        "domains": [
            {
                "domain_id": "govern",
                "name": "GOVERN (GV): Organizational Context",
                "controls": [
                    {"id": "nist-gv.oc-01", "title": "Organizational mission understood", "description": "The organization's mission, stakeholder expectations, and internal/external context are understood.", "category": "govern", "implementation_guidance": "Document business objectives and cybersecurity alignment."},
                    {"id": "nist-gv.oc-02", "title": "Internal and external context assessed", "description": "Internal and external factors influencing cybersecurity risk management are assessed.", "category": "govern", "implementation_guidance": "PESTLE analysis, threat landscape assessment."},
                    {"id": "nist-gv.rm-01", "title": "Risk management strategy established", "description": "Risk management objectives, risk appetite, and risk tolerance are established.", "category": "govern", "implementation_guidance": "Board-approved risk appetite statement."},
                    {"id": "nist-gv.rm-02", "title": "Risk management roles defined", "description": "Cybersecurity roles and responsibilities are established and communicated.", "category": "govern", "implementation_guidance": "CISO charter, IR team roles defined."},
                    {"id": "nist-gv.sc-01", "title": "Supply chain risk program", "description": "Cybersecurity supply chain risk management program is established.", "category": "govern", "implementation_guidance": "Third-party risk tiering and due diligence."},
                ],
            },
            {
                "domain_id": "identify",
                "name": "IDENTIFY (ID): Asset Management and Risk Assessment",
                "controls": [
                    {"id": "nist-id.am-01", "title": "Asset inventory maintained", "description": "Physical and software assets are inventoried and managed.", "category": "identify", "implementation_guidance": "CMDB and automated asset discovery."},
                    {"id": "nist-id.am-02", "title": "Software inventory maintained", "description": "Software within the organization is inventoried.", "category": "identify", "implementation_guidance": "Authorized software list, application catalog."},
                    {"id": "nist-id.am-03", "title": "Data flows mapped", "description": "Organizational communication and data flows are mapped.", "category": "identify", "implementation_guidance": "Data flow diagrams for all critical applications."},
                    {"id": "nist-id.ra-01", "title": "Vulnerabilities identified", "description": "Asset vulnerabilities are identified and documented.", "category": "identify", "implementation_guidance": "Regular vulnerability scanning and CVE monitoring."},
                    {"id": "nist-id.ra-04", "title": "Threats identified", "description": "Threats, both internal and external, are identified and documented.", "category": "identify", "implementation_guidance": "Threat intelligence program, MITRE ATT&CK mapping."},
                ],
            },
            {
                "domain_id": "protect",
                "name": "PROTECT (PR): Safeguards",
                "controls": [
                    {"id": "nist-pr.aa-01", "title": "Identity management", "description": "Identities and credentials are issued, managed, verified, revoked, and audited.", "category": "protect", "implementation_guidance": "IGA solution with lifecycle management."},
                    {"id": "nist-pr.aa-02", "title": "Access permissions managed", "description": "Access permissions, entitlements, and authorizations are managed.", "category": "protect", "implementation_guidance": "Periodic access reviews, RBAC enforcement."},
                    {"id": "nist-pr.ds-01", "title": "Data-at-rest protection", "description": "Data at rest is protected.", "category": "protect", "implementation_guidance": "Full disk encryption, database encryption."},
                    {"id": "nist-pr.ds-02", "title": "Data-in-transit protection", "description": "Data in transit is protected.", "category": "protect", "implementation_guidance": "TLS 1.3, IPSec VPNs."},
                    {"id": "nist-pr.ma-01", "title": "Baseline configurations maintained", "description": "Baseline configurations are created, maintained, and monitored.", "category": "protect", "implementation_guidance": "Golden images, configuration baselines."},
                ],
            },
            {
                "domain_id": "detect",
                "name": "DETECT (DE): Continuous Monitoring",
                "controls": [
                    {"id": "nist-de.cm-01", "title": "Network monitored", "description": "Networks and network services are monitored.", "category": "detect", "implementation_guidance": "NIDS, NetFlow analysis, 24x7 SOC."},
                    {"id": "nist-de.cm-02", "title": "Physical environment monitored", "description": "Physical environment is monitored.", "category": "detect", "implementation_guidance": "CCTV, environmental sensors for server rooms."},
                    {"id": "nist-de.cm-03", "title": "Personnel activity monitored", "description": "Personnel activity is monitored.", "category": "detect", "implementation_guidance": "UEBA for insider threat detection."},
                    {"id": "nist-de.cm-06", "title": "External service providers monitored", "description": "External service provider activities are monitored.", "category": "detect", "implementation_guidance": "API access logs, vendor activity baselining."},
                    {"id": "nist-de.ae-02", "title": "Adverse events analyzed", "description": "Potentially adverse events are analyzed to better understand associated activities.", "category": "detect", "implementation_guidance": "SIEM correlation rules, threat hunting."},
                ],
            },
            {
                "domain_id": "respond",
                "name": "RESPOND (RS): Incident Response",
                "controls": [
                    {"id": "nist-rs.ma-01", "title": "Incident response plan executed", "description": "Incident response plan is executed during or after an incident.", "category": "respond", "implementation_guidance": "Documented playbooks, on-call rotation."},
                    {"id": "nist-rs.ma-02", "title": "Incident reported", "description": "Incidents are reported consistent with applicable criteria.", "category": "respond", "implementation_guidance": "Regulatory breach notification timelines."},
                    {"id": "nist-rs.an-01", "title": "Incident investigated", "description": "Incidents are investigated.", "category": "respond", "implementation_guidance": "Digital forensics procedures and chain of custody."},
                    {"id": "nist-rs.mi-01", "title": "Incident contained", "description": "Incidents are contained.", "category": "respond", "implementation_guidance": "Isolation procedures, network segmentation."},
                ],
            },
            {
                "domain_id": "recover",
                "name": "RECOVER (RC): Recovery",
                "controls": [
                    {"id": "nist-rc.rp-01", "title": "Recovery plan executed", "description": "Recovery portion of incident response plan is executed.", "category": "recover", "implementation_guidance": "System restoration from known-good backups."},
                    {"id": "nist-rc.co-01", "title": "Public relations managed", "description": "Public relations are managed.", "category": "recover", "implementation_guidance": "Crisis communication plan, PR counsel."},
                    {"id": "nist-rc.co-02", "title": "Reputation repaired", "description": "Reputation after an incident is repaired.", "category": "recover", "implementation_guidance": "Post-incident communication plan."},
                    {"id": "nist-rc.im-01", "title": "Recovery lessons learned", "description": "Lessons learned from recovery are applied.", "category": "recover", "implementation_guidance": "Post-mortem, after-action review process."},
                ],
            },
        ],
    },
    "hipaa": {
        "id": "hipaa",
        "name": "HIPAA Security Rule",
        "abbreviation": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act Security Rule â€” safeguards for protecting electronic protected health information (ePHI).",
        "version": "2013 Omnibus",
        "category": "regulatory",
        "domains": [
            {
                "domain_id": "admin_safeguards",
                "name": "Administrative Safeguards",
                "controls": [
                    {"id": "hipaa-ar", "title": "Security management process", "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations.", "category": "administrative", "implementation_guidance": "Risk analysis, risk management plan, sanction policy."},
                    {"id": "hipaa-ao", "title": "Assigned security responsibility", "description": "Identify the security official responsible for HIPAA Security Rule compliance.", "category": "administrative", "implementation_guidance": "Designate a Security Officer with documented responsibilities."},
                    {"id": "hipaa-aw", "title": "Workforce security", "description": "Implement procedures to ensure appropriate workforce access to ePHI.", "category": "administrative", "implementation_guidance": "Authorization, clearance, termination procedures."},
                    {"id": "hipaa-ia", "title": "Information access management", "description": "Authorize access to ePHI based on role or function.", "category": "administrative", "implementation_guidance": "Minimum necessary access, role-based access control."},
                    {"id": "hipaa-sat", "title": "Security awareness and training", "description": "Implement a security awareness and training program for all workforce members.", "category": "administrative", "implementation_guidance": "Annual security training, phishing awareness, login monitoring."},
                    {"id": "hipaa-si", "title": "Security incident procedures", "description": "Implement policies and procedures to address security incidents.", "category": "administrative", "implementation_guidance": "Incident response plan, breach notification process."},
                    {"id": "hipaa-cp", "title": "Contingency plan", "description": "Establish and implement policies for responding to emergencies damaging ePHI.", "category": "administrative", "implementation_guidance": "Data backup, disaster recovery, emergency mode operation plans."},
                    {"id": "hipaa-eval", "title": "Evaluation", "description": "Perform periodic technical and non-technical evaluations.", "category": "administrative", "implementation_guidance": "Annual security assessment, penetration testing."},
                ],
            },
            {
                "domain_id": "physical_safeguards",
                "name": "Physical Safeguards",
                "controls": [
                    {"id": "hipaa-fac", "title": "Facility access controls", "description": "Implement policies to limit physical access to electronic information systems.", "category": "physical", "implementation_guidance": "Badge access, CCTV, visitor logs, contingency operations."},
                    {"id": "hipaa-ws", "title": "Workstation use and security", "description": "Implement policies and procedures to specify proper functions and physical attributes of workstations.", "category": "physical", "implementation_guidance": "Screen locks, clean desk policy, workstation positioning."},
                    {"id": "hipaa-dm", "title": "Device and media controls", "description": "Implement policies for receipt and removal of hardware and electronic media.", "category": "physical", "implementation_guidance": "Asset disposal, media sanitization, data backup."},
                ],
            },
            {
                "domain_id": "technical_safeguards",
                "name": "Technical Safeguards",
                "controls": [
                    {"id": "hipaa-ac", "title": "Access control", "description": "Implement technical policies and procedures for electronic information systems.", "category": "technical", "implementation_guidance": "Unique user ID, emergency access, automatic logoff, encryption/decryption."},
                    {"id": "hipaa-au", "title": "Audit controls", "description": "Implement hardware, software, and/or procedural mechanisms that record and examine activity.", "category": "technical", "implementation_guidance": "Audit logs, SIEM, access reviews."},
                    {"id": "hipaa-int", "title": "Integrity", "description": "Implement policies and procedures to protect ePHI from improper alteration or destruction.", "category": "technical", "implementation_guidance": "File integrity monitoring, checksums."},
                    {"id": "hipaa-at", "title": "Person or entity authentication", "description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.", "category": "technical", "implementation_guidance": "MFA, strong passwords, biometric verification."},
                    {"id": "hipaa-tx", "title": "Transmission security", "description": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic network.", "category": "technical", "implementation_guidance": "TLS encryption, integrity controls for transmission."},
                ],
            },
        ],
    },
    "gdpr": {
        "id": "gdpr",
        "name": "GDPR",
        "abbreviation": "GDPR",
        "description": "General Data Protection Regulation â€” EU regulation on data protection and privacy for individuals within the EU/EEA.",
        "version": "2018",
        "category": "regulatory",
        "domains": [
            {
                "domain_id": "principles",
                "name": "Data Protection Principles",
                "controls": [
                    {"id": "gdpr-prin-1", "title": "Lawfulness, fairness, transparency", "description": "Personal data shall be processed lawfully, fairly, and transparently.", "category": "principles", "implementation_guidance": "Legal basis documentation, privacy notices."},
                    {"id": "gdpr-prin-2", "title": "Purpose limitation", "description": "Personal data collected for specified, explicit, and legitimate purposes.", "category": "principles", "implementation_guidance": "Purpose specification in privacy notices, compatibility assessment."},
                    {"id": "gdpr-prin-3", "title": "Data minimization", "description": "Personal data adequate, relevant, and limited to what is necessary.", "category": "principles", "implementation_guidance": "Data field review, collection limitation."},
                    {"id": "gdpr-prin-4", "title": "Accuracy", "description": "Personal data accurate and kept up to date.", "category": "principles", "implementation_guidance": "Data quality processes, rectification procedures."},
                    {"id": "gdpr-prin-5", "title": "Storage limitation", "description": "Personal data kept no longer than necessary.", "category": "principles", "implementation_guidance": "Data retention schedules, automated purging."},
                    {"id": "gdpr-prin-6", "title": "Integrity and confidentiality", "description": "Appropriate security of personal data against unauthorized/unlawful processing.", "category": "principles", "implementation_guidance": "Encryption, pseudonymization, access controls."},
                ],
            },
            {
                "domain_id": "rights",
                "name": "Data Subject Rights",
                "controls": [
                    {"id": "gdpr-right-1", "title": "Right to be informed", "description": "Data subjects informed about processing of their personal data.", "category": "rights", "implementation_guidance": "Privacy policy, just-in-time notices."},
                    {"id": "gdpr-right-2", "title": "Right of access", "description": "Data subjects can access their personal data and supplementary information.", "category": "rights", "implementation_guidance": "DSAR portal, identity verification process."},
                    {"id": "gdpr-right-3", "title": "Right to rectification", "description": "Data subjects can have inaccurate personal data rectified.", "category": "rights", "implementation_guidance": "Data update procedures, self-service portals."},
                    {"id": "gdpr-right-4", "title": "Right to erasure", "description": "Data subjects can have personal data erased under certain circumstances.", "category": "rights", "implementation_guidance": "Data deletion workflows, backup considerations."},
                    {"id": "gdpr-right-5", "title": "Right to data portability", "description": "Data subjects can receive personal data in a structured, commonly used format.", "category": "rights", "implementation_guidance": "Export functionality, JSON/CSV formats."},
                    {"id": "gdpr-right-6", "title": "Right to object", "description": "Data subjects can object to processing based on legitimate interests or direct marketing.", "category": "rights", "implementation_guidance": "Opt-out mechanisms, objection handling."},
                ],
            },
            {
                "domain_id": "obligations",
                "name": "Controller Obligations",
                "controls": [
                    {"id": "gdpr-oblig-1", "title": "Data Protection Officer appointment", "description": "Appoint a DPO where required.", "category": "obligations", "implementation_guidance": "DPO role definition and independence assurance."},
                    {"id": "gdpr-oblig-2", "title": "Data Protection Impact Assessments", "description": "Conduct DPIAs for high-risk processing.", "category": "obligations", "implementation_guidance": "DPIA template, risk assessment methodology."},
                    {"id": "gdpr-oblig-3", "title": "Data breach notification", "description": "Notify supervisory authority within 72 hours of breach discovery.", "category": "obligations", "implementation_guidance": "Breach detection, notification procedures, documentation."},
                    {"id": "gdpr-oblig-4", "title": "Data Processing Agreements", "description": "DPAs in place with all data processors.", "category": "obligations", "implementation_guidance": "Standard contractual clauses, processor assessment."},
                    {"id": "gdpr-oblig-5", "title": "Records of processing activities", "description": "Maintain records of all processing activities.", "category": "obligations", "implementation_guidance": "Data inventory, processing register."},
                ],
            },
        ],
    },
    "cis_v8": {
        "id": "cis_v8",
        "name": "CIS Critical Security Controls v8",
        "abbreviation": "CIS Controls v8",
        "description": "Center for Internet Security Critical Security Controls v8 â€” prioritized set of actions to protect organizations from cyber threats.",
        "version": "8.1",
        "category": "best_practice",
        "domains": [
            {
                "domain_id": "ig1",
                "name": "Implementation Group 1 (Basic Cyber Hygiene)",
                "controls": [
                    {"id": "cis-1", "title": "Inventory and Control of Enterprise Assets", "description": "Actively manage all enterprise assets connected to the infrastructure.", "category": "ig1", "implementation_guidance": "Asset discovery, CMDB, endpoint management."},
                    {"id": "cis-2", "title": "Inventory and Control of Software Assets", "description": "Actively manage all software on the network.", "category": "ig1", "implementation_guidance": "Authorized software list, application whitelisting."},
                    {"id": "cis-3", "title": "Data Protection", "description": "Develop processes and technical controls to identify, classify, and secure data.", "category": "ig1", "implementation_guidance": "Data classification, DLP, encryption."},
                    {"id": "cis-4", "title": "Secure Configuration of Enterprise Assets and Software", "description": "Establish and maintain secure configurations for enterprise assets.", "category": "ig1", "implementation_guidance": "CIS Benchmarks, configuration management."},
                    {"id": "cis-5", "title": "Account Management", "description": "Use processes and tools to assign and manage authorization to credentials.", "category": "ig1", "implementation_guidance": "IAM, account lifecycle, access reviews."},
                    {"id": "cis-6", "title": "Access Control Management", "description": "Use processes and tools to create, assign, manage, and revoke access credentials and privileges.", "category": "ig1", "implementation_guidance": "RBAC, PAM, just-in-time access."},
                ],
            },
            {
                "domain_id": "ig2",
                "name": "Implementation Group 2 (Intermediate)",
                "controls": [
                    {"id": "cis-7", "title": "Continuous Vulnerability Management", "description": "Continuously acquire, assess, and act on vulnerability information.", "category": "ig2", "implementation_guidance": "Automated vulnerability scanning, patch management."},
                    {"id": "cis-8", "title": "Audit Log Management", "description": "Collect, alert, review, and retain audit logs of events.", "category": "ig2", "implementation_guidance": "Centralized logging, SIEM, log retention."},
                    {"id": "cis-9", "title": "Email and Web Browser Protections", "description": "Improve protections and detections of threats from email and web vectors.", "category": "ig2", "implementation_guidance": "Email security gateway, browser isolation."},
                    {"id": "cis-10", "title": "Malware Defenses", "description": "Prevent or control the installation, spread, and execution of malware.", "category": "ig2", "implementation_guidance": "EDR/XDR, anti-malware with centralized management."},
                    {"id": "cis-11", "title": "Data Recovery", "description": "Establish and maintain data recovery practices.", "category": "ig2", "implementation_guidance": "Backups, recovery testing, RPO/RTO."},
                    {"id": "cis-12", "title": "Network Infrastructure Management", "description": "Establish, implement, and actively manage network devices.", "category": "ig2", "implementation_guidance": "Network segmentation, device hardening."},
                ],
            },
            {
                "domain_id": "ig3",
                "name": "Implementation Group 3 (Advanced)",
                "controls": [
                    {"id": "cis-13", "title": "Network Monitoring and Defense", "description": "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense.", "category": "ig3", "implementation_guidance": "NIDS, NetFlow, threat intelligence."},
                    {"id": "cis-14", "title": "Security Awareness and Skills Training", "description": "Establish and maintain a security awareness program.", "category": "ig3", "implementation_guidance": "Security training, phishing simulations."},
                    {"id": "cis-15", "title": "Service Provider Management", "description": "Develop a process to evaluate service providers.", "category": "ig3", "implementation_guidance": "TPRM, SLA monitoring, compliance attestation."},
                    {"id": "cis-16", "title": "Application Software Security", "description": "Manage the security life cycle of software.", "category": "ig3", "implementation_guidance": "SAST/DAST, secure SDLC, WAF."},
                    {"id": "cis-17", "title": "Incident Response Management", "description": "Establish a program to develop and maintain an incident response capability.", "category": "ig3", "implementation_guidance": "IR plan, tabletop exercises, playbooks."},
                    {"id": "cis-18", "title": "Penetration Testing", "description": "Test the effectiveness and resiliency of enterprise assets.", "category": "ig3", "implementation_guidance": "External and internal pentesting, red team exercises."},
                ],
            },
        ],
    },
}


def _build_framework_detail(framework_data: dict) -> dict:
    total_controls = sum(len(d["controls"]) for d in framework_data["domains"])
    return {
        "id": framework_data["id"],
        "name": framework_data["name"],
        "abbreviation": framework_data["abbreviation"],
        "description": framework_data["description"],
        "version": framework_data["version"],
        "category": framework_data["category"],
        "total_controls": total_controls,
        "total_requirements": len(framework_data["domains"]),
        "domains": [
            {
                "domain_id": d["domain_id"],
                "name": d["name"],
                "control_count": len(d["controls"]),
                "controls": d["controls"],
            }
            for d in framework_data["domains"]
        ],
        "last_updated": datetime(2025, 1, 1, tzinfo=timezone.utc),
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Helper: construct AssessmentResponse from model
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _assessment_to_response(assessment: ComplianceAssessment, framework_name: str = "") -> dict:
    controls = assessment.controls_data or []
    passed = sum(1 for c in controls if c.get("status") == "passed")
    failed = sum(1 for c in controls if c.get("status") == "failed")
    partial = sum(1 for c in controls if c.get("status") == "partial")
    not_assessed = sum(1 for c in controls if c.get("status") in ("not_assessed", None))
    total = len(controls)
    completion_pct = ((total - not_assessed) / total * 100) if total > 0 else 0.0
    score = (passed / total * 100) if total > 0 else None

    return {
        "id": str(assessment.id),
        "framework_id": assessment.framework,
        "framework_name": framework_name or assessment.framework,
        "name": assessment.name,
        "status": assessment.status,
        "scope": None,
        "assessor_id": str(assessment.assigned_to) if assessment.assigned_to else None,
        "assessor_name": None,
        "target_date": None,
        "total_controls": total,
        "passed_controls": passed,
        "failed_controls": failed,
        "partial_controls": partial,
        "not_assessed_controls": not_assessed,
        "completion_percentage": round(completion_pct, 1),
        "overall_score": round(score, 1) if score is not None else None,
        "tenant_id": str(assessment.tenant_id),
        "created_by": None,
        "created_at": assessment.created_at,
        "updated_at": assessment.updated_at,
        "completed_at": assessment.completed_at,
    }


async def _audit(
    db: AsyncSession,
    tenant_id: str,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
):
    try:
        audit = AuditLog(
            tenant_id=uuid.UUID(tenant_id),
            user_id=uuid.UUID(user_id) if user_id else None,
            action=action,
            resource_type=resource_type,
            resource_id=uuid.UUID(resource_id) if resource_id else None,
            details=details,
            status="success",
            severity="info",
        )
        db.add(audit)
        await db.flush()
    except Exception:
        pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Frameworks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/frameworks",
    response_model=List[FrameworkDetail],
    summary="List Compliance Frameworks",
)
async def list_frameworks(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in name, description"),
):
    result = []
    for fw_id, fw_data in FRAMEWORKS.items():
        detail = _build_framework_detail(fw_data)
        if category and detail["category"] != category:
            continue
        if search:
            s = search.lower()
            if s not in detail["name"].lower() and s not in detail["description"].lower():
                continue
        result.append(FrameworkDetail(**detail))
    return result


@router.get(
    "/frameworks/{framework_id}",
    response_model=FrameworkDetail,
    summary="Get Framework Details",
)
async def get_framework(
    framework_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    fw_data = FRAMEWORKS.get(framework_id)
    if not fw_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Framework '{framework_id}' not found")
    return FrameworkDetail(**_build_framework_detail(fw_data))


@router.post(
    "/frameworks/{framework_id}/assess",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start Compliance Assessment",
)
async def start_assessment(
    framework_id: str,
    request: AssessmentRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    fw_data = FRAMEWORKS.get(framework_id)
    if not fw_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Framework '{framework_id}' not found")

    controls_data = []
    for domain in fw_data["domains"]:
        for ctrl in domain["controls"]:
            if request.include_controls and ctrl["id"] not in request.include_controls:
                continue
            controls_data.append(
                {
                    "control_id": ctrl["id"],
                    "title": ctrl["title"],
                    "category": ctrl.get("category", domain["domain_id"]),
                    "status": "not_assessed",
                    "evidence": None,
                    "notes": None,
                    "score": 0,
                }
            )

    total = len(controls_data)
    if total == 0 and request.include_controls:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No matching controls found for specified IDs")

    assessment = ComplianceAssessment(
        tenant_id=uuid.UUID(tenant_id),
        framework=framework_id,
        name=request.name or f"{fw_data['name']} Assessment - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        status="in_progress",
        score=None,
        total_controls=total,
        passed_controls=0,
        failed_controls=0,
        controls_data=controls_data,
        assigned_to=uuid.UUID(request.assessor_id) if request.assessor_id else None,
        started_at=datetime.now(timezone.utc),
    )
    db.add(assessment)
    await db.flush()
    await _audit(db, tenant_id, current_user.get("user_id", ""), "assessment_created", "compliance_assessment", str(assessment.id),
                 {"framework": framework_id, "total_controls": total})

    return AssessmentResponse(**_assessment_to_response(assessment, fw_data["name"]))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Assessments â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/assessments",
    response_model=PaginatedResponse,
    summary="List Assessments",
)
async def list_assessments(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    framework_id: Optional[str] = Query(None),
    status: Optional[AssessmentStatus] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    conditions = [ComplianceAssessment.tenant_id == uuid.UUID(tenant_id)]
    if framework_id:
        conditions.append(ComplianceAssessment.framework == framework_id)
    if status:
        conditions.append(ComplianceAssessment.status == status.value)
    if start_date:
        conditions.append(ComplianceAssessment.created_at >= start_date)
    if end_date:
        conditions.append(ComplianceAssessment.created_at <= end_date)
    if search:
        conditions.append(ComplianceAssessment.name.ilike(f"%{search}%"))

    stmt_count = select(func.count(ComplianceAssessment.id)).where(*conditions)
    total_result = await db.execute(stmt_count)
    total = total_result.scalar() or 0

    order_col = getattr(ComplianceAssessment, sort_by, ComplianceAssessment.created_at)
    order_clause = order_col.desc() if sort_order == "desc" else order_col.asc()
    offset = (page - 1) * page_size

    stmt = select(ComplianceAssessment).where(*conditions).order_by(order_clause).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    assessments = result.scalars().all()

    items = []
    for a in assessments:
        fw_name = FRAMEWORKS.get(a.framework, {}).get("name", a.framework)
        items.append(_assessment_to_response(a, fw_name))

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=AssessmentResponse,
    summary="Get Assessment Results",
)
async def get_assessment(
    assessment_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    fw_name = FRAMEWORKS.get(assessment.framework, {}).get("name", assessment.framework)
    return AssessmentResponse(**_assessment_to_response(assessment, fw_name))


@router.get(
    "/assessments/{assessment_id}/controls",
    response_model=List[ControlAssessmentResult],
    summary="List Assessment Controls",
)
async def list_assessment_controls(
    assessment_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    status: Optional[ControlStatus] = Query(None),
    domain: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    controls = assessment.controls_data or []
    filtered = []
    for c in controls:
        ctrl_status = c.get("status", "not_assessed")
        if status and ctrl_status != status.value:
            continue
        if domain and c.get("category", "").lower() != domain.lower():
            continue
        if search and search.lower() not in c.get("title", "").lower():
            continue

        evidence = c.get("evidence")
        evidence_count = 1 if evidence else 0
        filtered.append(
            ControlAssessmentResult(
                control_id=c.get("control_id", ""),
                title=c.get("title", ""),
                domain=c.get("category"),
                status=ctrl_status,
                score=c.get("score"),
                notes=c.get("notes"),
                evidence_count=evidence_count,
            )
        )
    return filtered


@router.patch(
    "/assessments/{assessment_id}/controls/{control_id}",
    response_model=ControlAssessmentResult,
    summary="Update Control Status",
)
async def update_control_status(
    assessment_id: str,
    control_id: str,
    update: ControlStatusUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    controls = list(assessment.controls_data) if assessment.controls_data else []
    found = None
    for c in controls:
        if c.get("control_id") == control_id:
            found = c
            break
    if not found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Control '{control_id}' not found in assessment")

    found["status"] = update.status.value
    if update.score is not None:
        found["score"] = update.score
    if update.notes is not None:
        found["notes"] = update.notes
    found["assessed_by"] = current_user.get("user_id")
    found["assessed_at"] = datetime.now(timezone.utc).isoformat()

    passed = sum(1 for c in controls if c.get("status") == "passed")
    failed = sum(1 for c in controls if c.get("status") == "failed")

    assessment.controls_data = controls
    assessment.passed_controls = passed
    assessment.failed_controls = failed
    assessment.score = (passed / max(assessment.total_controls, 1)) * 100
    assessment.updated_at = datetime.now(timezone.utc)

    await db.flush()
    await _audit(db, tenant_id, current_user.get("user_id", ""), "control_status_updated", "compliance_assessment",
                 assessment_id, {"control_id": control_id, "status": update.status.value})

    evidence = found.get("evidence")
    evidence_count = 1 if evidence else 0
    return ControlAssessmentResult(
        control_id=found.get("control_id", ""),
        title=found.get("title", ""),
        domain=found.get("category"),
        status=found.get("status", "not_assessed"),
        score=found.get("score"),
        notes=found.get("notes"),
        evidence_count=evidence_count,
        assessed_by=current_user.get("user_id"),
        assessed_at=datetime.now(timezone.utc),
    )


@router.post(
    "/assessments/{assessment_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload Compliance Evidence",
)
async def upload_evidence(
    assessment_id: str,
    evidence: EvidenceUpload,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    controls = list(assessment.controls_data) if assessment.controls_data else []
    updated = 0
    for c in controls:
        if c.get("control_id") in evidence.control_ids:
            c["evidence"] = evidence.file_name or evidence.name
            c["evidence_type"] = evidence.evidence_type.value
            c["evidence_storage_path"] = evidence.storage_path
            updated += 1

    if updated == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="None of the specified control IDs found in this assessment")

    assessment.controls_data = controls
    assessment.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await _audit(db, tenant_id, current_user.get("user_id", ""), "evidence_uploaded", "compliance_assessment",
                 assessment_id, {"file_name": evidence.file_name, "control_ids": evidence.control_ids})

    evidence_id = str(uuid.uuid4())
    return EvidenceResponse(
        id=evidence_id,
        name=evidence.name,
        evidence_type=evidence.evidence_type,
        description=evidence.description,
        control_ids=evidence.control_ids,
        file_name=evidence.file_name,
        file_size_bytes=evidence.file_size_bytes,
        content_type=evidence.content_type,
        storage_path=evidence.storage_path,
        uploaded_by=current_user.get("user_id"),
        tags=evidence.tags,
        tenant_id=tenant_id,
        created_at=datetime.now(timezone.utc),
        metadata=evidence.metadata,
    )


@router.get(
    "/assessments/{assessment_id}/report",
    response_model=ComplianceReport,
    summary="Generate Compliance Report",
)
async def generate_compliance_report(
    assessment_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    controls = assessment.controls_data or []
    fw_name = FRAMEWORKS.get(assessment.framework, {}).get("name", assessment.framework)

    passed = sum(1 for c in controls if c.get("status") == "passed")
    failed = sum(1 for c in controls if c.get("status") == "failed")
    partial = sum(1 for c in controls if c.get("status") == "partial")
    not_assessed = sum(1 for c in controls if c.get("status") in ("not_assessed", None))
    total = len(controls)
    overall = (passed / total * 100) if total > 0 else 0.0

    domain_scores = {}
    domain_totals = {}
    domain_passed = {}
    for c in controls:
        cat = c.get("category", "unknown")
        domain_totals[cat] = domain_totals.get(cat, 0) + 1
        if c.get("status") == "passed":
            domain_passed[cat] = domain_passed.get(cat, 0) + 1

    for cat, tot in domain_totals.items():
        domain_scores[cat] = round((domain_passed.get(cat, 0) / tot) * 100, 1)

    findings = []
    recommendations = []
    for c in controls:
        if c.get("status") == "failed":
            findings.append({
                "control_id": c.get("control_id"),
                "title": c.get("title"),
                "category": c.get("category"),
                "status": "failed",
                "notes": c.get("notes"),
            })
            recommendations.append({
                "control_id": c.get("control_id"),
                "title": c.get("title"),
                "remediation": "Review and implement the required control per framework guidance. Assign a remediation owner and target date.",
            })

    return ComplianceReport(
        assessment_id=assessment_id,
        framework_name=fw_name,
        generated_at=datetime.now(timezone.utc),
        overall_score=round(overall, 1),
        control_summary={
            "total": total,
            "passed": passed,
            "failed": failed,
            "partial": partial,
            "not_assessed": not_assessed,
        },
        domain_scores=domain_scores,
        findings=findings,
        recommendations=recommendations,
    )


@router.get(
    "/assessments/{assessment_id}/export",
    summary="Export Assessment",
)
async def export_assessment(
    assessment_id: str,
    format: ExportFormat = Query(ExportFormat.PDF),
    include_evidence: bool = Query(True),
    include_recommendations: bool = Query(True),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(
        ComplianceAssessment.id == uuid.UUID(assessment_id),
        ComplianceAssessment.tenant_id == uuid.UUID(tenant_id),
    )
    result = await db.execute(stmt)
    assessment = result.scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    controls = assessment.controls_data or []
    fw_name = FRAMEWORKS.get(assessment.framework, {}).get("name", assessment.framework)

    passed = sum(1 for c in controls if c.get("status") == "passed")
    failed = sum(1 for c in controls if c.get("status") == "failed")
    partial = sum(1 for c in controls if c.get("status") == "partial")
    not_assessed = sum(1 for c in controls if c.get("status") in ("not_assessed", None))

    export_data = {
        "assessment_id": assessment_id,
        "framework": assessment.framework,
        "framework_name": fw_name,
        "name": assessment.name,
        "status": assessment.status,
        "overall_score": round((passed / max(len(controls), 1)) * 100, 1),
        "control_summary": {
            "total": len(controls),
            "passed": passed,
            "failed": failed,
            "partial": partial,
            "not_assessed": not_assessed,
        },
        "controls": controls if include_evidence else [
            {k: v for k, v in c.items() if k not in ("evidence", "evidence_storage_path", "evidence_type")}
            for c in controls
        ],
        "recommendations": include_recommendations,
        "format": format.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    content_type_map = {"pdf": "application/pdf", "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "csv": "text/csv"}
    return Response(
        content=json.dumps(export_data, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=assessment_{assessment_id}_export.json",
                 "X-Requested-Format": format.value},
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Controls â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/controls",
    response_model=PaginatedResponse,
    summary="List All Controls",
)
async def list_controls(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    framework_id: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
):
    stmt = select(ComplianceAssessment).where(ComplianceAssessment.tenant_id == uuid.UUID(tenant_id))
    if framework_id:
        stmt = stmt.where(ComplianceAssessment.framework == framework_id)
    stmt = stmt.order_by(ComplianceAssessment.created_at.desc())
    result = await db.execute(stmt)
    assessments = result.scalars().all()

    seen = {}
    for a in assessments:
        for c in (a.controls_data or []):
            cid = c.get("control_id")
            cat = c.get("category", "")
            if domain and cat.lower() != domain.lower():
                continue
            if search and search.lower() not in c.get("title", "").lower() and search.lower() not in (cid or "").lower():
                continue
            if cid and cid not in seen:
                seen[cid] = {
                    "control_id": cid,
                    "title": c.get("title", ""),
                    "domain": cat,
                    "status_summary": {"passed": 0, "failed": 0, "partial": 0, "not_assessed": 0},
                    "framework": a.framework,
                    "assessment_count": 0,
                }
            if cid in seen:
                status = c.get("status", "not_assessed")
                seen[cid]["status_summary"][status] = seen[cid]["status_summary"].get(status, 0) + 1
                seen[cid]["assessment_count"] += 1

    items_list = list(seen.values())
    total = len(items_list)
    offset = (page - 1) * page_size
    page_items = items_list[offset:offset + page_size]

    return PaginatedResponse(
        items=page_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.get(
    "/controls/{control_id}",
    response_model=ControlDetail,
    summary="Get Control Detail",
)
async def get_control(
    control_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    for fw_id, fw_data in FRAMEWORKS.items():
        for domain in fw_data["domains"]:
            for ctrl in domain["controls"]:
                if ctrl["id"] == control_id:
                    return ControlDetail(
                        id=ctrl["id"],
                        control_id=ctrl["id"],
                        title=ctrl["title"],
                        description=ctrl["description"],
                        domain=domain["domain_id"],
                        subdomain=domain["name"],
                        guidance=ctrl.get("implementation_guidance"),
                        assessment_procedure=None,
                        related_controls=[],
                        mappings={fw_id: [ctrl["id"]]},
                        risk_level="medium",
                        evidence_required=["evidence"],
                        remediation_guidance=f"Implement per {fw_data['name']} guidance: {ctrl.get('implementation_guidance', '')}",
                        references=[f"{fw_data['name']} {fw_data['version']}"],
                        tags=[fw_data["category"]],
                    )

    stmt = select(ComplianceAssessment).where(ComplianceAssessment.tenant_id == uuid.UUID(tenant_id))
    result = await db.execute(stmt)
    for a in result.scalars().all():
        for c in (a.controls_data or []):
            if c.get("control_id") == control_id:
                return ControlDetail(
                    id=control_id,
                    control_id=control_id,
                    title=c.get("title", control_id),
                    description=c.get("notes", "From assessment data"),
                    domain=c.get("category"),
                    guidance="See assessment evidence",
                    related_controls=[],
                    mappings={a.framework: [control_id]},
                    risk_level="medium",
                )

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Control '{control_id}' not found")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Dashboards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/dashboards",
    response_model=ComplianceDashboardResponse,
    summary="Compliance Dashboard",
)
async def compliance_dashboard(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ComplianceAssessment).where(ComplianceAssessment.tenant_id == uuid.UUID(tenant_id))
    result = await db.execute(stmt)
    assessments = result.scalars().all()

    if not assessments:
        return ComplianceDashboardResponse()

    framework_scores = {}
    total_passed = 0
    total_failed = 0
    total_partial = 0
    total_not_assessed = 0
    total_all_controls = 0
    all_failed = []
    in_progress_count = 0

    for a in assessments:
        controls = a.controls_data or []
        p = sum(1 for c in controls if c.get("status") == "passed")
        f = sum(1 for c in controls if c.get("status") == "failed")
        total_all_controls += len(controls)
        total_passed += p
        total_failed += f
        total_partial += sum(1 for c in controls if c.get("status") == "partial")
        total_not_assessed += sum(1 for c in controls if c.get("status") in ("not_assessed", None))

        fw_name = FRAMEWORKS.get(a.framework, {}).get("name", a.framework)
        fw_total = len(controls)
        fw_score = (p / fw_total * 100) if fw_total > 0 else 0.0
        if fw_name not in framework_scores:
            framework_scores[fw_name] = {"total_controls": 0, "total_passed": 0, "assessments": 0}
        framework_scores[fw_name]["total_controls"] += fw_total
        framework_scores[fw_name]["total_passed"] += p
        framework_scores[fw_name]["assessments"] += 1

        if a.status == "in_progress":
            in_progress_count += 1

        for c in controls:
            if c.get("status") == "failed":
                all_failed.append({
                    "control_id": c.get("control_id"),
                    "title": c.get("title"),
                    "framework": fw_name,
                    "category": c.get("category"),
                    "status": "failed",
                })

    overall_score = (total_passed / total_all_controls * 100) if total_all_controls > 0 else 0.0
    control_pass_rate = (total_passed / max(total_all_controls - total_not_assessed, 1) * 100) if total_all_controls > total_not_assessed else 0.0

    fw_breakdown = []
    for fw_name, data in framework_scores.items():
        s = (data["total_passed"] / data["total_controls"] * 100) if data["total_controls"] > 0 else 0.0
        fw_breakdown.append({"framework": fw_name, "score": round(s, 1), "controls": data["total_controls"], "assessments": data["assessments"]})

    return ComplianceDashboardResponse(
        overall_score=round(overall_score, 1),
        framework_breakdown=fw_breakdown,
        control_pass_rate=round(control_pass_rate, 1),
        total_controls=total_all_controls,
        assessed_controls=total_passed + total_failed + total_partial,
        passed_controls=total_passed,
        failed_controls=total_failed,
        partial_controls=total_partial,
        top_gaps=all_failed[:10],
        active_remediation_plans=0,
        overdue_remediation_plans=0,
        assessments_in_progress=in_progress_count,
        trends={},
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Gaps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/gaps",
    response_model=PaginatedResponse,
    summary="List Compliance Gaps",
)
async def list_gaps(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
    assessment_id: Optional[str] = Query(None),
    framework_id: Optional[str] = Query(None),
    severity: Optional[GapSeverity] = Query(None),
    status: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    conditions = [ComplianceAssessment.tenant_id == uuid.UUID(tenant_id)]
    if assessment_id:
        conditions.append(ComplianceAssessment.id == uuid.UUID(assessment_id))
    if framework_id:
        conditions.append(ComplianceAssessment.framework == framework_id)

    stmt = select(ComplianceAssessment).where(*conditions)
    result = await db.execute(stmt)
    assessments = result.scalars().all()

    gaps = []
    for a in assessments:
        fw_name = FRAMEWORKS.get(a.framework, {}).get("name", a.framework)
        for c in (a.controls_data or []):
            if c.get("status") != "failed":
                continue
            cat = c.get("category", "")
            if domain and cat.lower() != domain.lower():
                continue
            title = c.get("title", "")
            if search and search.lower() not in title.lower() and search.lower() not in (c.get("control_id", "") or "").lower():
                continue

            detected = a.updated_at if a.updated_at else a.created_at
            gaps.append({
                "id": f"{a.id}-{c.get('control_id')}",
                "assessment_id": str(a.id),
                "control_id": c.get("control_id"),
                "control_title": title,
                "framework_id": a.framework,
                "framework_name": fw_name,
                "title": f"FAILED: {title}",
                "description": c.get("notes"),
                "severity": "medium",
                "status": "open",
                "domain": cat,
                "detected_at": detected,
                "tenant_id": str(a.tenant_id),
            })

    total = len(gaps)
    offset = (page - 1) * page_size
    page_items = gaps[offset:offset + page_size]

    return PaginatedResponse(
        items=page_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Remediation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/remediation-plans",
    response_model=PaginatedResponse,
    summary="List Remediation Plans",
)
async def list_remediation_plans(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    status: Optional[RemediationStatus] = Query(None),
    assignee_id: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    overdue: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    return PaginatedResponse(items=[], total=0, page=page, page_size=page_size, total_pages=0)


@router.patch(
    "/remediation-plans/{plan_id}",
    response_model=RemediationPlanResponse,
    summary="Update Remediation Plan",
)
async def update_remediation_plan(
    plan_id: str,
    update: RemediationUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    generated_gap_id = f"{assessment_id}-{update.title or 'remediation'}-{plan_id[:8]}"
    resp = RemediationPlanResponse(
        id=plan_id,
        gap_id=generated_gap_id,
        title=update.title or "Remediation Plan",
        description=update.description,
        assignee_id=update.assignee_id,
        assignee_name=None,
        priority=update.priority or "medium",
        status=update.status or RemediationStatus.PLANNED,
        target_date=update.target_date,
        estimated_effort_hours=None,
        actual_effort_hours=update.actual_effort_hours,
        steps=update.steps or [],
        tenant_id=tenant_id,
        created_by=current_user.get("user_id"),
        created_at=now,
        updated_at=now,
        completed_at=now if update.status == RemediationStatus.COMPLETED else None,
        verified_at=now if update.status == RemediationStatus.VERIFIED else None,
    )
    await _audit(db, tenant_id, current_user.get("user_id", ""), "remediation_plan_updated",
                 "remediation_plan", plan_id, {"status": str(resp.status), "verification_notes": update.verification_notes})
    return resp


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Evidence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@router.get(
    "/evidence",
    response_model=PaginatedResponse,
    summary="List Evidence Artifacts",
)
async def list_evidence(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    db: AsyncSession = Depends(get_db),
    assessment_id: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
    evidence_type: Optional[EvidenceType] = Query(None),
    search: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    conditions = [ComplianceAssessment.tenant_id == uuid.UUID(tenant_id)]
    if assessment_id:
        conditions.append(ComplianceAssessment.id == uuid.UUID(assessment_id))

    stmt = select(ComplianceAssessment).where(*conditions)
    result = await db.execute(stmt)
    assessments = result.scalars().all()

    evidence_items = []
    for a in assessments:
        for c in (a.controls_data or []):
            ev = c.get("evidence")
            if not ev:
                continue
            if control_id and c.get("control_id") != control_id:
                continue
            if evidence_type and c.get("evidence_type") != evidence_type.value:
                continue
            if search and search.lower() not in str(ev).lower():
                continue

            evidence_items.append({
                "id": f"{a.id}-{c.get('control_id')}",
                "name": str(ev),
                "evidence_type": c.get("evidence_type", "other"),
                "description": c.get("notes"),
                "control_ids": [c.get("control_id")],
                "file_name": str(ev),
                "file_size_bytes": None,
                "content_type": None,
                "storage_path": c.get("evidence_storage_path"),
                "uploaded_by": None,
                "tags": [],
                "tenant_id": str(a.tenant_id),
                "created_at": a.updated_at,
                "metadata": None,
            })

    total = len(evidence_items)
    offset = (page - 1) * page_size
    page_items = evidence_items[offset:offset + page_size]

    return PaginatedResponse(
        items=page_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# â”€â”€ Policies â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

HARDCODED_POLICIES = [
    {
        "id": "pol-acceptable-use",
        "title": "Acceptable Use Policy",
        "policy_number": "SEC-POL-001",
        "category": "security",
        "description": "Defines acceptable use of organizational information systems, networks, and data. Establishes user responsibilities for protecting company assets.",
        "content": "All users must comply with acceptable use guidelines including appropriate internet usage, email communication standards, software installation restrictions, and prohibition of unauthorized access.",
        "version": "2.0",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-12.1"], "iso27001": ["iso-a5.1"], "cis_v8": ["cis-1", "cis-2"]},
        "tags": ["user_policy", "acceptable_use", "all_staff"],
    },
    {
        "id": "pol-access-control",
        "title": "Access Control Policy",
        "policy_number": "SEC-POL-002",
        "category": "security",
        "description": "Establishes requirements for identity and access management including provisioning, de-provisioning, privilege management, and access reviews.",
        "content": "Access shall be granted on least-privilege and need-to-know principles. All access must be reviewed quarterly. Multi-factor authentication required for privileged access.",
        "version": "3.1",
        "status": "active",
        "effective_date": datetime(2024, 3, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 3, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-7.1", "pci-7.2", "pci-8.1"], "iso27001": ["iso-a8.2", "iso-a8.3"], "cis_v8": ["cis-5", "cis-6"]},
        "tags": ["access_control", "iam", "authentication"],
    },
    {
        "id": "pol-data-classification",
        "title": "Data Classification and Handling Policy",
        "policy_number": "SEC-POL-003",
        "category": "security",
        "description": "Defines data classification levels (Public, Internal, Confidential, Restricted) and handling requirements for each level, including storage, transmission, and disposal.",
        "content": "All data must be classified into one of four levels. Restricted data (cardholder data, PII, PHI) requires encryption at rest and in transit, strict access controls, and audit logging.",
        "version": "2.2",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-3.4", "pci-4.1"], "gdpr": ["gdpr-prin-1", "gdpr-prin-6"], "cis_v8": ["cis-3"]},
        "tags": ["data_classification", "dlp", "encryption"],
    },
    {
        "id": "pol-incident-response",
        "title": "Incident Response Policy",
        "policy_number": "SEC-POL-004",
        "category": "security",
        "description": "Defines the incident response lifecycle including detection, analysis, containment, eradication, recovery, and post-incident activities.",
        "content": "All security incidents must be reported within 1 hour of discovery. The CIRT shall be immediately activated for critical/high severity incidents. Post-mortem required within 5 business days.",
        "version": "4.0",
        "status": "active",
        "effective_date": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 6, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-12.5"], "nist_csf": ["nist-rs.ma-01", "nist-rs.mi-01"], "cis_v8": ["cis-17"]},
        "tags": ["incident_response", "ir", "breach"],
    },
    {
        "id": "pol-business-continuity",
        "title": "Business Continuity and Disaster Recovery Policy",
        "policy_number": "SEC-POL-005",
        "category": "security",
        "description": "Establishes requirements for business continuity planning, disaster recovery procedures, backup management, and annual testing.",
        "content": "Critical systems must have RPO <= 4 hours and RTO <= 24 hours. Annual DR test required. Backups must be tested quarterly. Offsite backup storage required.",
        "version": "3.0",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"iso27001": ["iso-a8.6"], "nist_csf": ["nist-rc.rp-01"], "cis_v8": ["cis-11"]},
        "tags": ["bcp", "dr", "backup", "disaster_recovery"],
    },
    {
        "id": "pol-change-management",
        "title": "Change Management Policy",
        "policy_number": "SEC-POL-006",
        "category": "security",
        "description": "Defines the change management process including request, review, approval, testing, implementation, and post-implementation review.",
        "content": "All changes to production systems require a change request, risk assessment, CAB approval for major changes, and documented backout plan. Emergency changes require post-implementation review.",
        "version": "2.1",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-6.4"], "soc2": ["soc2-sec-3"], "iso27001": ["iso-a8.9"]},
        "tags": ["change_management", "cab", "devops"],
    },
    {
        "id": "pol-vulnerability-management",
        "title": "Vulnerability Management Policy",
        "policy_number": "SEC-POL-007",
        "category": "security",
        "description": "Defines requirements for vulnerability scanning, risk assessment, patch management timelines, and remediation tracking.",
        "content": "Monthly authenticated vulnerability scans on all systems. Critical vulnerabilities patched within 7 days, high within 30 days, medium within 90 days. Quarterly external ASV scans.",
        "version": "3.2",
        "status": "active",
        "effective_date": datetime(2024, 4, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 4, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-6.1", "pci-11.2"], "iso27001": ["iso-a8.8"], "cis_v8": ["cis-7"]},
        "tags": ["vulnerability", "patching", "scanning"],
    },
    {
        "id": "pol-audit-logging",
        "title": "Audit Logging and Monitoring Policy",
        "policy_number": "SEC-POL-008",
        "category": "security",
        "description": "Defines requirements for audit log collection, retention, review, and protection for all system components.",
        "content": "Audit logs must be collected from all CDE and critical systems, retained for minimum 12 months, reviewed daily for security events, and protected from tampering.",
        "version": "2.0",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-10.1", "pci-10.5", "pci-10.6"], "iso27001": ["iso-a8.7"], "cis_v8": ["cis-8"]},
        "tags": ["logging", "audit", "monitoring", "siem"],
    },
    {
        "id": "pol-third-party",
        "title": "Third-Party Risk Management Policy",
        "policy_number": "SEC-POL-009",
        "category": "security",
        "description": "Defines requirements for vendor risk assessments, due diligence, ongoing monitoring, and contract security requirements.",
        "content": "All vendors accessing cardholder data or critical systems must undergo annual risk assessment. Contracts must include security requirements and right-to-audit clauses.",
        "version": "2.0",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-12.4"], "soc2": ["soc2-cc2.2"], "nist_csf": ["nist-gv.sc-01"]},
        "tags": ["third_party", "vendor", "tprm"],
    },
    {
        "id": "pol-security-awareness",
        "title": "Security Awareness and Training Policy",
        "policy_number": "SEC-POL-010",
        "category": "security",
        "description": "Defines requirements for mandatory security awareness training, phishing simulations, and role-based training.",
        "content": "All employees and contractors must complete annual security awareness training. Monthly phishing simulations. Role-based training for developers, administrators, and executives.",
        "version": "3.0",
        "status": "active",
        "effective_date": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "review_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "framework_mappings": {"pci_dss_v4": ["pci-12.3"], "iso27001": ["iso-a6.3"], "hipaa": ["hipaa-sat"], "cis_v8": ["cis-14"]},
        "tags": ["training", "awareness", "phishing"],
    },
]


@router.get(
    "/policies",
    response_model=PaginatedResponse,
    summary="List Security Policies",
)
async def list_policies(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    category: Optional[str] = Query(None),
    status: Optional[PolicyStatus] = Query(None),
    search: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    filtered = []
    for p in HARDCODED_POLICIES:
        if category and p["category"] != category:
            continue
        if status and p["status"] != status.value:
            continue
        if search and search.lower() not in p["title"].lower() and (p.get("description") and search.lower() not in p["description"].lower()):
            continue
        if tags:
            has_tag = any(t in p.get("tags", []) for t in tags)
            if not has_tag:
                continue
        filtered.append(p)

    total = len(filtered)
    offset = (page - 1) * page_size
    page_items = filtered[offset:offset + page_size]

    items = []
    for p in page_items:
        items.append({
            "id": p["id"],
            "title": p["title"],
            "policy_number": p.get("policy_number"),
            "category": p["category"],
            "description": p.get("description"),
            "content": p.get("content"),
            "version": p["version"],
            "status": p["status"],
            "effective_date": p.get("effective_date"),
            "review_date": p.get("review_date"),
            "owner_id": None,
            "framework_mappings": p.get("framework_mappings", {}),
            "tags": p.get("tags", []),
            "tenant_id": tenant_id,
            "created_by": None,
            "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "updated_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "last_reviewed_at": None,
            "last_reviewed_by": None,
            "metadata": None,
        })

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.post(
    "/policies",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Policy Document",
)
async def create_policy(
    policy: PolicyCreate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    return PolicyResponse(
        id=str(uuid.uuid4()),
        title=policy.title,
        policy_number=policy.policy_number,
        category=policy.category,
        description=policy.description,
        content=policy.content,
        version=policy.version or "1.0",
        status=policy.status,
        effective_date=policy.effective_date or datetime.now(timezone.utc),
        review_date=policy.review_date,
        owner_id=policy.owner_id,
        framework_mappings=policy.framework_mappings,
        tags=policy.tags,
        tenant_id=tenant_id,
        created_by=current_user.get("user_id"),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        last_reviewed_at=None,
        last_reviewed_by=None,
        metadata=policy.metadata,
    )


@router.get(
    "/policies/{policy_id}",
    response_model=PolicyResponse,
    summary="Get Policy Detail",
)
async def get_policy(
    policy_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    for p in HARDCODED_POLICIES:
        if p["id"] == policy_id:
            return PolicyResponse(
                id=p["id"],
                title=p["title"],
                policy_number=p.get("policy_number"),
                category=p["category"],
                description=p.get("description"),
                content=p.get("content"),
                version=p["version"],
                status=p["status"],
                effective_date=p.get("effective_date"),
                review_date=p.get("review_date"),
                owner_id=None,
                framework_mappings=p.get("framework_mappings", {}),
                tags=p.get("tags", []),
                tenant_id=tenant_id,
                created_by=None,
                created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                updated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                last_reviewed_at=None,
                last_reviewed_by=None,
                metadata=None,
            )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found")


@router.patch(
    "/policies/{policy_id}",
    response_model=PolicyResponse,
    summary="Update Policy",
)
async def update_policy(
    policy_id: str,
    update: PolicyUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    base_policy = next((p for p in HARDCODED_POLICIES if p["id"] == policy_id), None)
    if not base_policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found")

    result_policy = {
        "id": policy_id,
        "title": update.title or base_policy["title"],
        "policy_number": update.policy_number or base_policy.get("policy_number"),
        "category": update.category or base_policy["category"],
        "description": update.description or base_policy.get("description"),
        "content": update.content or base_policy.get("content"),
        "version": update.version or base_policy["version"],
        "status": update.status.value if update.status else base_policy["status"],
        "effective_date": update.effective_date or base_policy.get("effective_date"),
        "review_date": update.review_date or base_policy.get("review_date"),
        "owner_id": update.owner_id,
        "framework_mappings": update.framework_mappings or base_policy.get("framework_mappings", {}),
        "tags": update.tags or base_policy.get("tags", []),
        "tenant_id": tenant_id,
        "created_by": None,
        "created_at": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "last_reviewed_at": None,
        "last_reviewed_by": None,
        "metadata": update.metadata,
    }
    return PolicyResponse(**result_policy)


@router.get(
    "/policies/{policy_id}/review",
    response_model=PolicyReviewResponse,
    summary="Policy Review Evidence",
)
async def get_policy_review(
    policy_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    base_policy = next((p for p in HARDCODED_POLICIES if p["id"] == policy_id), None)
    if not base_policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found")

    return PolicyReviewResponse(
        policy_id=policy_id,
        policy_title=base_policy["title"],
        reviewed_by=None,
        reviewed_at=None,
        attestation=None,
        review_cycle="annual",
        next_review_date=base_policy.get("review_date"),
        review_history=[],
    )
