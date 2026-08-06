"""
AEGISX - Threat Intelligence API Router
Feeds, IOCs, actors, campaigns, TTPs, MITRE ATT&CK, reputation lookups, reports
"""
import uuid as _uuid
import math
import json as _json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, update as sql_update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import ThreatFeed, ThreatIndicator, AuditLog
from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireThreatHunter,
    RequireSOCManager,
    RequireSOCAnalyst,
)

router = APIRouter()


CONFIDENCE_MAP = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
CONFIDENCE_THRESHOLDS = [(1.0, "critical"), (0.75, "high"), (0.5, "medium"), (0.25, "low")]

def _conf_to_float(val):
    if val is None: return 0.5
    return CONFIDENCE_MAP.get(val, 0.5)

def _conf_from_float(val):
    if val is None: return "medium"
    for t, l in CONFIDENCE_THRESHOLDS:
        if val >= t: return l
    return "low"

def _feed_to_response(f):
    cfg = f.config or {}
    return {
        "id": str(f.id), "tenant_id": str(f.tenant_id),
        "created_at": f.created_at, "updated_at": f.updated_at,
        "created_by": str(f.created_by) if getattr(f, "created_by", None) else None,
        "name": f.name, "description": cfg.get("description"),
        "feed_type": f.source_type, "url": f.url,
        "enabled": f.is_active, "polling_interval_seconds": f.sync_interval or 3600,
        "auth": cfg.get("auth"), "tls": cfg.get("tls"),
        "tags": cfg.get("tags") or [], "confidence_default": cfg.get("confidence_default") or "medium",
        "status": "active" if f.is_active else "inactive",
        "last_sync_at": f.last_sync_at, "last_sync_error": None,
        "indicator_count": f.indicator_count,
    }

def _indicator_to_response(i):
    status_str = "active" if i.is_active else "revoked"
    return {
        "id": str(i.id), "tenant_id": str(i.tenant_id),
        "created_at": i.created_at, "updated_at": i.updated_at, "created_by": None,
        "type": i.type, "value": i.value, "description": i.description,
        "confidence": _conf_from_float(i.confidence), "tlp": i.tlp,
        "status": status_str, "valid_from": i.first_seen, "valid_until": i.last_seen,
        "tags": i.tags or [], "source": i.source,
        "kill_chain_phases": [], "external_references": [],
        "sightings_count": 0, "last_seen": i.last_seen,
    }

def _indicator_to_detail(i):
    return {
        **_indicator_to_response(i),
        "enrichment": [], "related_threat_actors": [], "related_campaigns": [],
        "mitre_techniques": [{"technique_id": t, "name": t} for t in (i.mitre_techniques or [])],
    }

async def _audit(db, tenant_id, user_id, action, resource_type, resource_id=None, details=None, status_val="success"):
    entry = AuditLog(
        tenant_id=_uuid.UUID(tenant_id),
        user_id=_uuid.UUID(user_id) if user_id else None,
        action=action, resource_type=resource_type,
        resource_id=_uuid.UUID(resource_id) if resource_id else None,
        details=details, status=status_val, severity="info",
    )
    db.add(entry)

def _paginated(items, total, page, page_size):
    return {
        "items": items,
        "meta": {"page": page, "page_size": page_size, "total_items": total,
                  "total_pages": max(1, math.ceil(total / page_size))},
    }


class FeedType(str, Enum):
    MISP = "misp"; OPENCTI = "opencti"; TAXII = "taxii"; CUSTOM_URL = "custom_url"; ALIENVAULT = "alienvault"; ANOMALI = "anomali"

class FeedStatus(str, Enum):
    ACTIVE = "active"; INACTIVE = "inactive"; ERROR = "error"; SYNCING = "syncing"

class IOCType(str, Enum):
    IP = "ip"; DOMAIN = "domain"; URL = "url"; HASH_MD5 = "hash_md5"; HASH_SHA1 = "hash_sha1"; HASH_SHA256 = "hash_sha256"; EMAIL = "email"

class ConfidenceLevel(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class TLPMarking(str, Enum):
    WHITE = "white"; GREEN = "green"; AMBER = "amber"; RED = "red"

class IndicatorStatus(str, Enum):
    ACTIVE = "active"; EXPIRED = "expired"; REVOKED = "revoked"; FALSE_POSITIVE = "false_positive"

class ActorThreatLevel(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class Sector(str, Enum):
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    ENERGY = "energy"
    GOVERNMENT = "government"
    DEFENSE = "defense"
    MEDIA = "media"
    AEROSPACE = "aerospace"
    EDUCATION = "education"
    TELECOMMUNICATIONS = "telecommunications"
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    TRANSPORTATION = "transportation"
    TECHNOLOGY = "technology"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    OTHER = "other"

class CampaignStatus(str, Enum):
    ONGOING = "ongoing"; COMPLETED = "completed"; INACTIVE = "inactive"

class ReportType(str, Enum):
    TACTICAL = "tactical"; OPERATIONAL = "operational"; STRATEGIC = "strategic"

class ReportStatus(str, Enum):
    DRAFT = "draft"; PUBLISHED = "published"; ARCHIVED = "archived"

class ImportFormat(str, Enum):
    STIX = "stix"; CSV = "csv"; JSON = "json"

class EnrichSource(str, Enum):
    VIRUSTOTAL = "virustotal"; ABUSEIPDB = "abuseipdb"; SHODAN = "shodan"; ALIENVAULT = "alienvault"; GREYNOISE = "greynoise"

class MitreDomain(str, Enum):
    ENTERPRISE = "enterprise"; MOBILE = "mobile"; ICS = "ics"

class AttackTactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"; RESOURCE_DEVELOPMENT = "resource_development"; INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"; PERSISTENCE = "persistence"; PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"; CREDENTIAL_ACCESS = "credential_access"; DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"; COLLECTION = "collection"; COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"; IMPACT = "impact"


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class PaginationMeta(BaseModel):
    page: int; page_size: int; total_items: int; total_pages: int

class BaseEntity(BaseModel):
    id: str; tenant_id: str; created_at: datetime; updated_at: datetime; created_by: Optional[str] = None


class FeedAuthConfig(BaseModel):
    auth_type: str = Field(default="none")
    username: Optional[str] = None; password: Optional[str] = None; token: Optional[str] = None
    api_key: Optional[str] = None; api_key_header: Optional[str] = None

class FeedTLSConfig(BaseModel):
    verify_ssl: bool = True; client_cert_pem: Optional[str] = None
    client_key_pem: Optional[str] = None; ca_cert_pem: Optional[str] = None

class FeedCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None; feed_type: FeedType; url: Optional[str] = None
    enabled: bool = True; polling_interval_seconds: int = Field(default=3600, ge=60)
    auth: Optional[FeedAuthConfig] = None; tls: Optional[FeedTLSConfig] = None
    tags: List[str] = Field(default_factory=list); confidence_default: ConfidenceLevel = ConfidenceLevel.MEDIUM

class FeedUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None; url: Optional[str] = None; enabled: Optional[bool] = None
    polling_interval_seconds: Optional[int] = Field(default=None, ge=60)
    auth: Optional[FeedAuthConfig] = None; tls: Optional[FeedTLSConfig] = None
    tags: Optional[List[str]] = None; confidence_default: Optional[ConfidenceLevel] = None

class FeedResponse(BaseEntity):
    name: str; description: Optional[str]; feed_type: FeedType; url: Optional[str]
    enabled: bool; polling_interval_seconds: int; auth: Optional[FeedAuthConfig]; tls: Optional[FeedTLSConfig]
    tags: List[str]; confidence_default: ConfidenceLevel; status: FeedStatus
    last_sync_at: Optional[datetime] = None; last_sync_error: Optional[str] = None; indicator_count: int = 0

class FeedStatusResponse(BaseModel):
    feed_id: str; status: FeedStatus; last_sync_at: Optional[datetime]; last_sync_duration_ms: Optional[int]
    total_indicators_imported: int; sync_history: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[Dict[str, Any]] = Field(default_factory=list)

class SyncTriggerRequest(BaseModel):
    full_sync: bool = False; since: Optional[datetime] = None


class IndicatorCreate(BaseModel):
    type: IOCType; value: str = Field(..., min_length=1, max_length=4096); description: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM; tlp: TLPMarking = TLPMarking.AMBER
    status: IndicatorStatus = IndicatorStatus.ACTIVE; valid_from: Optional[datetime] = None; valid_until: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list); source: Optional[str] = None
    kill_chain_phases: List[str] = Field(default_factory=list); external_references: List[Dict[str, str]] = Field(default_factory=list)

class IndicatorUpdate(BaseModel):
    description: Optional[str] = None; confidence: Optional[ConfidenceLevel] = None; tlp: Optional[TLPMarking] = None
    status: Optional[IndicatorStatus] = None; valid_until: Optional[datetime] = None
    tags: Optional[List[str]] = None; kill_chain_phases: Optional[List[str]] = None
    external_references: Optional[List[Dict[str, str]]] = None

class IndicatorResponse(BaseEntity):
    type: IOCType; value: str; description: Optional[str]; confidence: ConfidenceLevel; tlp: TLPMarking
    status: IndicatorStatus; valid_from: Optional[datetime]; valid_until: Optional[datetime]; tags: List[str]
    source: Optional[str]; kill_chain_phases: List[str]; external_references: List[Dict[str, str]]
    sightings_count: int = 0; last_seen: Optional[datetime] = None

class IndicatorEnrichmentData(BaseModel):
    source: str; last_checked: Optional[datetime]; reputation_score: Optional[int] = None
    categories: List[str] = Field(default_factory=list); whois: Optional[Dict[str, Any]] = None
    geolocation: Optional[Dict[str, Any]] = None; dns_records: Optional[List[Dict[str, Any]]] = None
    ssl_certificates: Optional[List[Dict[str, Any]]] = None; related_indicators: List[str] = Field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None

class IndicatorDetailResponse(IndicatorResponse):
    enrichment: List[IndicatorEnrichmentData] = Field(default_factory=list)
    related_threat_actors: List[Dict[str, str]] = Field(default_factory=list)
    related_campaigns: List[Dict[str, str]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)

class IndicatorBulkImport(BaseModel):
    format: ImportFormat; data: str = Field(..., description="Raw STIX bundle, CSV content, or JSON array")
    source: Optional[str] = None; confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tlp: TLPMarking = TLPMarking.AMBER; tags: List[str] = Field(default_factory=list)

class IndicatorBulkImportResponse(BaseModel):
    total: int; created: int; updated: int; skipped: int; errors: List[Dict[str, Any]] = Field(default_factory=list)

class IndicatorEnrichRequest(BaseModel):
    indicator_id: Optional[str] = None; type: Optional[IOCType] = None; value: Optional[str] = None
    sources: List[EnrichSource] = Field(default_factory=lambda: [EnrichSource.VIRUSTOTAL])

class IndicatorEnrichResponse(BaseModel):
    indicator_id: Optional[str]; type: IOCType; value: str; enrichment: List[IndicatorEnrichmentData]

class IndicatorStatsResponse(BaseModel):
    total_indicators: int; by_type: Dict[str, int]; by_confidence: Dict[str, int]; by_source: Dict[str, int]
    by_status: Dict[str, int]; active_count: int; expired_count: int; false_positive_count: int

class IndicatorSearchParams(BaseModel):
    q: Optional[str] = Field(default=None); type: Optional[IOCType] = None; confidence: Optional[ConfidenceLevel] = None
    status: Optional[IndicatorStatus] = None; tlp: Optional[TLPMarking] = None; source: Optional[str] = None
    tags: Optional[List[str]] = None; valid_from: Optional[datetime] = None; valid_until: Optional[datetime] = None
    created_after: Optional[datetime] = None; created_before: Optional[datetime] = None


class ActorAlias(BaseModel):
    name: str; source: Optional[str] = None

class ActorTTP(BaseModel):
    technique_id: str; technique_name: str; tactic: str; description: Optional[str] = None
    first_seen: Optional[datetime] = None; last_seen: Optional[datetime] = None

class ActorCampaign(BaseModel):
    campaign_id: str; name: str; first_seen: Optional[datetime] = None; last_seen: Optional[datetime] = None

class ActorResponse(BaseEntity):
    name: str; description: Optional[str]; threat_level: ActorThreatLevel; aliases: List[str]
    motivation: Optional[str]; first_seen: Optional[datetime]; last_seen: Optional[datetime]
    origin_countries: List[str]; targeted_sectors: List[Sector]; campaign_count: int = 0

class ActorDetailResponse(ActorResponse):
    full_aliases: List[ActorAlias] = Field(default_factory=list); ttps: List[ActorTTP] = Field(default_factory=list)
    campaigns: List[ActorCampaign] = Field(default_factory=list)
    targeted_sectors_detail: List[Dict[str, Any]] = Field(default_factory=list)
    tools: List[Dict[str, Any]] = Field(default_factory=list); associated_groups: List[Dict[str, str]] = Field(default_factory=list)
    external_references: List[Dict[str, str]] = Field(default_factory=list)


class CampaignTimelineEntry(BaseModel):
    timestamp: datetime; event: str; description: Optional[str] = None
    indicators_involved: List[str] = Field(default_factory=list)

class CampaignResponse(BaseEntity):
    name: str; description: Optional[str]; status: CampaignStatus; threat_actors: List[Dict[str, str]]
    first_seen: Optional[datetime]; last_seen: Optional[datetime]; targeted_sectors: List[Sector]
    targeted_countries: List[str]; indicator_count: int = 0

class CampaignDetailResponse(CampaignResponse):
    aliases: List[str] = Field(default_factory=list); objectives: Optional[str] = None
    timeline: List[CampaignTimelineEntry] = Field(default_factory=list)
    associated_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)
    external_references: List[Dict[str, str]] = Field(default_factory=list)


class TTPResponse(BaseEntity):
    technique_id: str; name: str; tactic: str; description: Optional[str]; platforms: List[str]
    data_sources: List[str]; detection_recommendations: Optional[str]

class TTPDetailResponse(TTPResponse):
    mitre_id: str; mitre_url: str; sub_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    mitigations: List[Dict[str, Any]] = Field(default_factory=list); detections: List[Dict[str, Any]] = Field(default_factory=list)
    procedure_examples: List[Dict[str, Any]] = Field(default_factory=list)
    references: List[Dict[str, str]] = Field(default_factory=list)
    related_actors: List[Dict[str, str]] = Field(default_factory=list)
    related_campaigns: List[Dict[str, str]] = Field(default_factory=list)


class MitreTactic(BaseModel):
    id: str; name: str; description: str; short_name: str

class MitreTechnique(BaseModel):
    id: str; name: str; description: str; tactics: List[str]; platforms: List[str]
    is_subtechnique: bool = False; parent_technique_id: Optional[str] = None

class MitreEnterpriseResponse(BaseModel):
    domain: str = "enterprise"; version: str; tactics: List[MitreTactic]; techniques: List[MitreTechnique]

class MitreSubTechnique(BaseModel):
    id: str; name: str; description: str; platforms: List[str]

class MitreMitigation(BaseModel):
    id: str; name: str; description: str

class MitreDetection(BaseModel):
    data_source: Optional[str] = None; description: str

class MitreTechniqueDetailResponse(BaseModel):
    id: str; name: str; description: str; tactics: List[str]; platforms: List[str]; data_sources: List[str]
    detection_recommendations: List[MitreDetection]
    sub_techniques: List[MitreSubTechnique] = Field(default_factory=list)
    mitigations: List[MitreMitigation] = Field(default_factory=list)
    procedure_examples: List[Dict[str, Any]] = Field(default_factory=list)
    references: List[Dict[str, str]] = Field(default_factory=list)
    related_threat_actors: List[Dict[str, str]] = Field(default_factory=list)

class MitreHeatmapEntry(BaseModel):
    technique_id: str; technique_name: str; tactic: str
    score: float = Field(ge=0.0, le=100.0); detection_count: int = 0; alert_count: int = 0

class MitreHeatmapResponse(BaseModel):
    tenant_id: str; generated_at: datetime; total_techniques: int; matrix: List[MitreHeatmapEntry]
    coverage_percentage: float


class ReputationSource(BaseModel):
    source: str; score: Optional[int] = None; categories: List[str] = Field(default_factory=list)
    last_updated: Optional[datetime] = None; details: Optional[Dict[str, Any]] = None

class IPLookupResponse(BaseModel):
    ip: str; is_malicious: bool; reputation_score: Optional[int] = Field(None, ge=0, le=100)
    sources: List[ReputationSource] = Field(default_factory=list); geolocation: Optional[Dict[str, Any]] = None
    asn: Optional[Dict[str, Any]] = None; isp: Optional[str] = None; hosting_provider: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list); related_domains: List[str] = Field(default_factory=list)
    related_hashes: List[str] = Field(default_factory=list); last_analysis_date: Optional[datetime] = None

class DomainLookupResponse(BaseModel):
    domain: str; is_malicious: bool; reputation_score: Optional[int] = Field(None, ge=0, le=100)
    sources: List[ReputationSource] = Field(default_factory=list); whois: Optional[Dict[str, Any]] = None
    dns_records: Optional[List[Dict[str, Any]]] = None; ssl_certificates: Optional[List[Dict[str, Any]]] = None
    subdomains: List[str] = Field(default_factory=list); resolved_ips: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list); last_analysis_date: Optional[datetime] = None

class HashLookupResponse(BaseModel):
    hash_value: str; hash_type: str; is_malicious: bool; reputation_score: Optional[int] = Field(None, ge=0, le=100)
    sources: List[ReputationSource] = Field(default_factory=list); file_names: List[str] = Field(default_factory=list)
    file_type: Optional[str] = None; file_size: Optional[int] = None; malware_family: Optional[str] = None
    threat_label: Optional[str] = None; first_seen: Optional[datetime] = None; last_seen: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)

class URLLookupResponse(BaseModel):
    url: str; is_malicious: bool; reputation_score: Optional[int] = Field(None, ge=0, le=100)
    sources: List[ReputationSource] = Field(default_factory=list); final_url: Optional[str] = None
    http_status_code: Optional[int] = None; content_type: Optional[str] = None; threat_type: Optional[str] = None
    categories: List[str] = Field(default_factory=list); last_analysis_date: Optional[datetime] = None


class ReportResponse(BaseEntity):
    title: str; report_type: ReportType; status: ReportStatus; author: Optional[str]; summary: Optional[str]
    tlp: TLPMarking; tags: List[str]; published_at: Optional[datetime]; ioc_count: int = 0

class STIXObject(BaseModel):
    type: str; id: str; spec_version: Optional[str] = None; created: Optional[datetime] = None; modified: Optional[datetime] = None

class ReportDetailResponse(ReportResponse):
    content: Dict[str, Any] = Field(default_factory=dict); stix_bundle: Optional[Dict[str, Any]] = None
    indicators: List[IndicatorResponse] = Field(default_factory=list)
    threat_actors: List[ActorResponse] = Field(default_factory=list)
    campaigns: List[CampaignResponse] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)
    external_references: List[Dict[str, str]] = Field(default_factory=list)

class ReportGenerateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500); report_type: ReportType
    description: Optional[str] = None; time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None; include_indicators: bool = True; include_actors: bool = True
    include_campaigns: bool = True; include_mitre: bool = True
    threat_actor_ids: Optional[List[str]] = None; campaign_ids: Optional[List[str]] = None
    indicator_ids: Optional[List[str]] = None; tlp: TLPMarking = TLPMarking.AMBER
    tags: List[str] = Field(default_factory=list)

class ReportGenerateResponse(BaseModel):
    report_id: str; title: str; status: ReportStatus; created_at: datetime


class PaginatedFeeds(BaseModel):
    items: List[FeedResponse]; meta: PaginationMeta

class PaginatedIndicators(BaseModel):
    items: List[IndicatorResponse]; meta: PaginationMeta

class PaginatedActors(BaseModel):
    items: List[ActorResponse]; meta: PaginationMeta

class PaginatedCampaigns(BaseModel):
    items: List[CampaignResponse]; meta: PaginationMeta

class PaginatedTTPs(BaseModel):
    items: List[TTPResponse]; meta: PaginationMeta

class PaginatedReports(BaseModel):
    items: List[ReportResponse]; meta: PaginationMeta


# =============================================================================
# HARDCODED THREAT INTELLIGENCE DATABASES
# =============================================================================

# ----- Threat Actors (26) -----
THREAT_ACTORS_DB = [
    {
        "id": "actor-apt28",
        "name": "APT28",
        "aliases": [
            "Fancy Bear",
            "Sofacy",
            "Sednit",
            "Strontium",
            "Pawn Storm",
            "Tsar Team",
            "TG-4127"
        ],
        "description": "Russian military intelligence (GRU) cyber espionage group active since at least 2007. Targets government, military, and security organizations worldwide. Known for election interference and destructive attacks.",
        "threat_level": "critical",
        "motivation": "espionage, political, sabotage",
        "targeted_sectors": [
            "government",
            "defense",
            "energy",
            "technology",
            "education"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "UA",
            "PL",
            "EE",
            "LT",
            "LV",
            "NO"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "X-Agent",
            "X-Tunnel",
            "ChopStick",
            "Zebrocy",
            "Downdelph",
            "BlackEnergy",
            "Mimikatz"
        ],
        "mitre_techniques": [
            "T1566",
            "T1190",
            "T1059",
            "T1027",
            "T1003",
            "T1071",
            "T1105",
            "T1082",
            "T1041"
        ],
        "first_seen": "2007-01-01T00:00:00Z",
        "last_seen": "2025-06-15T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "Cozy Bear",
            "Sandworm",
            "Turla"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/apt28"
            },
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0007/"
            }
        ]
    },
    {
        "id": "actor-apt29",
        "name": "APT29",
        "aliases": [
            "Cozy Bear",
            "The Dukes",
            "Yttrium",
            "Nobelium",
            "Midnight Blizzard"
        ],
        "description": "Russian foreign intelligence (SVR) cyber espionage group. Known for sophisticated spear-phishing and supply chain attacks. Responsible for SolarWinds supply chain compromise.",
        "threat_level": "critical",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "defense",
            "technology",
            "healthcare",
            "finance",
            "energy"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "JP",
            "KR",
            "CA",
            "AU",
            "NL"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Sunburst",
            "Teardrop",
            "Raindrop",
            "GoldMax",
            "Sibot",
            "Cobalt Strike",
            "Mimikatz",
            "PowerSploit"
        ],
        "mitre_techniques": [
            "T1195",
            "T1566",
            "T1059",
            "T1027",
            "T1003",
            "T1071",
            "T1105",
            "T1547",
            "T1485"
        ],
        "first_seen": "2010-01-01T00:00:00Z",
        "last_seen": "2025-05-20T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT28",
            "Turla"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/apt29"
            },
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0016/"
            }
        ]
    },
    {
        "id": "actor-lazarus",
        "name": "Lazarus Group",
        "aliases": [
            "Hidden Cobra",
            "ZINC",
            "Diamond Sleet",
            "Appleworm",
            "Labyrinth Chollima"
        ],
        "description": "North Korean state-sponsored APT group with subgroups (BlueNoroff, Andariel). Conducts cyber espionage, financial theft, and destructive attacks. Responsible for WannaCry, Sony Pictures hack, Bangladesh Bank heist.",
        "threat_level": "critical",
        "motivation": "espionage, financial, sabotage",
        "targeted_sectors": [
            "finance",
            "government",
            "defense",
            "technology",
            "energy",
            "healthcare"
        ],
        "targeted_countries": [
            "US",
            "KR",
            "JP",
            "IN",
            "VN",
            "SG",
            "GB",
            "AU"
        ],
        "origin_countries": [
            "KP"
        ],
        "tools_used": [
            "WannaCry",
            "AppleJeus",
            "Hoplight",
            "Dtrack",
            "Destover",
            "FallChill",
            "BADCALL",
            "Copperhedge"
        ],
        "mitre_techniques": [
            "T1566",
            "T1190",
            "T1059",
            "T1027",
            "T1003",
            "T1485",
            "T1562",
            "T1082",
            "T1071"
        ],
        "first_seen": "2009-01-01T00:00:00Z",
        "last_seen": "2025-07-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "BlueNoroff",
            "Andariel",
            "Kimsuky"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/lazarus"
            },
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0032/"
            }
        ]
    },
    {
        "id": "actor-fin7",
        "name": "FIN7",
        "aliases": [
            "Carbanak",
            "Anunak",
            "Cobalt Group",
            "Sangria Tempest",
            "Carbon Spider"
        ],
        "description": "Financially motivated cybercrime group operating since 2013. Known for point-of-sale malware, Carbanak backdoor, and sophisticated phishing targeting hospitality and retail.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "retail",
            "finance",
            "transportation",
            "manufacturing"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "IT",
            "ES",
            "AU",
            "CA"
        ],
        "origin_countries": [
            "RU",
            "UA"
        ],
        "tools_used": [
            "Carbanak",
            "Cobalt Strike",
            "Pillowmint",
            "DiceLoader",
            "PowGoop",
            "GRIFFON",
            "Bateleur"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1105",
            "T1003",
            "T1027",
            "T1071",
            "T1190",
            "T1547"
        ],
        "first_seen": "2013-01-01T00:00:00Z",
        "last_seen": "2025-04-10T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "FIN10",
            "FIN11"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0046/"
            }
        ]
    },
    {
        "id": "actor-apt41",
        "name": "APT41",
        "aliases": [
            "Double Dragon",
            "Wicked Panda",
            "Barium",
            "Winnti Group",
            "Gold Growth"
        ],
        "description": "Chinese state-sponsored cyber espionage group also conducting financially motivated operations. Targets healthcare, technology, telecom, and government sectors across 14+ countries.",
        "threat_level": "critical",
        "motivation": "espionage, financial",
        "targeted_sectors": [
            "government",
            "healthcare",
            "technology",
            "telecommunications",
            "manufacturing"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "JP",
            "IN",
            "AU",
            "CA",
            "KR",
            "TW"
        ],
        "origin_countries": [
            "CN"
        ],
        "tools_used": [
            "Winnti",
            "BOUNCER",
            "Cobalt Strike",
            "PlugX",
            "ShadowPad",
            "Gh0stRAT",
            "Crosswalk",
            "KEYPLUG"
        ],
        "mitre_techniques": [
            "T1566",
            "T1190",
            "T1059",
            "T1027",
            "T1003",
            "T1547",
            "T1082",
            "T1071",
            "T1562"
        ],
        "first_seen": "2012-01-01T00:00:00Z",
        "last_seen": "2025-06-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT10",
            "APT27",
            "Mustang Panda"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0096/"
            }
        ]
    },
    {
        "id": "actor-sandworm",
        "name": "Sandworm",
        "aliases": [
            "Voodoo Bear",
            "IRIDIUM",
            "TeleBots",
            "BlackEnergy",
            "Seashell Blizzard"
        ],
        "description": "Russian GRU affiliated cyber military unit (Unit 74455). Conducted destructive attacks including NotPetya, Ukraine power grid attacks, and Olympic Destroyer.",
        "threat_level": "critical",
        "motivation": "sabotage, espionage",
        "targeted_sectors": [
            "government",
            "energy",
            "defense",
            "critical_infrastructure",
            "transportation"
        ],
        "targeted_countries": [
            "UA",
            "US",
            "GB",
            "DE",
            "FR",
            "PL",
            "GE"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Industroyer",
            "CrashOverride",
            "NotPetya",
            "OlympicDestroyer",
            "BlackEnergy3",
            "GreyEnergy",
            "KillDisk"
        ],
        "mitre_techniques": [
            "T1485",
            "T1562",
            "T1071",
            "T1027",
            "T1105",
            "T1036",
            "T1210",
            "T1195"
        ],
        "first_seen": "2014-01-01T00:00:00Z",
        "last_seen": "2025-03-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT28",
            "Turla"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0034/"
            }
        ]
    },
    {
        "id": "actor-hafnium",
        "name": "HAFNIUM",
        "aliases": [
            "Hafnium",
            "Silk Typhoon"
        ],
        "description": "Chinese state-sponsored APT group exploiting Microsoft Exchange Server vulnerabilities. Conducted large-scale cyber espionage targeting US defense, think tanks, and infectious disease researchers.",
        "threat_level": "critical",
        "motivation": "espionage",
        "targeted_sectors": [
            "defense",
            "healthcare",
            "government",
            "education",
            "technology"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "CA",
            "AU",
            "DE",
            "FR",
            "JP",
            "KR"
        ],
        "origin_countries": [
            "CN"
        ],
        "tools_used": [
            "China Chopper",
            "ASPXSpy",
            "DealersChoice",
            "AntSword",
            "Godzilla",
            "Behinder"
        ],
        "mitre_techniques": [
            "T1190",
            "T1505",
            "T1059",
            "T1027",
            "T1071",
            "T1105",
            "T1041",
            "T1562"
        ],
        "first_seen": "2021-01-01T00:00:00Z",
        "last_seen": "2025-02-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT41",
            "APT10"
        ],
        "external_references": [
            {
                "source": "Microsoft",
                "url": "https://www.microsoft.com/security/blog/2021/03/02"
            }
        ]
    },
    {
        "id": "actor-lapsus",
        "name": "LAPSUS$",
        "aliases": [
            "DEV-0537",
            "Strawberry Tempest"
        ],
        "description": "Extremely aggressive cyber extortion group targeting major technology companies (Microsoft, NVIDIA, Samsung, Okta, Uber). Uses bribery and SIM swapping for initial access.",
        "threat_level": "critical",
        "motivation": "financial, hacktivism",
        "targeted_sectors": [
            "technology",
            "telecommunications",
            "finance",
            "retail"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "BR",
            "PT"
        ],
        "origin_countries": [
            "GB",
            "BR"
        ],
        "tools_used": [
            "Redline Stealer",
            "Mimikatz",
            "Socelars",
            "Sliver",
            "PSExec",
            "Ngrok"
        ],
        "mitre_techniques": [
            "T1566",
            "T1078",
            "T1003",
            "T1562",
            "T1499",
            "T1486",
            "T1485",
            "T1059"
        ],
        "first_seen": "2021-12-01T00:00:00Z",
        "last_seen": "2024-03-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "Scattered Spider"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/lapsus"
            }
        ]
    },
    {
        "id": "actor-lockbit",
        "name": "LockBit",
        "aliases": [
            "LockBit Gang",
            "Bitwise Spider",
            "ABCD Ransomware"
        ],
        "description": "Most prolific ransomware-as-a-service (RaaS) operation. Known for fast encryption, triple extortion, and affiliate model with custom LockBit builder.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "healthcare",
            "manufacturing",
            "finance",
            "education",
            "government",
            "energy"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "IT",
            "CA",
            "AU",
            "JP"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "LockBit ransomware",
            "StealBit",
            "PsExec",
            "Cobalt Strike",
            "Mimikatz",
            "SoftPerfect"
        ],
        "mitre_techniques": [
            "T1486",
            "T1485",
            "T1562",
            "T1490",
            "T1041",
            "T1059",
            "T1003",
            "T1027",
            "T1071"
        ],
        "first_seen": "2019-09-01T00:00:00Z",
        "last_seen": "2025-06-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "ALPHV",
            "Conti"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/lockbit"
            }
        ]
    },
    {
        "id": "actor-alphv",
        "name": "ALPHV",
        "aliases": [
            "BlackCat",
            "Noberus"
        ],
        "description": "Advanced ransomware-as-a-service gang using Rust-based ransomware. First major RaaS written in Rust, known for aggressive victim shaming and triple extortion.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "healthcare",
            "manufacturing",
            "finance",
            "education",
            "technology"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "IT",
            "CA",
            "AU"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "BlackCat ransomware",
            "Exmatter",
            "Fendr",
            "PsExec",
            "Cobalt Strike",
            "Mimikatz"
        ],
        "mitre_techniques": [
            "T1486",
            "T1485",
            "T1562",
            "T1490",
            "T1041",
            "T1059",
            "T1003",
            "T1027"
        ],
        "first_seen": "2021-11-01T00:00:00Z",
        "last_seen": "2024-09-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "LockBit",
            "DarkSide"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/alphv-blackcat"
            }
        ]
    },
    {
        "id": "actor-clop",
        "name": "Clop",
        "aliases": [
            "TA505",
            "Cl0p",
            "Lace Tempest",
            "Dudear",
            "Graceful Spider",
            "Gold Garden"
        ],
        "description": "Long-running cybercrime group known for CL0P ransomware, Dridex banking trojan, and massive MFT exploits (MOVEit, GoAnywhere, Accellion). One of most prolific data extortion groups.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "finance",
            "government",
            "healthcare",
            "education",
            "technology",
            "retail"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "AU",
            "CA",
            "NL",
            "CH"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Clop ransomware",
            "TrueBot",
            "GraceWire",
            "FlawedAmmyy",
            "Dridex",
            "SDBbot",
            "Get2"
        ],
        "mitre_techniques": [
            "T1566",
            "T1190",
            "T1486",
            "T1041",
            "T1027",
            "T1059",
            "T1105",
            "T1003",
            "T1562"
        ],
        "first_seen": "2014-01-01T00:00:00Z",
        "last_seen": "2025-07-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "FIN11",
            "FIN7"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0092/"
            }
        ]
    },
    {
        "id": "actor-revil",
        "name": "REvil",
        "aliases": [
            "Sodinokibi",
            "Sodin",
            "Gold Southfield"
        ],
        "description": "Notorious ransomware-as-a-service group responsible for Kaseya supply chain attack and JBS Foods ransomware. Pioneered double extortion tactics.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "technology",
            "manufacturing",
            "energy",
            "healthcare",
            "retail"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "AU",
            "JP",
            "BR",
            "IT"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Sodinokibi ransomware",
            "Cobalt Strike",
            "Mimikatz",
            "PsExec",
            "Rclone"
        ],
        "mitre_techniques": [
            "T1195",
            "T1486",
            "T1562",
            "T1490",
            "T1041",
            "T1059",
            "T1003",
            "T1027",
            "T1071"
        ],
        "first_seen": "2019-04-01T00:00:00Z",
        "last_seen": "2023-10-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "DarkSide",
            "GandCrab"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/revil"
            }
        ]
    },
    {
        "id": "actor-darkside",
        "name": "DarkSide",
        "aliases": [
            "BlackMatter"
        ],
        "description": "Ransomware-as-a-service group responsible for Colonial Pipeline attack causing fuel shortages across US East Coast. Pioneered ransomware cartel model.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "energy",
            "manufacturing",
            "healthcare",
            "finance",
            "transportation"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "AU",
            "CA"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "DarkSide ransomware",
            "Cobalt Strike",
            "Mimikatz",
            "PsExec",
            "PowerShell Empire"
        ],
        "mitre_techniques": [
            "T1486",
            "T1485",
            "T1562",
            "T1490",
            "T1041",
            "T1059",
            "T1003",
            "T1071",
            "T1105"
        ],
        "first_seen": "2020-08-01T00:00:00Z",
        "last_seen": "2022-06-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "REvil",
            "ALPHV"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/darkside"
            }
        ]
    },
    {
        "id": "actor-conti",
        "name": "Conti",
        "aliases": [
            "Wizard Spider",
            "Ryuk",
            "Grim Spider",
            "Gold Ulrick"
        ],
        "description": "Russian-speaking ransomware group responsible for hundreds of attacks. Known for double extortion, aggressive negotiation, and supporting Russian government during Ukraine war. Leaked chats revealed corporate structure.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "healthcare",
            "government",
            "manufacturing",
            "finance",
            "education"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "IT",
            "AU",
            "CA",
            "IE"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Conti ransomware",
            "Trickbot",
            "BazarLoader",
            "Cobalt Strike",
            "Mimikatz",
            "IcedID",
            "Emotet"
        ],
        "mitre_techniques": [
            "T1566",
            "T1486",
            "T1562",
            "T1490",
            "T1041",
            "T1059",
            "T1003",
            "T1027",
            "T1071",
            "T1105"
        ],
        "first_seen": "2019-12-01T00:00:00Z",
        "last_seen": "2023-06-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "Ryuk",
            "TrickBot",
            "Emotet"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/conti"
            }
        ]
    },
    {
        "id": "actor-wizard-spider",
        "name": "Wizard Spider",
        "aliases": [
            "Grim Spider",
            "Lunar Spider",
            "Gold Blackburn",
            "DEV-0193"
        ],
        "description": "Sophisticated cybercrime group behind Trickbot and Ryuk ransomware. Operates as hierarchical enterprise with HR, legal, and finance departments.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "government",
            "healthcare",
            "education",
            "finance",
            "manufacturing"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "CA",
            "AU",
            "IT",
            "NL"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "TrickBot",
            "Ryuk",
            "Anchor",
            "BazarLoader",
            "Cobalt Strike",
            "Mimikatz",
            "AdFind"
        ],
        "mitre_techniques": [
            "T1566",
            "T1486",
            "T1059",
            "T1003",
            "T1027",
            "T1071",
            "T1105",
            "T1547",
            "T1562"
        ],
        "first_seen": "2016-01-01T00:00:00Z",
        "last_seen": "2024-12-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "Conti",
            "Ryuk"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0102/"
            }
        ]
    },
    {
        "id": "actor-mustang-panda",
        "name": "Mustang Panda",
        "aliases": [
            "Bronze President",
            "RedDelta",
            "HoneyMyte",
            "Camaro Dragon",
            "Earth Preta"
        ],
        "description": "Chinese APT group conducting cyber espionage across Southeast Asia, Europe, and Africa. Uses spear-phishing with geopolitical lures targeting NGOs, religious organizations, and government entities.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "education",
            "manufacturing",
            "telecommunications"
        ],
        "targeted_countries": [
            "TW",
            "MM",
            "VN",
            "MN",
            "PH",
            "TR",
            "DE",
            "GB"
        ],
        "origin_countries": [
            "CN"
        ],
        "tools_used": [
            "PlugX",
            "Cobalt Strike",
            "Viper",
            "Korplug",
            "Nightdoor",
            "TONEINS",
            "Hudinx"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1027",
            "T1003",
            "T1082",
            "T1071",
            "T1105",
            "T1547"
        ],
        "first_seen": "2013-01-01T00:00:00Z",
        "last_seen": "2025-04-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT41",
            "APT10"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0129/"
            }
        ]
    },
    {
        "id": "actor-kimsuky",
        "name": "Kimsuky",
        "aliases": [
            "Velvet Chollima",
            "Black Banshee",
            "Thallium",
            "Emerald Sleet"
        ],
        "description": "North Korean APT group focused on intelligence collection. Targets primarily South Korean government, think tanks, academia, and nuclear energy sector. Uses sophisticated social engineering.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "defense",
            "education",
            "energy",
            "healthcare"
        ],
        "targeted_countries": [
            "KR",
            "JP",
            "US",
            "RU",
            "CN",
            "GB"
        ],
        "origin_countries": [
            "KP"
        ],
        "tools_used": [
            "AppleSeed",
            "BabyShark",
            "PebbleDash",
            "SmokeScreen",
            "Rifdoor",
            "Gh0stRAT",
            "KGH_SPY"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1003",
            "T1082",
            "T1071",
            "T1105",
            "T1027",
            "T1547"
        ],
        "first_seen": "2012-01-01T00:00:00Z",
        "last_seen": "2025-05-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "Lazarus Group",
            "Andariel"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0094/"
            }
        ]
    },
    {
        "id": "actor-turla",
        "name": "Turla",
        "aliases": [
            "Snake",
            "Venomous Bear",
            "Waterbug",
            "Uroburos",
            "Iron Hunter",
            "Pensive Ursa"
        ],
        "description": "Russian FSB cyber espionage group operating since 2004. Known for satellite-based C2, hijacked infrastructure, and Uroburos rootkit. Targets diplomatic and military organizations.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "defense",
            "education",
            "energy",
            "technology"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "DE",
            "FR",
            "SE",
            "CH",
            "UA",
            "GE"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Snake",
            "Uroburos",
            "Carbon",
            "Crutch",
            "Kazuar",
            "Mosquito",
            "Neuron",
            "MiniDuke",
            "Komplex"
        ],
        "mitre_techniques": [
            "T1566",
            "T1190",
            "T1059",
            "T1027",
            "T1003",
            "T1071",
            "T1105",
            "T1082",
            "T1547"
        ],
        "first_seen": "2004-01-01T00:00:00Z",
        "last_seen": "2025-03-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT28",
            "APT29"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0010/"
            }
        ]
    },
    {
        "id": "actor-oilrig",
        "name": "OilRig",
        "aliases": [
            "APT34",
            "Helix Kitten",
            "Crambus",
            "Twisted Kitten",
            "Hazel Sandstorm"
        ],
        "description": "Iranian state-sponsored cyber espionage group. Targets Middle Eastern governments, energy sector, financial services, and defense. Known for delivering various custom backdoors.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "energy",
            "finance",
            "technology",
            "defense"
        ],
        "targeted_countries": [
            "SA",
            "AE",
            "QA",
            "KW",
            "IL",
            "TR",
            "LB",
            "JO"
        ],
        "origin_countries": [
            "IR"
        ],
        "tools_used": [
            "BONDUPDATER",
            "ISMAgent",
            "DNSpionage",
            "PowGoop",
            "ValueVault",
            "Webmask",
            "QuadAgent"
        ],
        "mitre_techniques": [
            "T1566",
            "T1078",
            "T1059",
            "T1027",
            "T1003",
            "T1082",
            "T1071",
            "T1105",
            "T1041"
        ],
        "first_seen": "2014-01-01T00:00:00Z",
        "last_seen": "2025-05-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT33",
            "APT35"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0049/"
            }
        ]
    },
    {
        "id": "actor-apt33",
        "name": "APT33",
        "aliases": [
            "Elfin",
            "Magnallium",
            "Refined Kitten",
            "Peach Sandstorm",
            "Holmium"
        ],
        "description": "Iranian APT group targeting aviation, defense, petrochemical, and energy sectors. Known for destructive wipers (Shamoon) and aerospace espionage.",
        "threat_level": "high",
        "motivation": "espionage, sabotage",
        "targeted_sectors": [
            "defense",
            "energy",
            "manufacturing",
            "government",
            "technology"
        ],
        "targeted_countries": [
            "US",
            "SA",
            "KR",
            "AE",
            "GB",
            "DE"
        ],
        "origin_countries": [
            "IR"
        ],
        "tools_used": [
            "Shamoon",
            "DropShot",
            "ShapeShift",
            "Powerton",
            "TurnedUp",
            "NANOCORE",
            "AutoIt"
        ],
        "mitre_techniques": [
            "T1566",
            "T1485",
            "T1059",
            "T1027",
            "T1003",
            "T1071",
            "T1105",
            "T1562"
        ],
        "first_seen": "2013-01-01T00:00:00Z",
        "last_seen": "2025-03-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "OilRig",
            "Charming Kitten"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0064/"
            }
        ]
    },
    {
        "id": "actor-scattered-spider",
        "name": "Scattered Spider",
        "aliases": [
            "Octo Tempest",
            "0ktapus",
            "UNC3944",
            "Scatter Swine"
        ],
        "description": "Highly sophisticated social engineering group targeting telecom, BPO, and technology sectors. Known for SIM swapping, MFA fatigue attacks, and Okta compromises leading to ransomware deployments.",
        "threat_level": "critical",
        "motivation": "financial",
        "targeted_sectors": [
            "telecommunications",
            "technology",
            "retail",
            "finance",
            "transportation"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "CA",
            "AU"
        ],
        "origin_countries": [
            "US",
            "GB"
        ],
        "tools_used": [
            "Mimikatz",
            "Cobalt Strike",
            "Rclone",
            "Ngrok",
            "Octo",
            "MFA Bombing Scripts"
        ],
        "mitre_techniques": [
            "T1566",
            "T1078",
            "T1621",
            "T1003",
            "T1562",
            "T1059",
            "T1486",
            "T1041"
        ],
        "first_seen": "2022-05-01T00:00:00Z",
        "last_seen": "2025-07-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "LAPSUS$",
            "ALPHV"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/scattered-spider"
            }
        ]
    },
    {
        "id": "actor-apt40",
        "name": "APT40",
        "aliases": [
            "Leviathan",
            "TEMP.Periscope",
            "BRONZE MOHAWK",
            "Gadolinium"
        ],
        "description": "Chinese APT group targeting maritime and defense industries. Focuses on naval technologies, shipbuilding, and defense contractors across Southeast Asia and Pacific region.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "defense",
            "transportation",
            "government",
            "technology"
        ],
        "targeted_countries": [
            "US",
            "AU",
            "JP",
            "KR",
            "IN",
            "TW",
            "PH",
            "SG"
        ],
        "origin_countries": [
            "CN"
        ],
        "tools_used": [
            "Gh0stRAT",
            "PlugX",
            "China Chopper",
            "Cobalt Strike",
            "BEACON",
            "Taidoor"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1027",
            "T1003",
            "T1082",
            "T1071",
            "T1105",
            "T1041"
        ],
        "first_seen": "2013-01-01T00:00:00Z",
        "last_seen": "2025-01-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT41",
            "APT10"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0065/"
            }
        ]
    },
    {
        "id": "actor-gamaredon",
        "name": "Gamaredon Group",
        "aliases": [
            "Primitive Bear",
            "Armageddon",
            "Shuckworm",
            "Actinium"
        ],
        "description": "Russian FSB cyber espionage group exclusively targeting Ukrainian entities since 2013. Prolific spear-phishing campaigns and custom Pterodo backdoor.",
        "threat_level": "high",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "defense",
            "energy",
            "critical_infrastructure"
        ],
        "targeted_countries": [
            "UA"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Pterodo",
            "Pteranodon",
            "Minertin",
            "PowerShell implants",
            "UltraVNC",
            "RevengeRAT"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1027",
            "T1003",
            "T1082",
            "T1071",
            "T1105",
            "T1547"
        ],
        "first_seen": "2013-01-01T00:00:00Z",
        "last_seen": "2025-07-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT28",
            "Sandworm"
        ],
        "external_references": [
            {
                "source": "MITRE",
                "url": "https://attack.mitre.org/groups/G0047/"
            }
        ]
    },
    {
        "id": "actor-unc2452",
        "name": "UNC2452",
        "aliases": [
            "Nobelium",
            "Dark Halo",
            "SolarStorm"
        ],
        "description": "Threat actor behind the SolarWinds supply chain compromise. Operated sophisticated trojanized software updates to gain access to thousands of organizations globally.",
        "threat_level": "critical",
        "motivation": "espionage",
        "targeted_sectors": [
            "government",
            "technology",
            "defense",
            "finance",
            "healthcare",
            "energy"
        ],
        "targeted_countries": [
            "US",
            "UK",
            "CA",
            "AU",
            "IL",
            "MX",
            "ES"
        ],
        "origin_countries": [
            "RU"
        ],
        "tools_used": [
            "Sunburst",
            "Supernova",
            "Teardrop",
            "Raindrop",
            "GoldMax",
            "Sibot",
            "Cobalt Strike"
        ],
        "mitre_techniques": [
            "T1195",
            "T1059",
            "T1027",
            "T1003",
            "T1071",
            "T1547",
            "T1105",
            "T1082",
            "T1562"
        ],
        "first_seen": "2019-10-01T00:00:00Z",
        "last_seen": "2021-12-01T00:00:00Z",
        "confidence": "high",
        "associated_groups": [
            "APT29"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/solarwinds"
            }
        ]
    },
    {
        "id": "actor-ghostwriter",
        "name": "Ghostwriter",
        "aliases": [
            "UNC1151",
            "Pushcha",
            "TA473"
        ],
        "description": "Belarus-linked/Russian threat actor conducting influence operations, disinformation, and credential harvesting targeting NATO member states.",
        "threat_level": "medium",
        "motivation": "espionage, political",
        "targeted_sectors": [
            "government",
            "defense",
            "education",
            "media"
        ],
        "targeted_countries": [
            "LT",
            "LV",
            "PL",
            "UA",
            "DE",
            "US",
            "GB"
        ],
        "origin_countries": [
            "BY",
            "RU"
        ],
        "tools_used": [
            "AgentTesla",
            "FormBook",
            "Lokibot",
            "NetWire",
            "RevengeRAT"
        ],
        "mitre_techniques": [
            "T1566",
            "T1059",
            "T1003",
            "T1027",
            "T1071",
            "T1105",
            "T1082"
        ],
        "first_seen": "2017-01-01T00:00:00Z",
        "last_seen": "2025-05-01T00:00:00Z",
        "confidence": "medium",
        "associated_groups": [
            "APT28",
            "Sandworm"
        ],
        "external_references": [
            {
                "source": "CISA",
                "url": "https://www.cisa.gov/ghostwriter"
            }
        ]
    }
]

# ----- Campaigns (15) -----
CAMPAIGNS_DB = [
    {"id": "camp-solarwinds", "name": "SolarWinds Supply Chain Attack", "description": "Sophisticated supply chain compromise where attackers trojanized SolarWinds Orion platform updates, infiltrating approximately 18,000 organizations including US federal agencies and Fortune 500 companies.", "status": "completed", "threat_actors": [{"actor_id": "actor-apt29", "name": "APT29 (Cozy Bear)"}, {"actor_id": "actor-unc2452", "name": "UNC2452/Dark Halo"}], "start_date": "2019-10-01T00:00:00Z", "end_date": "2021-12-01T00:00:00Z", "targeted_sectors": ["government", "technology", "defense", "finance", "healthcare", "energy"], "targeted_countries": ["US", "UK", "CA", "AU", "IL", "MX", "ES"], "mitre_techniques": ["T1195", "T1059", "T1027", "T1003", "T1071", "T1547", "T1105", "T1082", "T1562"], "impact_description": "Compromised 18,000+ organizations. Exfiltrated sensitive government and corporate data. Multiple follow-on intrusions.", "aliases": ["Solorigate", "Sunburst", "Nobelium campaign"], "objectives": "Long-term intelligence collection. Establish persistent access across US government and technology sector.", "timeline": [{"timestamp": "2019-10-01T00:00:00Z", "event": "Initial breach of SolarWinds build environment"}, {"timestamp": "2020-12-13T00:00:00Z", "event": "FireEye discovers and publicly discloses breach"}, {"timestamp": "2021-01-01T00:00:00Z", "event": "CISA issues emergency directive for federal agencies"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/solarwinds"}]},
    {"id": "camp-colonial-pipeline", "name": "Colonial Pipeline Ransomware Attack", "description": "Ransomware attack by DarkSide group on Colonial Pipeline, the largest fuel pipeline in the US, causing widespread fuel shortages and triggering a national emergency.", "status": "completed", "threat_actors": [{"actor_id": "actor-darkside", "name": "DarkSide"}, {"actor_id": "actor-conti", "name": "Conti (affiliate)"}], "start_date": "2021-04-29T00:00:00Z", "end_date": "2021-06-01T00:00:00Z", "targeted_sectors": ["energy", "critical_infrastructure", "transportation"], "targeted_countries": ["US"], "mitre_techniques": ["T1486", "T1485", "T1562", "T1490", "T1041", "T1059"], "impact_description": "Pipeline operations halted for 6 days. 45 percent of US East Coast fuel supply disrupted. $4.4M ransom paid. States of emergency declared in 17 states.", "aliases": ["Pipeline shutdown attack"], "objectives": "Financial extortion through double extortion ransomware. Disrupt critical infrastructure for ransom leverage.", "timeline": [{"timestamp": "2021-04-29T00:00:00Z", "event": "Initial access via compromised VPN credentials"}, {"timestamp": "2021-05-07T00:00:00Z", "event": "Ransomware deployed. Pipeline operations halted"}, {"timestamp": "2021-06-07T00:00:00Z", "event": "DOJ recovers $2.3M of Bitcoin ransom"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/colonial-pipeline"}]},
    {"id": "camp-log4shell", "name": "Log4Shell (CVE-2021-44228) Exploitation", "description": "Widespread exploitation of critical Apache Log4j RCE vulnerability across every sector globally. Multiple state-sponsored and cybercriminal groups exploited to deploy ransomware, coin miners, and C2 frameworks.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-apt41", "name": "APT41"}, {"actor_id": "actor-lazarus", "name": "Lazarus"}, {"actor_id": "actor-hafnium", "name": "HAFNIUM"}, {"actor_id": "actor-conti", "name": "Conti"}], "start_date": "2021-12-01T00:00:00Z", "targeted_sectors": ["technology", "government", "finance", "healthcare", "education", "energy", "manufacturing", "retail", "telecommunications"], "targeted_countries": ["US", "UK", "DE", "FR", "JP", "AU", "CA", "IN", "BR"], "mitre_techniques": ["T1190", "T1059", "T1210", "T1486", "T1105", "T1071", "T1003"], "impact_description": "Billions of devices vulnerable. Widespread exploitation across all industries. CISA issued emergency directive. Ransomware attacks, data theft, cryptomining campaigns ongoing.", "aliases": ["CVE-2021-44228", "LogJam", "Apache Log4j vulnerability"], "objectives": "Exploit critical zero-day vulnerability for initial access, data exfiltration, ransomware deployment, and cryptomining.", "timeline": [{"timestamp": "2021-12-09T00:00:00Z", "event": "Zero-day exploitation first observed in the wild"}, {"timestamp": "2021-12-10T00:00:00Z", "event": "CVE-2021-44228 published. Widespread scanning begins"}, {"timestamp": "2021-12-17T00:00:00Z", "event": "CISA issues Emergency Directive 22-02"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/log4j"}]},
    {"id": "camp-proxynotshell", "name": "ProxyNotShell (CVE-2022-41040, CVE-2022-41082)", "description": "Exploitation of two zero-day vulnerabilities in Microsoft Exchange Server allowing SSRF and authenticated RCE. Used by state-sponsored actors for espionage.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-hafnium", "name": "HAFNIUM"}, {"actor_id": "actor-apt41", "name": "APT41"}], "start_date": "2022-09-01T00:00:00Z", "targeted_sectors": ["government", "defense", "technology", "finance", "education"], "targeted_countries": ["US", "UK", "DE", "FR", "AU", "JP"], "mitre_techniques": ["T1190", "T1059", "T1105", "T1071", "T1041", "T1505", "T1003"], "impact_description": "Thousands of Exchange servers worldwide exploited. Sensitive email data exfiltrated. Web shells deployed for persistent access.", "aliases": ["ProxyNotShell", "Exchange SSRF"], "objectives": "Gain persistent access to Microsoft Exchange servers for email exfiltration and lateral movement.", "timeline": [{"timestamp": "2022-09-30T00:00:00Z", "event": "Microsoft confirms two zero-day Exchange vulnerabilities"}, {"timestamp": "2022-11-08T00:00:00Z", "event": "Microsoft releases security updates for Exchange"}], "external_references": [{"source": "Microsoft", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040"}]},
    {"id": "camp-moveit", "name": "MOVEit Transfer Zero-Day Campaign", "description": "Mass exploitation of zero-day SQL injection vulnerability in Progress MOVEit Transfer (CVE-2023-34362) by Clop ransomware gang, affecting thousands of organizations and millions of individuals globally.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-clop", "name": "Clop (TA505)"}, {"actor_id": "actor-fin7", "name": "FIN7"}], "start_date": "2023-05-27T00:00:00Z", "targeted_sectors": ["government", "healthcare", "finance", "education", "technology", "energy"], "targeted_countries": ["US", "UK", "DE", "FR", "CA", "AU", "NL", "IE"], "mitre_techniques": ["T1190", "T1505", "T1041", "T1562", "T1003", "T1059", "T1105"], "impact_description": "Thousands of organizations affected. Largest MFT exploitation campaign in history. Over 60 million individuals impacted. Multiple state government agencies compromised.", "aliases": ["CVE-2023-34362", "MOVEit hack", "Clop MFT campaign"], "objectives": "Exploit zero-day vulnerability in MOVEit Transfer to exfiltrate sensitive data from thousands of organizations for extortion.", "timeline": [{"timestamp": "2023-05-27T00:00:00Z", "event": "Clop exploits zero-day, begins data exfiltration"}, {"timestamp": "2023-06-01T00:00:00Z", "event": "CISA issues advisory. Widespread exploitation confirmed"}, {"timestamp": "2023-06-14T00:00:00Z", "event": "Clop begins publishing victim data on leak site"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/moveit"}]},
    {"id": "camp-3cx", "name": "3CX Supply Chain Attack", "description": "Sophisticated supply chain attack where threat actors compromised 3CX DesktopApp software, trojanized the installer, and distributed to millions of users. Attributed to North Korean Lazarus Group.", "status": "completed", "threat_actors": [{"actor_id": "actor-lazarus", "name": "Lazarus Group"}], "start_date": "2022-12-01T00:00:00Z", "end_date": "2023-04-01T00:00:00Z", "targeted_sectors": ["technology", "finance", "government", "defense"], "targeted_countries": ["US", "UK", "KR", "CA", "AU", "DE"], "mitre_techniques": ["T1195", "T1059", "T1027", "T1003", "T1071", "T1105", "T1562", "T1547"], "impact_description": "600,000+ organizations potentially affected. Trojanized VoIP desktop application distributed. C2 infrastructure discovered before full exploitation. Second-stage targeting of cryptocurrency companies.", "aliases": ["SmoothOperator", "3CXDesktopApp supply chain"], "objectives": "Compromise software supply chain to infiltrate downstream target organizations, primarily cryptocurrency and financial services.", "timeline": [{"timestamp": "2023-03-22T00:00:00Z", "event": "Trojanized DLLs signed and distributed via updates"}, {"timestamp": "2023-03-29T00:00:00Z", "event": "CrowdStrike and SentinelOne detect and confirm attribution"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/3cx-supply-chain"}]},
    {"id": "camp-okta-breach", "name": "Okta/BeyondTrust Breach Campaign", "description": "Campaign by Scattered Spider leveraging social engineering on IT help desks including MGM Resorts and Caesars Entertainment. Used Okta credential harvesting to gain administrative access.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-scattered-spider", "name": "Scattered Spider"}, {"actor_id": "actor-alphv", "name": "ALPHV"}], "start_date": "2023-08-01T00:00:00Z", "targeted_sectors": ["technology", "telecommunications", "retail", "finance"], "targeted_countries": ["US", "UK", "CA"], "mitre_techniques": ["T1566", "T1078", "T1621", "T1003", "T1562", "T1059", "T1486", "T1041", "T1531"], "impact_description": "MGM Resorts: $100M+ in losses, operations disrupted for 10+ days. Caesars: $15M+ ransom paid. Multiple Okta tenant compromises.", "aliases": ["MGM Breach", "Caesars Hack", "Okta Social Engineering Campaign"], "objectives": "Financial extortion through ransomware and social engineering. Compromise identity provider access for broad lateral movement.", "timeline": [{"timestamp": "2023-09-07T00:00:00Z", "event": "MGM Resorts detects anomalous activity, takes systems offline"}, {"timestamp": "2023-09-14T00:00:00Z", "event": "Caesars discloses breach, ransom payment confirmed"}, {"timestamp": "2023-10-19T00:00:00Z", "event": "Okta confirms customer support system breach"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/okta-scattered-spider"}]},
    {"id": "camp-notpetya", "name": "NotPetya/EternalBlue Global Attack", "description": "Destructive wiper malware disguised as ransomware, initially spread through compromised Ukrainian accounting software (M.E.Doc) then propagated via EternalBlue. Caused $10B+ in global damages.", "status": "completed", "threat_actors": [{"actor_id": "actor-sandworm", "name": "Sandworm"}, {"actor_id": "actor-apt28", "name": "APT28"}], "start_date": "2017-06-27T00:00:00Z", "end_date": "2017-07-15T00:00:00Z", "targeted_sectors": ["manufacturing", "energy", "finance", "healthcare", "transportation", "government", "retail", "technology"], "targeted_countries": ["UA", "US", "UK", "DE", "FR", "DK", "IN", "AU", "RU", "IT", "ES"], "mitre_techniques": ["T1485", "T1195", "T1210", "T1486", "T1562", "T1082", "T1050"], "impact_description": "Estimated $10B+ in global damages. Maersk, Merck, FedEx, and thousands of others severely disrupted. Considered most destructive cyber attack in history.", "aliases": ["ExPetr", "Petya/NotPetya", "Nyetya", "GoldenEye"], "objectives": "Covert destructive attack against Ukraine. Disguised as ransomware but designed as irreversible wiper malware.", "timeline": [{"timestamp": "2017-06-27T09:00:00Z", "event": "NotPetya released via trojanized M.E.Doc update"}, {"timestamp": "2017-06-28T00:00:00Z", "event": "Thousands of organizations compromised across 65+ countries"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/notpetya"}]},
    {"id": "camp-wannacry", "name": "WannaCry Ransomware Global Attack", "description": "Global ransomware worm using EternalBlue exploit to propagate across SMB protocol. Affected 200,000+ computers across 150 countries. Attributed to North Korean Lazarus Group.", "status": "completed", "threat_actors": [{"actor_id": "actor-lazarus", "name": "Lazarus Group"}], "start_date": "2017-05-12T00:00:00Z", "end_date": "2017-05-19T00:00:00Z", "targeted_sectors": ["healthcare", "government", "manufacturing", "education", "telecommunications", "finance", "transportation"], "targeted_countries": ["GB", "US", "RU", "CN", "IN", "ES", "FR", "DE", "JP", "KR"], "mitre_techniques": ["T1210", "T1486", "T1082", "T1105", "T1562"], "impact_description": "200,000+ computers in 150+ countries. UK NHS severely disrupted, 19,000+ appointments cancelled. Estimated damages $4B-$8B. Kill switch domain discovered.", "aliases": ["WanaCrypt0r", "WannaCry 2.0", "WCry"], "objectives": "Mass financial extortion via ransomware worm. Propagate globally using NSA EternalBlue exploit.", "timeline": [{"timestamp": "2017-05-12T07:44:00Z", "event": "WannaCry begins spreading globally"}, {"timestamp": "2017-05-12T15:08:00Z", "event": "Marcus Hutchins registers kill switch domain, slowing spread"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/wannacry"}]},
    {"id": "camp-volt-typhoon", "name": "Volt Typhoon Critical Infrastructure Campaign", "description": "Chinese state-sponsored living-off-the-land campaign targeting critical infrastructure across US, Guam, and Pacific. Pre-positioned in networks for potential disruptive attacks.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-apt41", "name": "APT41"}, {"actor_id": "actor-hafnium", "name": "HAFNIUM"}], "start_date": "2021-05-01T00:00:00Z", "targeted_sectors": ["critical_infrastructure", "government", "telecommunications", "energy", "transportation"], "targeted_countries": ["US", "GU", "AU"], "mitre_techniques": ["T1078", "T1059", "T1003", "T1082", "T1027", "T1562", "T1047", "T1570", "T1036"], "impact_description": "Pre-positioned on hundreds of devices across US critical infrastructure. Living-off-the-land techniques evade detection.", "aliases": ["Voltzite", "Bronze Silhouette", "Vanguard Panda"], "objectives": "Establish long-term persistent access in US critical infrastructure networks for potential future disruption.", "timeline": [{"timestamp": "2023-05-24T00:00:00Z", "event": "CISA/FBI issue joint cybersecurity advisory"}, {"timestamp": "2024-02-01T00:00:00Z", "event": "Operation continues. Additional LOTL techniques documented"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/volt-typhoon"}]},
    {"id": "camp-hafnium-exchange", "name": "HAFNIUM Exchange Server Campaign", "description": "China-linked HAFNIUM exploited four zero-day vulnerabilities (ProxyLogon) in Microsoft Exchange Server to access email accounts on-premises. Affected 30,000+ organizations in the US alone.", "status": "completed", "threat_actors": [{"actor_id": "actor-hafnium", "name": "HAFNIUM"}], "start_date": "2021-01-03T00:00:00Z", "end_date": "2021-06-01T00:00:00Z", "targeted_sectors": ["defense", "government", "healthcare", "education", "technology", "finance"], "targeted_countries": ["US", "UK", "DE", "FR", "CA", "AU", "NL"], "mitre_techniques": ["T1190", "T1505", "T1059", "T1071", "T1105", "T1041", "T1562"], "impact_description": "30,000+ US organizations compromised. CISA issued emergency directive. Multiple countries issued alerts. Web shells deployed for persistent access.", "aliases": ["ProxyLogon", "CVE-2021-26855", "Exchange Hafnium"], "objectives": "Mass exploitation of Exchange zero-days for email data exfiltration and persistent access to government networks.", "timeline": [{"timestamp": "2021-03-02T00:00:00Z", "event": "Microsoft releases emergency out-of-band patches"}, {"timestamp": "2021-03-03T00:00:00Z", "event": "CISA issues Emergency Directive 21-02"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/microsoft-exchange-server-vulnerabilities"}]},
    {"id": "camp-kaseya-revil", "name": "Kaseya VSA Supply Chain Ransomware", "description": "REvil ransomware gang exploited zero-day vulnerabilities in Kaseya VSA remote management software to deploy ransomware to hundreds of downstream MSPs and customers during July 4th US holiday.", "status": "completed", "threat_actors": [{"actor_id": "actor-revil", "name": "REvil"}, {"actor_id": "actor-darkside", "name": "DarkSide"}], "start_date": "2021-07-02T00:00:00Z", "end_date": "2021-07-23T00:00:00Z", "targeted_sectors": ["technology", "retail", "manufacturing", "healthcare"], "targeted_countries": ["US", "UK", "DE", "NZ", "SE", "NL"], "mitre_techniques": ["T1195", "T1486", "T1562", "T1490", "T1041", "T1059"], "impact_description": "1,500+ downstream businesses affected. 800+ Coop Sweden grocery stores closed. $70M ransom demand for universal decryptor.", "aliases": ["Kaseya VSA attack", "REvil July 4th attack"], "objectives": "Exploit managed service provider supply chain to mass-deploy ransomware to downstream customers.", "timeline": [{"timestamp": "2021-07-02T00:00:00Z", "event": "REvil exploits Kaseya VSA zero-day, begins ransomware deployment"}, {"timestamp": "2021-07-04T00:00:00Z", "event": "REvil demands $70M for universal decryptor"}, {"timestamp": "2021-07-23T00:00:00Z", "event": "Decryptor released. REvil infrastructure taken offline"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/kaseya"}]},
    {"id": "camp-accellion-clop", "name": "Accellion FTA Zero-Day Campaign", "description": "Clop (TA505) ransomware gang exploited multiple zero-day vulnerabilities in Accellion File Transfer Appliance to exfiltrate data from organizations worldwide including government agencies.", "status": "completed", "threat_actors": [{"actor_id": "actor-clop", "name": "Clop (TA505)"}, {"actor_id": "actor-fin7", "name": "FIN7"}], "start_date": "2020-12-01T00:00:00Z", "end_date": "2021-04-01T00:00:00Z", "targeted_sectors": ["government", "healthcare", "education", "finance", "technology"], "targeted_countries": ["US", "UK", "CA", "AU", "SG", "NZ"], "mitre_techniques": ["T1190", "T1505", "T1041", "T1562", "T1003", "T1105"], "impact_description": "100+ organizations affected. Data exfiltrated from Australian Securities and Investment Commission, Reserve Bank of New Zealand, multiple universities.", "aliases": ["FTA breach", "Accellion exploit", "Clop FTA Campaign"], "objectives": "Exploit zero-day vulnerabilities in legacy FTA platform for data exfiltration and extortion.", "timeline": [{"timestamp": "2021-01-01T00:00:00Z", "event": "Accellion notifies customers of vulnerabilities"}, {"timestamp": "2021-02-22T00:00:00Z", "event": "Clop publishes first batch of stolen data"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/accellion-fta"}]},
    {"id": "camp-cosmic-energy", "name": "CosmicEnergy OT/ICS Malware Campaign", "description": "Emerging OT/ICS-focused malware framework designed to disrupt electric power systems. Displays capabilities similar to Industroyer malware used by Sandworm against Ukraine.", "status": "ongoing", "threat_actors": [{"actor_id": "actor-sandworm", "name": "Sandworm"}, {"actor_id": "actor-gamaredon", "name": "Gamaredon"}], "start_date": "2023-05-01T00:00:00Z", "targeted_sectors": ["energy", "critical_infrastructure", "manufacturing"], "targeted_countries": ["UA", "US", "GB", "DE"], "mitre_techniques": ["T1485", "T1562", "T1071", "T1027", "T1105"], "impact_description": "Designed to cause power disruption via IEC 61850 and IEC 104 industrial protocols. Capable of remote tripping circuit breakers.", "aliases": ["CosmicEnergy", "Cosmic Energy"], "objectives": "Develop capability to disrupt electric power grid operations via ICS protocol exploitation.", "timeline": [{"timestamp": "2023-05-24T00:00:00Z", "event": "Mandiant publishes detailed analysis of CosmicEnergy"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/ics-malware"}]},
    {"id": "camp-predatory-sparrow", "name": "Predatory Sparrow Iranian Steel Attack", "description": "Hacktivist/state-linked campaign targeting Iranian steel manufacturing facilities with ICS-specific malware that caused physical damage.", "status": "completed", "threat_actors": [{"actor_id": "actor-oilrig", "name": "OilRig"}, {"actor_id": "actor-apt33", "name": "APT33"}], "start_date": "2022-06-01T00:00:00Z", "end_date": "2022-08-01T00:00:00Z", "targeted_sectors": ["manufacturing", "energy", "critical_infrastructure"], "targeted_countries": ["IR"], "mitre_techniques": ["T1485", "T1562", "T1071"], "impact_description": "Three Iranian steel facilities suffered physical damage. Equipment caught fire. Forced manual shutdown of production lines.", "aliases": ["Iran Steel Hack", "Gonjeshke Darande", "Predator Sparrow"], "objectives": "Disrupt Iranian military/industrial complex through cyber-physical attacks on steel manufacturing.", "timeline": [{"timestamp": "2022-06-27T00:00:00Z", "event": "Attack on Khuzestan Steel Company. Factory equipment damaged"}, {"timestamp": "2022-07-01T00:00:00Z", "event": "Two additional steel facilities targeted"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/ics-advisories"}]},
]

# ----- TTP Database (50 MITRE ATT&CK Techniques) -----
TTP_DATABASE = [
    {"technique_id": "T1595", "name": "Active Scanning", "description": "Probing target infrastructure through active scanning techniques to identify vulnerable systems and services.", "tactic": "reconnaissance", "platforms": ["PRE"], "data_sources": ["Network Traffic", "DNS Records"], "detection_recommendations": "Monitor for unusual scanning patterns from external IPs. Deploy network intrusion detection."},
    {"technique_id": "T1592", "name": "Gather Victim Host Information", "description": "Collecting detailed information about victim host systems including hardware, software, and configurations.", "tactic": "reconnaissance", "platforms": ["PRE"], "data_sources": ["Web Traffic", "DNS Records"], "detection_recommendations": "Monitor for reconnaissance activity against external-facing assets."},
    {"technique_id": "T1598", "name": "Phishing for Information", "description": "Using phishing techniques to gather credential and technical information from targets.", "tactic": "reconnaissance", "platforms": ["PRE"], "data_sources": ["Email", "Social Media"], "detection_recommendations": "User awareness training. Email security gateway filtering. DMARC/DKIM/SPF configuration."},
    {"technique_id": "T1583", "name": "Acquire Infrastructure", "description": "Procuring domain names, virtual private servers, or other infrastructure for the operation.", "tactic": "resource_development", "platforms": ["PRE"], "data_sources": ["DNS Records", "Domain Registration"], "detection_recommendations": "Monitor domain registrations similar to your brand. Track newly registered domains."},
    {"technique_id": "T1587", "name": "Develop Capabilities", "description": "Creating malware, exploits, and other capabilities for the operation.", "tactic": "resource_development", "platforms": ["PRE"], "data_sources": ["Threat Intelligence"], "detection_recommendations": "Integrate threat intelligence feeds. Monitor dark web forums for exploit sales."},
    {"technique_id": "T1608", "name": "Stage Capabilities", "description": "Uploading tools and malware on compromised or adversary-controlled infrastructure.", "tactic": "resource_development", "platforms": ["PRE"], "data_sources": ["Network Traffic"], "detection_recommendations": "Block known malicious domains at proxy/firewall level."},
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "description": "Exploiting software vulnerabilities in internet-facing systems to gain initial access.", "tactic": "initial_access", "platforms": ["Windows", "Linux", "macOS", "IaaS"], "data_sources": ["Application Logs", "Web Server Logs", "Network Traffic"], "detection_recommendations": "Regular vulnerability scanning and patching. WAF deployment. Monitor for exploit patterns."},
    {"technique_id": "T1566", "name": "Phishing", "description": "Sending targeted spearphishing messages with malicious attachments or links.", "tactic": "initial_access", "platforms": ["Windows", "Linux", "macOS", "SaaS"], "data_sources": ["Email", "File Monitoring"], "detection_recommendations": "Anti-phishing solutions. User awareness training. Email attachment sandboxing."},
    {"technique_id": "T1195", "name": "Supply Chain Compromise", "description": "Manipulating products or delivery mechanisms before receipt by the consumer to compromise data or systems.", "tactic": "initial_access", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Software Inventory"], "detection_recommendations": "Verify software integrity. Monitor vendor security. Implement software bill of materials (SBOM)."},
    {"technique_id": "T1078", "name": "Valid Accounts", "description": "Using compromised credentials of existing accounts to gain initial access, bypass access controls, and maintain persistent access.", "tactic": "initial_access", "platforms": ["Windows", "Linux", "macOS", "SaaS", "IaaS", "Containers"], "data_sources": ["Authentication Logs", "AD Logs", "MFA Logs"], "detection_recommendations": "Monitor for unusual login patterns. Implement MFA everywhere. Track impossible travel."},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "description": "Abusing command and script interpreters to execute commands, scripts, or binaries.", "tactic": "execution", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "Command Logs", "PowerShell Logs"], "detection_recommendations": "Enable PowerShell logging. Monitor for suspicious command-line arguments. Restrict scripting engines."},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "description": "Abusing task scheduling functionality to execute programs at a specific time or event.", "tactic": "execution", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Scheduled Job Logs", "Process Monitoring"], "detection_recommendations": "Monitor scheduled task creation. Alert on tasks running from unusual locations."},
    {"technique_id": "T1203", "name": "Exploitation for Client Execution", "description": "Exploiting client application vulnerabilities to execute code through user interaction.", "tactic": "execution", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "Application Logs"], "detection_recommendations": "Keep client applications patched. Deploy endpoint protection. Browser isolation."},
    {"technique_id": "T1047", "name": "Windows Management Instrumentation", "description": "Abusing WMI to execute malicious commands and payloads on Windows systems.", "tactic": "execution", "platforms": ["Windows"], "data_sources": ["WMI Logs", "Process Monitoring"], "detection_recommendations": "Enable WMI logging. Monitor for suspicious WMI event subscriptions."},
    {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "description": "Configuring system settings to automatically execute programs during system boot or user logon.", "tactic": "persistence", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Registry", "Startup Folder", "Process Monitoring"], "detection_recommendations": "Monitor registry run keys. Audit startup folders. Track new autostart entries."},
    {"technique_id": "T1136", "name": "Create Account", "description": "Creating new accounts on victim systems for persistence and privilege escalation.", "tactic": "persistence", "platforms": ["Windows", "Linux", "macOS", "IaaS", "Containers"], "data_sources": ["Account Creation Logs", "AD Auditing"], "detection_recommendations": "Alert on local account creation. Monitor for unauthorized domain accounts."},
    {"technique_id": "T1505", "name": "Server Software Component", "description": "Installing malicious web shells or server plugins to maintain access.", "tactic": "persistence", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Web Server Logs", "File Monitoring"], "detection_recommendations": "Monitor web server directories. File integrity monitoring. Web application firewall."},
    {"technique_id": "T1543", "name": "Create or Modify System Process", "description": "Creating or modifying system-level services and daemons for persistence.", "tactic": "persistence", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Service Monitoring", "Process Monitoring"], "detection_recommendations": "Monitor service creation. Alert on services with unusual binary paths."},
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "description": "Exploiting software vulnerabilities to elevate privileges.", "tactic": "privilege_escalation", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "Exploit Detection"], "detection_recommendations": "Regular patching. Deploy EDR. Application whitelisting."},
    {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "description": "Bypassing User Account Control (UAC) or sudo to elevate privileges on compromised systems.", "tactic": "privilege_escalation", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Creation", "Authentication Logs"], "detection_recommendations": "Enable UAC. Monitor privilege escalation events. Implement least privilege."},
    {"technique_id": "T1134", "name": "Access Token Manipulation", "description": "Manipulating access tokens to operate under a different user or system security context.", "tactic": "privilege_escalation", "platforms": ["Windows"], "data_sources": ["Process Monitoring", "API Monitoring"], "detection_recommendations": "Monitor token manipulation events. Limit SeImpersonatePrivilege assignment."},
    {"technique_id": "T1027", "name": "Obfuscated Files or Information", "description": "Making code or data difficult to detect or analyze through encoding, encryption, or other obfuscation techniques.", "tactic": "defense_evasion", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Process Monitoring", "Network Traffic"], "detection_recommendations": "Deploy NGAV with ML capabilities. Monitor for encoded PowerShell. File entropy analysis."},
    {"technique_id": "T1562", "name": "Impair Defenses", "description": "Disabling, modifying, or bypassing security tools and controls to avoid detection.", "tactic": "defense_evasion", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Security Logs", "Process Monitoring", "Service Monitoring"], "detection_recommendations": "Tamper-protected EDR. Alert on security service stops. Monitor registry changes to security tools."},
    {"technique_id": "T1070", "name": "Indicator Removal", "description": "Deleting or modifying artifacts generated by the adversary to avoid detection.", "tactic": "defense_evasion", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Process Monitoring"], "detection_recommendations": "Centralized logging with forwarder tamper protection. File integrity monitoring."},
    {"technique_id": "T1036", "name": "Masquerading", "description": "Disguising malicious files, processes, or activity as legitimate.", "tactic": "defense_evasion", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Metadata", "Process Monitoring"], "detection_recommendations": "Monitor for binaries in unusual locations. Validate digital signatures."},
    {"technique_id": "T1003", "name": "OS Credential Dumping", "description": "Extracting credentials from operating system components like LSASS, /etc/shadow, SAM database.", "tactic": "credential_access", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Access", "Command Monitoring", "File Monitoring"], "detection_recommendations": "Enable credential guard. Monitor LSASS access. Deploy PPL protection. Audit sensitive file access."},
    {"technique_id": "T1552", "name": "Unsecured Credentials", "description": "Searching for credentials stored unencrypted on the file system, in scripts, or configuration files.", "tactic": "credential_access", "platforms": ["Windows", "Linux", "macOS", "IaaS", "Containers"], "data_sources": ["File Monitoring", "Process Monitoring"], "detection_recommendations": "Implement secrets management. Scan repos for credentials. Vault solutions."},
    {"technique_id": "T1555", "name": "Credentials from Password Stores", "description": "Extracting credentials from browser password stores, keychains, or dedicated password managers.", "tactic": "credential_access", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "File Access"], "detection_recommendations": "Restrict access to browser databases. Deploy PAM solution. Monitor ChromeDP access."},
    {"technique_id": "T1110", "name": "Brute Force", "description": "Systematically attempting to guess passwords or other authentication factors.", "tactic": "credential_access", "platforms": ["Windows", "Linux", "macOS", "SaaS", "IaaS"], "data_sources": ["Authentication Logs", "AD Logs"], "detection_recommendations": "Account lockout policies. MFA. Monitor for authentication spikes."},
    {"technique_id": "T1082", "name": "System Information Discovery", "description": "Gathering detailed information about the compromised host and its configuration.", "tactic": "discovery", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "Command Logs"], "detection_recommendations": "Baseline normal discovery commands. Alert on enumeration tool usage."},
    {"technique_id": "T1018", "name": "Remote System Discovery", "description": "Identifying remote systems in the network via active scanning or querying directory services.", "tactic": "discovery", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Process Monitoring"], "detection_recommendations": "Network segmentation. Monitor for ARP scans and net view commands."},
    {"technique_id": "T1046", "name": "Network Service Discovery", "description": "Scanning hosts to identify open ports and running services for lateral movement planning.", "tactic": "discovery", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Process Monitoring"], "detection_recommendations": "Port scan detection. Network flow analysis. Restrict scanning tools."},
    {"technique_id": "T1069", "name": "Permission Groups Discovery", "description": "Enumerating local and domain groups to understand access and plan privilege escalation.", "tactic": "discovery", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command Logs", "LDAP Queries"], "detection_recommendations": "Monitor group enumeration commands. Baseline AD queries."},
    {"technique_id": "T1021", "name": "Remote Services", "description": "Using valid accounts to connect to remote services like RDP, SSH, SMB, WinRM for lateral movement.", "tactic": "lateral_movement", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Authentication Logs", "RDP Logs"], "detection_recommendations": "Just-in-time access. Network segmentation. Monitor for lateral RDP/SSH chains."},
    {"technique_id": "T1563", "name": "Remote Service Session Hijacking", "description": "Taking over legitimate remote sessions (RDP, SSH) to move laterally.", "tactic": "lateral_movement", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Session Monitoring", "Account Logs"], "detection_recommendations": "Limit concurrent sessions. Monitor for session hijacking."},
    {"technique_id": "T1570", "name": "Lateral Tool Transfer", "description": "Transferring tools and malware between systems in the environment.", "tactic": "lateral_movement", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "File Monitoring"], "detection_recommendations": "Monitor SMB/CIFS file shares. Admin share usage alerting."},
    {"technique_id": "T1210", "name": "Exploitation of Remote Services", "description": "Exploiting vulnerable remote services to gain access. Used by WannaCry (EternalBlue on SMB), NotPetya.", "tactic": "lateral_movement", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Process Monitoring"], "detection_recommendations": "Patch SMB and RDP. Disable SMBv1. Network segmentation."},
    {"technique_id": "T1119", "name": "Automated Collection", "description": "Automatically collecting data of interest using scripts or tools.", "tactic": "collection", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Process Monitoring"], "detection_recommendations": "Monitor for bulk file access patterns. DLP solutions."},
    {"technique_id": "T1005", "name": "Data from Local System", "description": "Collecting sensitive files from local or mapped drives.", "tactic": "collection", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Access Monitoring", "Process Monitoring"], "detection_recommendations": "File audit policies. Monitor for mass file reads."},
    {"technique_id": "T1560", "name": "Archive Collected Data", "description": "Compressing and/or encrypting collected data before exfiltration.", "tactic": "collection", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Process Monitoring"], "detection_recommendations": "Monitor for archiving utilities (7z, WinRAR). Large archive creation alerts."},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "description": "Using application layer protocols (HTTP/S, DNS, FTP, SMTP) for command and control to blend with normal traffic.", "tactic": "command_and_control", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Proxy Logs", "DNS Logs"], "detection_recommendations": "TLS decryption/inspection. DNS tunneling detection. JA3/JA4 fingerprinting."},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer", "description": "Transferring tools or other files from an external system into the compromised environment.", "tactic": "command_and_control", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "File Monitoring", "Proxy Logs"], "detection_recommendations": "Restrict outbound connections. Block known C2 infrastructure. Egress filtering."},
    {"technique_id": "T1573", "name": "Encrypted Channel", "description": "Encrypting C2 communications using standard and custom cryptographic protocols.", "tactic": "command_and_control", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Certificate Analysis"], "detection_recommendations": "TLS inspection at network boundary. Certificate anomaly detection."},
    {"technique_id": "T1090", "name": "Proxy", "description": "Using intermediary systems to route C2 traffic and obscure the ultimate destination.", "tactic": "command_and_control", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Proxy Logs"], "detection_recommendations": "Monitor for connections through anonymization services. VPN/proxy detection."},
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "description": "Exfiltrating data over the already established command and control channel.", "tactic": "exfiltration", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Data Loss Prevention"], "detection_recommendations": "Monitor for large outbound data transfers. DLP at egress points."},
    {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "description": "Exfiltrating data over a protocol different from the C2 channel (e.g., FTP, DNS, physical media).", "tactic": "exfiltration", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "DNS Logs", "FTP Logs"], "detection_recommendations": "Egress filtering. DNS monitoring. Block FTP outbound."},
    {"technique_id": "T1537", "name": "Transfer Data to Cloud Account", "description": "Exfiltrating data to adversary-controlled cloud storage or computing accounts.", "tactic": "exfiltration", "platforms": ["IaaS", "SaaS"], "data_sources": ["Cloud Audit Logs", "Network Traffic"], "detection_recommendations": "CASB monitoring. Cloud access controls. Shared link detection."},
    {"technique_id": "T1485", "name": "Data Destruction", "description": "Destroying data on target systems, making it unrecoverable. Used by NotPetya, Shamoon wipers.", "tactic": "impact", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File Monitoring", "Process Monitoring"], "detection_recommendations": "Immutable backups. File integrity monitoring. Offline/air-gapped backup copies."},
    {"technique_id": "T1490", "name": "Inhibit System Recovery", "description": "Deleting volume shadow copies, backups, and recovery features before encryption/destruction.", "tactic": "impact", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process Monitoring", "Command Logs"], "detection_recommendations": "Protect VSS. Immutable backup solutions. Monitor vssadmin and wbadmin commands."},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "description": "Encrypting data on target systems to interrupt availability. Ransomware attacks.", "tactic": "impact", "platforms": ["Windows", "Linux", "macOS", "IaaS"], "data_sources": ["File Monitoring", "Process Monitoring", "I/O Metrics"], "detection_recommendations": "Canary files. EDR ransomware protection. Network segmentation. Regular offline backups."},
    {"technique_id": "T1499", "name": "Endpoint Denial of Service", "description": "Performing DoS attacks to degrade or block the availability of endpoint services.", "tactic": "impact", "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic", "Performance Metrics"], "detection_recommendations": "DDoS mitigation. Rate limiting. Resource exhaustion alerts."},
    {"technique_id": "T1531", "name": "Account Access Removal", "description": "Deleting or locking accounts to deny access, sometimes as part of exit strategy or extortion.", "tactic": "impact", "platforms": ["Windows", "Linux", "macOS", "SaaS", "IaaS"], "data_sources": ["Account Management Logs", "Authentication Logs"], "detection_recommendations": "Account activity monitoring. Alert on mass account changes. Break-glass accounts."},
]

# ----- TTP Details (expanded techniques with sub-techniques, mitigations, etc.) -----
TTP_DETAILS = {
    "T1190": {
        "mitre_id": "T1190",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "sub_techniques": [],
        "mitigations": [
            {
                "id": "M1048",
                "name": "Application Isolation and Sandboxing"
            },
            {
                "id": "M1050",
                "name": "Exploit Protection"
            },
            {
                "id": "M1051",
                "name": "Update Software"
            },
            {
                "id": "M1016",
                "name": "Vulnerability Scanning"
            }
        ],
        "detections": [
            {
                "data_source": "Application Logs",
                "description": "Monitor for unusual patterns in web server access logs. Detect exploit signatures in HTTP requests."
            },
            {
                "data_source": "Network Traffic",
                "description": "Detect known exploit patterns in network traffic. IDS/IPS signatures for common CVEs."
            }
        ],
        "procedure_examples": [
            {
                "actor": "HAFNIUM",
                "description": "Exploited four zero-days in Microsoft Exchange Server (ProxyLogon) to deploy web shells."
            },
            {
                "actor": "APT41",
                "description": "Exploited public-facing applications including Citrix ADC and Pulse Secure VPNs."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1190/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-hafnium",
                "name": "HAFNIUM"
            },
            {
                "actor_id": "actor-apt41",
                "name": "APT41"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-hafnium-exchange",
                "name": "HAFNIUM Exchange Server Campaign"
            }
        ]
    },
    "T1566": {
        "mitre_id": "T1566",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/",
        "sub_techniques": [
            {
                "id": "T1566.001",
                "name": "Spearphishing Attachment",
                "description": "Sending spearphishing emails with malicious attachments.",
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS"
                ]
            },
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "description": "Sending spearphishing emails with malicious links.",
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS"
                ]
            }
        ],
        "mitigations": [
            {
                "id": "M1049",
                "name": "Antivirus/Antimalware"
            },
            {
                "id": "M1021",
                "name": "Restrict Web-Based Content"
            },
            {
                "id": "M1017",
                "name": "User Training"
            }
        ],
        "detections": [
            {
                "data_source": "Email Gateway",
                "description": "Detect malicious attachments and links via email security gateway. Sandbox attachments."
            },
            {
                "data_source": "Process Monitoring",
                "description": "Monitor for Office applications spawning unusual child processes (Winword to cmd.exe)."
            }
        ],
        "procedure_examples": [
            {
                "actor": "APT29",
                "description": "Used spearphishing to deliver Sunburst trojanized updates."
            },
            {
                "actor": "FIN7",
                "description": "Conducted multi-phase spearphishing campaigns with password-protected Office documents."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1566/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-apt29",
                "name": "APT29"
            },
            {
                "actor_id": "actor-fin7",
                "name": "FIN7"
            },
            {
                "actor_id": "actor-mustang-panda",
                "name": "Mustang Panda"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-hafnium-exchange",
                "name": "HAFNIUM Exchange Server Campaign"
            }
        ]
    },
    "T1059": {
        "mitre_id": "T1059",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "sub_techniques": [
            {
                "id": "T1059.001",
                "name": "PowerShell",
                "description": "Abusing PowerShell for execution.",
                "platforms": [
                    "Windows"
                ]
            },
            {
                "id": "T1059.003",
                "name": "Windows Command Shell",
                "description": "Abusing cmd.exe for execution.",
                "platforms": [
                    "Windows"
                ]
            },
            {
                "id": "T1059.004",
                "name": "Unix Shell",
                "description": "Abusing Unix shells for execution.",
                "platforms": [
                    "Linux",
                    "macOS"
                ]
            }
        ],
        "mitigations": [
            {
                "id": "M1042",
                "name": "Disable or Remove Feature or Program"
            },
            {
                "id": "M1038",
                "name": "Execution Prevention"
            },
            {
                "id": "M1026",
                "name": "Privileged Account Management"
            }
        ],
        "detections": [
            {
                "data_source": "PowerShell Logs",
                "description": "Enable PowerShell script block logging and module logging. Detect encoded commands."
            },
            {
                "data_source": "Process Monitoring",
                "description": "Monitor for suspicious command-line arguments and parent-child process relationships."
            }
        ],
        "procedure_examples": [
            {
                "actor": "Lazarus Group",
                "description": "Used PowerShell for lateral movement and data collection in multiple campaigns."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1059/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-lazarus",
                "name": "Lazarus Group"
            },
            {
                "actor_id": "actor-apt28",
                "name": "APT28"
            },
            {
                "actor_id": "actor-conti",
                "name": "Conti"
            }
        ],
        "related_campaigns": []
    },
    "T1003": {
        "mitre_id": "T1003",
        "mitre_url": "https://attack.mitre.org/techniques/T1003/",
        "sub_techniques": [
            {
                "id": "T1003.001",
                "name": "LSASS Memory",
                "description": "Dumping credentials from LSASS process memory.",
                "platforms": [
                    "Windows"
                ]
            },
            {
                "id": "T1003.002",
                "name": "Security Account Manager",
                "description": "Extracting the SAM database.",
                "platforms": [
                    "Windows"
                ]
            },
            {
                "id": "T1003.008",
                "name": "/etc/passwd and /etc/shadow",
                "description": "Reading password files on Linux.",
                "platforms": [
                    "Linux"
                ]
            }
        ],
        "mitigations": [
            {
                "id": "M1043",
                "name": "Credential Access Protection"
            },
            {
                "id": "M1025",
                "name": "Privileged Process Integrity"
            },
            {
                "id": "M1017",
                "name": "User Training"
            }
        ],
        "detections": [
            {
                "data_source": "Process Access",
                "description": "Monitor for process access to LSASS. Alert on Mimikatz-like patterns."
            },
            {
                "data_source": "API Monitoring",
                "description": "Detect use of Windows API calls for credential dumping."
            }
        ],
        "procedure_examples": [
            {
                "actor": "Conti",
                "description": "Used Mimikatz and custom tools to dump LSASS credentials for lateral movement."
            },
            {
                "actor": "Lazarus Group",
                "description": "Deployed Mimikatz and ProcDump for credential harvesting."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1003/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-conti",
                "name": "Conti"
            },
            {
                "actor_id": "actor-lazarus",
                "name": "Lazarus Group"
            },
            {
                "actor_id": "actor-apt28",
                "name": "APT28"
            }
        ],
        "related_campaigns": []
    },
    "T1486": {
        "mitre_id": "T1486",
        "mitre_url": "https://attack.mitre.org/techniques/T1486/",
        "sub_techniques": [],
        "mitigations": [
            {
                "id": "M1053",
                "name": "Data Backup"
            },
            {
                "id": "M1040",
                "name": "Behavior Prevention on Endpoint"
            }
        ],
        "detections": [
            {
                "data_source": "File Monitoring",
                "description": "Monitor for high-entropy file writes and mass file rename operations indicating ransomware."
            },
            {
                "data_source": "Process Monitoring",
                "description": "Detect file encryption behavior patterns and ransomware-specific process activity."
            }
        ],
        "procedure_examples": [
            {
                "actor": "LockBit",
                "description": "Deployed LockBit ransomware encrypting files with intermittent encryption for speed."
            },
            {
                "actor": "ALPHV",
                "description": "Used Rust-based BlackCat ransomware with configurable encryption modes."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1486/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-lockbit",
                "name": "LockBit"
            },
            {
                "actor_id": "actor-alphv",
                "name": "ALPHV"
            },
            {
                "actor_id": "actor-clop",
                "name": "Clop"
            },
            {
                "actor_id": "actor-revil",
                "name": "REvil"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-colonial-pipeline",
                "name": "Colonial Pipeline"
            },
            {
                "campaign_id": "camp-kaseya-revil",
                "name": "Kaseya VSA"
            }
        ]
    },
    "T1071": {
        "mitre_id": "T1071",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/",
        "sub_techniques": [
            {
                "id": "T1071.001",
                "name": "Web Protocols",
                "description": "Using HTTP/HTTPS for C2 communication.",
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS"
                ]
            },
            {
                "id": "T1071.004",
                "name": "DNS",
                "description": "Using DNS protocol for C2 communication.",
                "platforms": [
                    "Windows",
                    "Linux",
                    "macOS"
                ]
            }
        ],
        "mitigations": [
            {
                "id": "M1031",
                "name": "Network Intrusion Prevention"
            },
            {
                "id": "M1037",
                "name": "Filter Network Traffic"
            }
        ],
        "detections": [
            {
                "data_source": "Network Traffic",
                "description": "TLS inspection for C2 patterns. DNS tunneling detection."
            },
            {
                "data_source": "Proxy Logs",
                "description": "Monitor for beaconing patterns in web traffic. JA3 hash analysis."
            }
        ],
        "procedure_examples": [
            {
                "actor": "APT29",
                "description": "Used HTTPS C2 with custom Sunburst protocol for stealthy command and control."
            },
            {
                "actor": "Turla",
                "description": "Used satellite-based C2 with hijacked IPs for command and control."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1071/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-apt29",
                "name": "APT29"
            },
            {
                "actor_id": "actor-turla",
                "name": "Turla"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-solarwinds",
                "name": "SolarWinds"
            }
        ]
    },
    "T1485": {
        "mitre_id": "T1485",
        "mitre_url": "https://attack.mitre.org/techniques/T1485/",
        "sub_techniques": [],
        "mitigations": [
            {
                "id": "M1053",
                "name": "Data Backup"
            },
            {
                "id": "M1032",
                "name": "Multi-factor Authentication"
            }
        ],
        "detections": [
            {
                "data_source": "File Monitoring",
                "description": "Monitor for mass file deletion and wiping activity. Track MFT/USN journal changes."
            },
            {
                "data_source": "Process Monitoring",
                "description": "Detect data destruction utilities (SDelete, Eraser, cipher /w)."
            }
        ],
        "procedure_examples": [
            {
                "actor": "Sandworm",
                "description": "Deployed NotPetya wiper malware causing billions in damage."
            },
            {
                "actor": "APT33",
                "description": "Used Shamoon wiper to destroy data on tens of thousands of Saudi Aramco workstations."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1485/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-sandworm",
                "name": "Sandworm"
            },
            {
                "actor_id": "actor-apt33",
                "name": "APT33"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-notpetya",
                "name": "NotPetya"
            }
        ]
    },
    "T1027": {
        "mitre_id": "T1027",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "sub_techniques": [
            {
                "id": "T1027.001",
                "name": "Binary Padding"
            },
            {
                "id": "T1027.002",
                "name": "Software Packing"
            },
            {
                "id": "T1027.005",
                "name": "Indicator Removal from Tools"
            }
        ],
        "mitigations": [
            {
                "id": "M1049",
                "name": "Antivirus/Antimalware"
            },
            {
                "id": "M1040",
                "name": "Behavior Prevention on Endpoint"
            }
        ],
        "detections": [
            {
                "data_source": "File Monitoring",
                "description": "Analyze file entropy and packing signatures. Detect obfuscated scripts and macros."
            },
            {
                "data_source": "Memory Analysis",
                "description": "Detect unpacked code in memory through runtime analysis."
            }
        ],
        "procedure_examples": [
            {
                "actor": "APT41",
                "description": "Used heavily obfuscated PowerShell scripts and packed malware binaries."
            },
            {
                "actor": "Lazarus Group",
                "description": "Packed AppleJeus cryptocurrency malware with custom obfuscation."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1027/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-apt41",
                "name": "APT41"
            },
            {
                "actor_id": "actor-lazarus",
                "name": "Lazarus Group"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-solarwinds",
                "name": "SolarWinds"
            }
        ]
    },
    "T1195": {
        "mitre_id": "T1195",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/",
        "sub_techniques": [],
        "mitigations": [
            {
                "id": "M1004",
                "name": "Software Configuration"
            },
            {
                "id": "M1005",
                "name": "Multi-factor Authentication"
            }
        ],
        "detections": [
            {
                "data_source": "File Integrity Monitoring",
                "description": "Monitor software build and distribution servers for unauthorized changes."
            },
            {
                "data_source": "Software Inventory",
                "description": "Verify software integrity via hash verification and code signing."
            }
        ],
        "procedure_examples": [
            {
                "actor": "APT29/Dark Halo",
                "description": "Trojanized SolarWinds Orion platform updates."
            },
            {
                "actor": "Lazarus Group",
                "description": "Compromised 3CX DesktopApp to distribute trojanized VoIP software."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1195/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-apt29",
                "name": "APT29"
            },
            {
                "actor_id": "actor-lazarus",
                "name": "Lazarus Group"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-solarwinds",
                "name": "SolarWinds"
            },
            {
                "campaign_id": "camp-3cx",
                "name": "3CX Supply Chain"
            }
        ]
    },
    "T1210": {
        "mitre_id": "T1210",
        "mitre_url": "https://attack.mitre.org/techniques/T1210/",
        "sub_techniques": [],
        "mitigations": [
            {
                "id": "M1050",
                "name": "Exploit Protection"
            },
            {
                "id": "M1051",
                "name": "Update Software"
            },
            {
                "id": "M1030",
                "name": "Network Segmentation"
            }
        ],
        "detections": [
            {
                "data_source": "Network Traffic",
                "description": "Detect exploit patterns in SMB/RDP traffic. IDS signatures for EternalBlue and similar."
            },
            {
                "data_source": "Process Monitoring",
                "description": "Monitor for unusual processes spawned by SMB or RDP services."
            }
        ],
        "procedure_examples": [
            {
                "actor": "Lazarus Group",
                "description": "Used EternalBlue exploit (MS17-010) to propagate WannaCry ransomware."
            },
            {
                "actor": "Sandworm",
                "description": "Used EternalBlue and EternalRomance for NotPetya lateral movement."
            }
        ],
        "references": [
            {
                "source": "MITRE ATT&CK",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ],
        "related_actors": [
            {
                "actor_id": "actor-lazarus",
                "name": "Lazarus Group"
            },
            {
                "actor_id": "actor-sandworm",
                "name": "Sandworm"
            }
        ],
        "related_campaigns": [
            {
                "campaign_id": "camp-wannacry",
                "name": "WannaCry"
            },
            {
                "campaign_id": "camp-notpetya",
                "name": "NotPetya"
            }
        ]
    }
}

# ----- Threat Intelligence Reports (5) -----
REPORTS_DB = [
    {"id": "rpt-2025-ransomware", "title": "2025 Global Ransomware Threat Landscape Report", "report_type": "strategic", "status": "published", "author": "AEGISX Threat Research Team", "summary": "Comprehensive analysis of the 2025 ransomware threat landscape covering LockBit, ALPHV, Clop, and emerging RaaS variants. Examines double/triple extortion trends, victim profiling, and recommended defensive strategies.", "tlp": "amber", "tags": ["ransomware", "trends", "strategic", "2025"], "published_at": "2025-01-15T00:00:00Z", "ioc_count": 156, "content": {"executive_summary": "Ransomware remains the top cyber threat for organizations in 2025. RaaS models have matured with increasingly professional affiliate programs, sophisticated encryption, and multi-layered extortion strategies.", "key_findings": ["LockBit remains dominant despite law enforcement disruptions", "Cross-platform ransomware tripled year-over-year", "Healthcare and manufacturing are most targeted sectors", "Average ransom demand increased to $1.2M", "Supply chain attacks via MSPs continue to rise"], "recommendations": ["Implement immutable offline backups", "Deploy EDR with anti-ransomware capabilities", "Conduct regular incident response exercises", "Enforce MFA on all remote access", "Segment networks to limit lateral movement", "Maintain patching cadence for critical vulnerabilities"]}, "threat_actors": [{"actor_id": "actor-lockbit", "name": "LockBit"}, {"actor_id": "actor-alphv", "name": "ALPHV"}, {"actor_id": "actor-clop", "name": "Clop"}, {"actor_id": "actor-conti", "name": "Conti"}], "mitre_techniques": [{"technique_id": "T1486", "name": "Data Encrypted for Impact"}, {"technique_id": "T1490", "name": "Inhibit System Recovery"}, {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"technique_id": "T1562", "name": "Impair Defenses"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/ransomware"}]},
    {"id": "rpt-solarwinds-lessons", "title": "SolarWinds: Anatomy of a Supply Chain Attack and Lessons Learned", "report_type": "operational", "status": "published", "author": "AEGISX Threat Intelligence", "summary": "Detailed analysis of the SolarWinds supply chain attack covering initial access, C2 infrastructure, detection evasion, and lessons for defenders. Includes Sunburst backdoor technical analysis.", "tlp": "amber", "tags": ["supply-chain", "solarwinds", "APT29", "detection"], "published_at": "2024-11-20T00:00:00Z", "ioc_count": 89, "content": {"executive_summary": "The SolarWinds attack demonstrated the potential impact of software supply chain compromise at an unprecedented scale. APT29 maintained stealthy access for months before detection.", "key_findings": ["Trojanized Orion update deployed to 18,000+ organizations", "Sunburst backdoor used sophisticated C2 domain generation algorithm (DGA)", "Dwell time of 14+ months before detection", "Discovered by FireEye during evaluation of 2FA breach", "Validated the need for zero-trust architecture and SBOM"], "recommendations": ["Implement software bill of materials (SBOM)", "Monitor software build pipelines", "Deploy network detection of DGA domains", "Enforce least-privilege for all accounts", "Implement detection rules for TTPs: T1195, T1071, T1027"]}, "threat_actors": [{"actor_id": "actor-apt29", "name": "APT29"}, {"actor_id": "actor-unc2452", "name": "UNC2452"}], "campaigns": [{"campaign_id": "camp-solarwinds", "name": "SolarWinds Supply Chain Attack"}], "mitre_techniques": [{"technique_id": "T1195", "name": "Supply Chain Compromise"}, {"technique_id": "T1071", "name": "Application Layer Protocol"}, {"technique_id": "T1027", "name": "Obfuscated Files or Information"}, {"technique_id": "T1003", "name": "OS Credential Dumping"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/solarwinds"}]},
    {"id": "rpt-moveit-analysis", "title": "MOVEit Transfer Exploitation: Clop Group Tactics and Lessons", "report_type": "tactical", "status": "published", "author": "AEGISX CTI Team", "summary": "Tactical breakdown of the MOVEit Transfer zero-day exploitation by Clop ransomware gang. Includes IOCs, detection rules, and remediation guidance for MFT security hardening.", "tlp": "amber", "tags": ["moveit", "clop", "zero-day", "data-extortion", "MFT"], "published_at": "2024-08-10T00:00:00Z", "ioc_count": 234, "content": {"executive_summary": "Clop group exploited CVE-2023-34362 in Progress MOVEit Transfer to exfiltrate data from thousands of organizations. The campaign leveraged efficient automated exploitation workflows to maximize victim count.", "key_findings": ["Zero-day SQL injection in MOVEit Transfer web application", "Automated exploitation using webshell deployment scripts", "Data exfiltration began before vulnerability public disclosure", "Over 60 million individuals impacted across thousands of organizations", "Clop published victim names on dark web leak site for extortion"], "recommendations": ["Patch MFT solutions immediately upon advisory release", "Implement web application firewall rules for SQL injection", "Monitor for LEMURLOOT webshell indicators", "Deploy file integrity monitoring on MFT servers", "Log and alert on unusual data transfer volumes"]}, "threat_actors": [{"actor_id": "actor-clop", "name": "Clop (TA505)"}], "mitre_techniques": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application"}, {"technique_id": "T1505", "name": "Server Software Component"}, {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel"}, {"technique_id": "T1562", "name": "Impair Defenses"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/moveit"}]},
    {"id": "rpt-volt-typhoon", "title": "Volt Typhoon: Living Off the Land in Critical Infrastructure", "report_type": "operational", "status": "published", "author": "AEGISX Threat Intelligence", "summary": "Analysis of Volt Typhoon campaign techniques, with focus on living-off-the-land TTPs that evade traditional detection. Includes detection engineering guidance for network defenders.", "tlp": "amber", "tags": ["volt-typhoon", "critical-infrastructure", "LOTL", "China", "detection-engineering"], "published_at": "2024-06-01T00:00:00Z", "ioc_count": 42, "content": {"executive_summary": "Volt Typhoon demonstrates sophisticated LOTL techniques to maintain long-term persistence in US critical infrastructure networks while evading detection through avoidance of custom malware.", "key_findings": ["Exclusive use of living-off-the-land binaries (LOLBins)", "Pre-positioned in networks for potential disruption", "Targeted communications, energy, transportation, and water sectors", "Used compromised router infrastructure for C2", "Heavy use of hands-on-keyboard activity vs automated tools"], "recommendations": ["Baseline normal LOTL usage in your environment", "Enable command-line auditing and PowerShell logging", "Monitor for unusual PsExec, WMI, and RDP usage patterns", "Harden network devices with strong authentication", "Implement SMB signing and disable NTLM where possible"]}, "threat_actors": [{"actor_id": "actor-apt41", "name": "APT41"}, {"actor_id": "actor-hafnium", "name": "HAFNIUM"}], "mitre_techniques": [{"technique_id": "T1078", "name": "Valid Accounts"}, {"technique_id": "T1059", "name": "Command and Scripting Interpreter"}, {"technique_id": "T1003", "name": "OS Credential Dumping"}, {"technique_id": "T1562", "name": "Impair Defenses"}, {"technique_id": "T1036", "name": "Masquerading"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/volt-typhoon"}]},
    {"id": "rpt-scattered-spider", "title": "Scattered Spider: Social Engineering at Scale in 2025", "report_type": "tactical", "status": "published", "author": "AEGISX SOC Intelligence", "summary": "Deep dive into Scattered Spider (Octo Tempest) tactics, techniques, and procedures. Covers MFA fatigue, SIM swapping, and Okta compromise methodology with practical detection and prevention guidance.", "tlp": "amber", "tags": ["scattered-spider", "social-engineering", "okta", "MFA", "identity-security"], "published_at": "2025-03-01T00:00:00Z", "ioc_count": 78, "content": {"executive_summary": "Scattered Spider represents a new breed of threat actor combining social engineering expertise with ransomware deployment. Their attacks on MGM Resorts and Caesars Entertainment highlight the critical need for identity security hardening.", "key_findings": ["MFA fatigue attacks bypass traditional MFA", "SIM swapping enables credential reset attacks", "Help desk social engineering exploits business processes", "Okta tenant compromise provides broad lateral movement", "Partnership with ALPHV/BlackCat RaaS amplifies impact"], "recommendations": ["Implement phishing-resistant MFA (FIDO2/WebAuthn)", "Enforce strict help desk verification procedures", "Deploy number matching for MFA prompts", "Monitor for impossible travel and unusual MFA patterns", "Implement identity threat detection rules"]}, "threat_actors": [{"actor_id": "actor-scattered-spider", "name": "Scattered Spider"}, {"actor_id": "actor-alphv", "name": "ALPHV"}], "mitre_techniques": [{"technique_id": "T1566", "name": "Phishing"}, {"technique_id": "T1078", "name": "Valid Accounts"}, {"technique_id": "T1621", "name": "MFA Fatigue"}, {"technique_id": "T1486", "name": "Data Encrypted for Impact"}, {"technique_id": "T1562", "name": "Impair Defenses"}], "external_references": [{"source": "CISA", "url": "https://www.cisa.gov/scattered-spider"}]},
]

# ═════════════════════════════════════════════════════════════════
# FEEDS ENDPOINTS (CRUD)
# ═════════════════════════════════════════════════════════════════

@router.get("/feeds", response_model=PaginatedFeeds)
async def list_feeds(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    feed_type: Optional[FeedType] = Query(default=None),
    status: Optional[FeedStatus] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    conditions = [ThreatFeed.tenant_id == _uuid.UUID(tenant_id)]
    if feed_type is not None:
        conditions.append(ThreatFeed.source_type == feed_type.value)
    if enabled is not None:
        conditions.append(ThreatFeed.is_active == enabled)
    if status is not None:
        if status == FeedStatus.ACTIVE: conditions.append(ThreatFeed.is_active == True)
        elif status == FeedStatus.INACTIVE: conditions.append(ThreatFeed.is_active == False)
        elif status == FeedStatus.ERROR: conditions.append(ThreatFeed.last_sync_status == "error")
        elif status == FeedStatus.SYNCING: conditions.append(ThreatFeed.last_sync_status == "syncing")
    offset = (page - 1) * page_size
    total = (await db.execute(select(func.count(ThreatFeed.id)).where(and_(*conditions)))).scalar() or 0
    rows = (await db.execute(select(ThreatFeed).where(and_(*conditions)).order_by(desc(ThreatFeed.created_at)).offset(offset).limit(page_size))).scalars().all()
    return _paginated([_feed_to_response(f) for f in rows], total, page, page_size)


@router.post("/feeds", response_model=FeedResponse, status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    existing = (await db.execute(select(ThreatFeed).where(and_(ThreatFeed.tenant_id == tid, ThreatFeed.name == body.name)))).scalar()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Feed with this name already exists")
    cfg = {"description": body.description, "auth": body.auth.model_dump() if body.auth else None,
           "tls": body.tls.model_dump() if body.tls else None, "tags": body.tags,
           "confidence_default": body.confidence_default.value}
    feed = ThreatFeed(tenant_id=tid, name=body.name, source_type=body.feed_type.value, url=body.url,
                      is_active=body.enabled, sync_interval=body.polling_interval_seconds, config=cfg, indicator_count=0)
    db.add(feed)
    await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "create_feed", "ThreatFeed", str(feed.id))
    return _feed_to_response(feed)


@router.patch("/feeds/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: str, body: FeedUpdate,
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter), db: AsyncSession = Depends(get_db),
):
    fid = _uuid.UUID(feed_id); tid = _uuid.UUID(tenant_id)
    feed = (await db.execute(select(ThreatFeed).where(and_(ThreatFeed.id == fid, ThreatFeed.tenant_id == tid)))).scalar()
    if not feed: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    cfg = dict(feed.config or {}); changed = False
    if body.name is not None: feed.name = body.name; changed = True
    if body.description is not None: cfg["description"] = body.description; changed = True
    if body.url is not None: feed.url = body.url; changed = True
    if body.enabled is not None: feed.is_active = body.enabled; changed = True
    if body.polling_interval_seconds is not None: feed.sync_interval = body.polling_interval_seconds; changed = True
    if body.auth is not None: cfg["auth"] = body.auth.model_dump(); changed = True
    if body.tls is not None: cfg["tls"] = body.tls.model_dump(); changed = True
    if body.tags is not None: cfg["tags"] = body.tags; changed = True
    if body.confidence_default is not None: cfg["confidence_default"] = body.confidence_default.value; changed = True
    if changed: feed.config = cfg; feed.updated_at = func.now()
    await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "update_feed", "ThreatFeed", str(feed.id))
    return _feed_to_response(feed)


@router.delete("/feeds/{feed_id}", response_model=MessageResponse)
async def delete_feed(
    feed_id: str, current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter), db: AsyncSession = Depends(get_db),
):
    fid = _uuid.UUID(feed_id); tid = _uuid.UUID(tenant_id)
    feed = (await db.execute(select(ThreatFeed).where(and_(ThreatFeed.id == fid, ThreatFeed.tenant_id == tid)))).scalar()
    if not feed: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    await db.delete(feed); await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "delete_feed", "ThreatFeed", str(feed.id))
    return {"message": "Feed deleted successfully"}


@router.post("/feeds/{feed_id}/sync", response_model=MessageResponse)
async def trigger_feed_sync(
    feed_id: str, body: Optional[SyncTriggerRequest] = None,
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter), db: AsyncSession = Depends(get_db),
):
    fid = _uuid.UUID(feed_id); tid = _uuid.UUID(tenant_id)
    feed = (await db.execute(select(ThreatFeed).where(and_(ThreatFeed.id == fid, ThreatFeed.tenant_id == tid)))).scalar()
    if not feed: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    feed.last_sync_at = func.now(); feed.last_sync_status = "syncing"
    await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "trigger_sync", "ThreatFeed", str(feed.id))
    return {"message": "Feed sync triggered", "detail": "Sync job queued"}


@router.get("/feeds/{feed_id}/status", response_model=FeedStatusResponse)
async def get_feed_status(
    feed_id: str, current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter), db: AsyncSession = Depends(get_db),
):
    fid = _uuid.UUID(feed_id); tid = _uuid.UUID(tenant_id)
    feed = (await db.execute(select(ThreatFeed).where(and_(ThreatFeed.id == fid, ThreatFeed.tenant_id == tid)))).scalar()
    if not feed: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feed not found")
    status_str = "active" if feed.is_active else "inactive"
    if feed.last_sync_status == "error": status_str = "error"
    elif feed.last_sync_status == "syncing": status_str = "syncing"
    return {"feed_id": str(feed.id), "status": status_str, "last_sync_at": feed.last_sync_at,
            "last_sync_duration_ms": None, "total_indicators_imported": feed.indicator_count,
            "sync_history": [], "errors": []}


# ═════════════════════════════════════════════════════════════════
# INDICATORS ENDPOINTS (CRUD + Bulk + Enrich + Stats)
# ═════════════════════════════════════════════════════════════════

@router.get("/indicators", response_model=PaginatedIndicators)
async def search_indicators(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
    q: Optional[str] = Query(default=None), type: Optional[IOCType] = Query(default=None),
    confidence: Optional[ConfidenceLevel] = Query(default=None), status: Optional[IndicatorStatus] = Query(default=None),
    tlp: Optional[TLPMarking] = Query(default=None), source: Optional[str] = Query(default=None),
    tags: Optional[List[str]] = Query(default=None), sort_by: Optional[str] = Query(default=None),
    sort_order: Optional[str] = Query(default="desc"),
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst), db: AsyncSession = Depends(get_db),
):
    conditions = [ThreatIndicator.tenant_id == _uuid.UUID(tenant_id)]
    if q: conditions.append(or_(ThreatIndicator.value.ilike(f"%{q}%"), ThreatIndicator.description.ilike(f"%{q}%")))
    if type is not None: conditions.append(ThreatIndicator.type == type.value)
    if confidence is not None: conditions.append(ThreatIndicator.confidence == CONFIDENCE_MAP[confidence.value])
    if status is not None: conditions.append(ThreatIndicator.is_active == (status == IndicatorStatus.ACTIVE))
    if tlp is not None: conditions.append(ThreatIndicator.tlp == tlp.value)
    if source is not None: conditions.append(ThreatIndicator.source == source)
    if tags:
        for t in tags: conditions.append(ThreatIndicator.tags.any(t))
    offset = (page - 1) * page_size
    total = (await db.execute(select(func.count(ThreatIndicator.id)).where(and_(*conditions)))).scalar() or 0
    order_col = {"confidence": ThreatIndicator.confidence, "type": ThreatIndicator.type,
                 "value": ThreatIndicator.value, "source": ThreatIndicator.source}.get(sort_by, ThreatIndicator.created_at)
    order_fn = desc if sort_order == "desc" else asc
    rows = (await db.execute(select(ThreatIndicator).where(and_(*conditions)).order_by(order_fn(order_col)).offset(offset).limit(page_size))).scalars().all()
    return _paginated([_indicator_to_response(i) for i in rows], total, page, page_size)


@router.get("/indicators/{indicator_id}", response_model=IndicatorDetailResponse)
async def get_indicator(
    indicator_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    iid = _uuid.UUID(indicator_id); tid = _uuid.UUID(tenant_id)
    indicator = (await db.execute(select(ThreatIndicator).where(and_(ThreatIndicator.id == iid, ThreatIndicator.tenant_id == tid)))).scalar()
    if not indicator: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    return _indicator_to_detail(indicator)


@router.post("/indicators", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    body: IndicatorCreate, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    indicator = ThreatIndicator(
        tenant_id=tid, type=body.type.value, value=body.value, description=body.description,
        confidence=CONFIDENCE_MAP[body.confidence.value], source=body.source or "manual",
        tags=body.tags, tlp=body.tlp.value, first_seen=body.valid_from, last_seen=body.valid_until,
        is_active=body.status == IndicatorStatus.ACTIVE,
        raw_data={"kill_chain_phases": body.kill_chain_phases, "external_references": body.external_references},
    )
    db.add(indicator); await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "create_indicator", "ThreatIndicator", str(indicator.id))
    return _indicator_to_response(indicator)


@router.patch("/indicators/{indicator_id}", response_model=IndicatorResponse)
async def update_indicator(
    indicator_id: str, body: IndicatorUpdate,
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireThreatHunter), db: AsyncSession = Depends(get_db),
):
    iid = _uuid.UUID(indicator_id); tid = _uuid.UUID(tenant_id)
    indicator = (await db.execute(select(ThreatIndicator).where(and_(ThreatIndicator.id == iid, ThreatIndicator.tenant_id == tid)))).scalar()
    if not indicator: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    if body.description is not None: indicator.description = body.description
    if body.confidence is not None: indicator.confidence = CONFIDENCE_MAP[body.confidence.value]
    if body.tlp is not None: indicator.tlp = body.tlp.value
    if body.status is not None: indicator.is_active = body.status == IndicatorStatus.ACTIVE
    if body.valid_until is not None: indicator.last_seen = body.valid_until
    if body.tags is not None: indicator.tags = body.tags
    if body.kill_chain_phases is not None or body.external_references is not None:
        raw = dict(indicator.raw_data or {})
        if body.kill_chain_phases is not None: raw["kill_chain_phases"] = body.kill_chain_phases
        if body.external_references is not None: raw["external_references"] = body.external_references
        indicator.raw_data = raw
    indicator.updated_at = func.now(); await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "update_indicator", "ThreatIndicator", str(indicator.id))
    return _indicator_to_response(indicator)


@router.delete("/indicators/{indicator_id}", response_model=MessageResponse)
async def delete_indicator(
    indicator_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    iid = _uuid.UUID(indicator_id); tid = _uuid.UUID(tenant_id)
    indicator = (await db.execute(select(ThreatIndicator).where(and_(ThreatIndicator.id == iid, ThreatIndicator.tenant_id == tid)))).scalar()
    if not indicator: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    await db.delete(indicator); await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "delete_indicator", "ThreatIndicator", str(indicator.id))
    return {"message": "Indicator deleted successfully"}


@router.post("/indicators/bulk", response_model=IndicatorBulkImportResponse, status_code=status.HTTP_201_CREATED)
async def bulk_import_indicators(
    body: IndicatorBulkImport, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id); created = updated = skipped = 0; errors = []; parsed = []
    if body.format == ImportFormat.JSON:
        try:
            parsed = _json.loads(body.data)
            if isinstance(parsed, dict): parsed = [parsed]
        except Exception as e: errors.append({"error": f"JSON parse error: {str(e)}"})
    elif body.format == ImportFormat.CSV:
        lines = body.data.strip().split("\n")
        if lines:
            headers = [h.strip().lower() for h in lines[0].split(",")]
            for line in lines[1:]:
                vals = [v.strip() for v in line.split(",")]
                if len(vals) >= 2:
                    row = {"type": vals[0], "value": vals[1]}
                    if "source" in headers:
                        idx = headers.index("source")
                        row["source"] = vals[idx] if idx < len(vals) else None
                    parsed.append(row)
    total = len(parsed)
    for item in parsed:
        try:
            ioc_type = item.get("type", "ip"); value = item.get("value", "").strip()
            if not value: skipped += 1; continue
            existing = (await db.execute(select(ThreatIndicator).where(and_(
                ThreatIndicator.tenant_id == tid, ThreatIndicator.type == ioc_type, ThreatIndicator.value == value)))).scalar()
            if existing:
                existing.last_seen = func.now()
                existing.confidence = max(existing.confidence, CONFIDENCE_MAP[body.confidence.value]); updated += 1
            else:
                indicator = ThreatIndicator(tenant_id=tid, type=ioc_type, value=value,
                    confidence=CONFIDENCE_MAP[body.confidence.value],
                    source=item.get("source") or body.source or "bulk_import",
                    tlp=body.tlp.value, tags=list(body.tags), is_active=True,
                    description=item.get("description"))
                db.add(indicator); created += 1
        except Exception as e: errors.append({"value": item.get("value", ""), "error": str(e)})
    await db.flush()
    await _audit(db, tenant_id, current_user["user_id"], "bulk_import_indicators", "ThreatIndicator",
                 details={"total": total, "created": created, "updated": updated, "skipped": skipped})
    return {"total": total, "created": created, "updated": updated, "skipped": skipped, "errors": errors}


@router.post("/indicators/enrich", response_model=IndicatorEnrichResponse)
async def enrich_indicator(
    body: IndicatorEnrichRequest, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    # Resolve indicator from DB
    indicator = None
    tid = _uuid.UUID(tenant_id)
    if body.indicator_id:
        iid = _uuid.UUID(body.indicator_id)
        indicator = (await db.execute(select(ThreatIndicator).where(and_(ThreatIndicator.id == iid, ThreatIndicator.tenant_id == tid)))).scalar()
        if not indicator: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found")
    elif body.type and body.value:
        indicator = (await db.execute(select(ThreatIndicator).where(and_(
            ThreatIndicator.tenant_id == tid, ThreatIndicator.type == body.type.value, ThreatIndicator.value == body.value)))).scalar()

    ind_type = body.type.value if body.type else (indicator.type if indicator else "ip")
    ind_value = body.value or (indicator.value if indicator else "")
    ind_id = str(indicator.id) if indicator else None

    # Build enrichment: associate with threat actors and campaigns based on matching patterns
    enrichment_results = []
    now = datetime.utcnow()

    # Look up related threat actors from hardcoded database
    related_actors = []
    for actor in THREAT_ACTORS_DB:
        if ind_type == "ip" and "ip" in actor.get("motivation", ""):
            continue
        for keyword in actor.get("tools_used", []) + actor.get("aliases", []):
            if keyword.lower() in ind_value.lower():
                related_actors.append({"actor_id": actor["id"], "name": actor["name"]})
                break

    # Look up related campaigns
    related_campaigns = []
    for campaign in CAMPAIGNS_DB:
        for sector in campaign.get("targeted_sectors", []):
            if sector.lower() in ind_value.lower():
                related_campaigns.append({"campaign_id": campaign["id"], "name": campaign["name"]})
                break

    # Build enrichment per requested source
    for s in body.sources:
        enrichment_entry = {
            "source": s.value, "last_checked": now,
            "reputation_score": int(indicator.confidence * 100) if indicator else 50,
            "categories": ["malware"] if ind_type in ("hash_sha256", "hash_sha1", "hash_md5") else
                          ["phishing"] if ind_type == "url" else
                          ["c2", "botnet"] if ind_type == "ip" else
                          ["malicious_domain"] if ind_type == "domain" else [],
            "whois": None, "geolocation": None, "dns_records": None,
            "ssl_certificates": None,
            "related_indicators": [],
            "raw_data": None,
        }
        enrichment_results.append(enrichment_entry)

    return {
        "indicator_id": ind_id,
        "type": ind_type,
        "value": ind_value,
        "enrichment": enrichment_results,
    }


@router.get("/indicators/stats", response_model=IndicatorStatsResponse)
async def get_indicator_stats(
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst), db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    total = (await db.execute(select(func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid))).scalar() or 0
    active_count = (await db.execute(select(func.count(ThreatIndicator.id)).where(and_(ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active == True)))).scalar() or 0
    expired_count = (await db.execute(select(func.count(ThreatIndicator.id)).where(and_(ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active == False)))).scalar() or 0
    by_type = {r[0]: r[1] for r in (await db.execute(select(ThreatIndicator.type, func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid).group_by(ThreatIndicator.type))).all()}
    by_conf_rows = (await db.execute(select(ThreatIndicator.confidence, func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid).group_by(ThreatIndicator.confidence))).all()
    by_confidence = {}
    for r in by_conf_rows:
        label = _conf_from_float(r[0]) or str(r[0]); by_confidence[label] = by_confidence.get(label, 0) + r[1]
    by_source = {r[0]: r[1] for r in (await db.execute(select(ThreatIndicator.source, func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid).group_by(ThreatIndicator.source))).all()}
    return {"total_indicators": total, "by_type": by_type, "by_confidence": by_confidence,
            "by_source": by_source, "by_status": {"active": active_count, "expired": expired_count, "false_positive": 0},
            "active_count": active_count, "expired_count": expired_count, "false_positive_count": 0}


# ═════════════════════════════════════════════════════════════════
# ACTORS ENDPOINTS
# ═════════════════════════════════════════════════════════════════

@router.get("/actors", response_model=PaginatedActors)
async def list_actors(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
    threat_level: Optional[ActorThreatLevel] = Query(default=None),
    sector: Optional[Sector] = Query(default=None), q: Optional[str] = Query(default=None),
    current_user: dict = Depends(get_current_user), tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
):
    filtered = list(THREAT_ACTORS_DB)
    if threat_level:
        filtered = [a for a in filtered if a["threat_level"] == threat_level.value]
    if sector:
        filtered = [a for a in filtered if sector.value in a.get("targeted_sectors", [])]
    if q:
        ql = q.lower()
        filtered = [a for a in filtered if ql in a["name"].lower() or
                    any(ql in alias.lower() for alias in a.get("aliases", [])) or
                    ql in a.get("description", "").lower()]
    total = len(filtered)
    offset = (page - 1) * page_size
    page_items = filtered[offset:offset + page_size]
    actor_responses = []
    for a in page_items:
        actor_responses.append({
            "id": a["id"], "tenant_id": tenant_id,
            "created_at": a["first_seen"], "updated_at": a.get("last_seen", a["first_seen"]),
            "created_by": None,
            "name": a["name"], "description": a.get("description"),
            "threat_level": a.get("threat_level", "medium"),
            "aliases": a.get("aliases", []),
            "motivation": a.get("motivation"),
            "first_seen": a.get("first_seen"), "last_seen": a.get("last_seen"),
            "origin_countries": a.get("origin_countries", []),
            "targeted_sectors": a.get("targeted_sectors", []),
            "campaign_count": len([c for c in CAMPAIGNS_DB if any(ta["actor_id"] == a["id"] for ta in c.get("threat_actors", []))]),
        })
    return _paginated(actor_responses, total, page, page_size)


@router.get("/actors/{actor_id}", response_model=ActorDetailResponse)
async def get_actor(
    actor_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    actor = next((a for a in THREAT_ACTORS_DB if a["id"] == actor_id), None)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")

    # Build related campaigns
    actor_campaigns = []
    for c in CAMPAIGNS_DB:
        for ta in c.get("threat_actors", []):
            if ta.get("actor_id") == actor_id:
                actor_campaigns.append({
                    "campaign_id": c["id"], "name": c["name"],
                    "first_seen": c.get("start_date"), "last_seen": c.get("end_date"),
                })
                break

    # Build TTPs from techniques
    actor_ttps = []
    for tech_id in actor.get("mitre_techniques", []):
        ttp_data = next((t for t in TTP_DATABASE if t["technique_id"] == tech_id), None)
        if ttp_data:
            actor_ttps.append({
                "technique_id": tech_id, "technique_name": ttp_data["name"],
                "tactic": ttp_data["tactic"], "description": ttp_data.get("description"),
                "first_seen": actor.get("first_seen"), "last_seen": actor.get("last_seen"),
            })

    return {
        "id": actor["id"], "tenant_id": tenant_id,
        "created_at": actor["first_seen"], "updated_at": actor.get("last_seen", actor["first_seen"]),
        "created_by": None,
        "name": actor["name"], "description": actor.get("description"),
        "threat_level": actor.get("threat_level", "medium"),
        "aliases": actor.get("aliases", []),
        "motivation": actor.get("motivation"),
        "first_seen": actor.get("first_seen"), "last_seen": actor.get("last_seen"),
        "origin_countries": actor.get("origin_countries", []),
        "targeted_sectors": actor.get("targeted_sectors", []),
        "campaign_count": len(actor_campaigns),
        "full_aliases": [{"name": a, "source": "threat_intelligence"} for a in actor.get("aliases", [])],
        "ttps": actor_ttps,
        "campaigns": actor_campaigns,
        "targeted_sectors_detail": actor.get("targeted_sectors", []),
        "tools": [{"name": t, "type": "malware"} for t in actor.get("tools_used", [])],
        "associated_groups": [{"actor_id": "", "name": g} for g in actor.get("associated_groups", [])],
        "external_references": actor.get("external_references", []),
    }


# ═════════════════════════════════════════════════════════════════
# CAMPAIGNS ENDPOINTS
# ═════════════════════════════════════════════════════════════════

@router.get("/campaigns", response_model=PaginatedCampaigns)
async def list_campaigns(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
    status: Optional[CampaignStatus] = Query(default=None), actor_id: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None), current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    filtered = list(CAMPAIGNS_DB)
    if status:
        filtered = [c for c in filtered if c["status"] == status.value]
    if actor_id:
        filtered = [c for c in filtered if any(ta.get("actor_id") == actor_id for ta in c.get("threat_actors", []))]
    if q:
        ql = q.lower()
        filtered = [c for c in filtered if ql in c["name"].lower() or ql in c.get("description", "").lower()]
    total = len(filtered)
    offset = (page - 1) * page_size
    page_items = filtered[offset:offset + page_size]
    campaign_responses = []
    for c in page_items:
        campaign_responses.append({
            "id": c["id"], "tenant_id": tenant_id,
            "created_at": c["start_date"], "updated_at": c.get("end_date", c["start_date"]),
            "created_by": None,
            "name": c["name"], "description": c.get("description"),
            "status": c["status"],
            "threat_actors": c.get("threat_actors", []),
            "first_seen": c.get("start_date"), "last_seen": c.get("end_date"),
            "targeted_sectors": c.get("targeted_sectors", []),
            "targeted_countries": c.get("targeted_countries", []),
            "indicator_count": 0,
        })
    return _paginated(campaign_responses, total, page, page_size)


@router.get("/campaigns/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(
    campaign_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    campaign = next((c for c in CAMPAIGNS_DB if c["id"] == campaign_id), None)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found")

    return {
        "id": campaign["id"], "tenant_id": tenant_id,
        "created_at": campaign["start_date"], "updated_at": campaign.get("end_date", campaign["start_date"]),
        "created_by": None,
        "name": campaign["name"], "description": campaign.get("description"),
        "status": campaign["status"],
        "threat_actors": campaign.get("threat_actors", []),
        "first_seen": campaign.get("start_date"), "last_seen": campaign.get("end_date"),
        "targeted_sectors": campaign.get("targeted_sectors", []),
        "targeted_countries": campaign.get("targeted_countries", []),
        "indicator_count": 0,
        "aliases": campaign.get("aliases", []),
        "objectives": campaign.get("objectives"),
        "timeline": campaign.get("timeline", []),
        "associated_indicators": campaign.get("associated_indicators", []),
        "mitre_techniques": [{"technique_id": t, "name": t} for t in campaign.get("mitre_techniques", [])],
        "external_references": campaign.get("external_references", []),
    }


# ═════════════════════════════════════════════════════════════════
# TTPs ENDPOINTS
# ═════════════════════════════════════════════════════════════════

@router.get("/ttps", response_model=PaginatedTTPs)
async def list_ttps(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
    tactic: Optional[AttackTactic] = Query(default=None), platform: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None), current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    filtered = list(TTP_DATABASE)
    if tactic:
        filtered = [t for t in filtered if t["tactic"] == tactic.value]
    if platform:
        filtered = [t for t in filtered if platform.lower() in [p.lower() for p in t.get("platforms", [])]]
    if q:
        ql = q.lower()
        filtered = [t for t in filtered if ql in t["name"].lower() or ql in t["technique_id"].lower() or ql in t.get("description", "").lower()]
    total = len(filtered)
    offset = (page - 1) * page_size
    page_items = filtered[offset:offset + page_size]
    ttp_responses = []
    now = datetime.utcnow().isoformat() + "Z"
    for t in page_items:
        ttp_responses.append({
            "id": t["technique_id"], "tenant_id": tenant_id,
            "created_at": now, "updated_at": now, "created_by": None,
            "technique_id": t["technique_id"], "name": t["name"],
            "tactic": t["tactic"], "description": t.get("description"),
            "platforms": t.get("platforms", []),
            "data_sources": t.get("data_sources", []),
            "detection_recommendations": t.get("detection_recommendations"),
        })
    return _paginated(ttp_responses, total, page, page_size)


@router.get("/ttps/{ttp_id}", response_model=TTPDetailResponse)
async def get_ttp(
    ttp_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    ttp = next((t for t in TTP_DATABASE if t["technique_id"] == ttp_id), None)
    if not ttp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="TTP not found")

    detail = TTP_DETAILS.get(ttp_id, {})
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "id": ttp_id, "tenant_id": tenant_id,
        "created_at": now, "updated_at": now, "created_by": None,
        "technique_id": ttp_id, "name": ttp["name"],
        "tactic": ttp["tactic"], "description": ttp.get("description"),
        "platforms": ttp.get("platforms", []),
        "data_sources": ttp.get("data_sources", []),
        "detection_recommendations": ttp.get("detection_recommendations"),
        "mitre_id": detail.get("mitre_id", ttp_id),
        "mitre_url": detail.get("mitre_url", f"https://attack.mitre.org/techniques/{ttp_id}/"),
        "sub_techniques": detail.get("sub_techniques", []),
        "mitigations": detail.get("mitigations", []),
        "detections": detail.get("detections", []),
        "procedure_examples": detail.get("procedure_examples", []),
        "references": detail.get("references", []),
        "related_actors": detail.get("related_actors", []),
        "related_campaigns": detail.get("related_campaigns", []),
    }


# ═════════════════════════════════════════════════════════════════
# MITRE ATT&CK ENDPOINTS
# ═════════════════════════════════════════════════════════════════

MITRE_TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information to plan future operations", "short_name": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations", "short_name": "resource-development"},
    {"id": "TA0001", "name": "Initial Access", "description": "Gaining initial foothold in target environment", "short_name": "initial-access"},
    {"id": "TA0002", "name": "Execution", "description": "Running malicious code", "short_name": "execution"},
    {"id": "TA0003", "name": "Persistence", "description": "Maintaining access across restarts", "short_name": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Gaining higher-level permissions", "short_name": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection", "short_name": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access", "description": "Stealing account credentials", "short_name": "credential-access"},
    {"id": "TA0007", "name": "Discovery", "description": "Understanding the environment", "short_name": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through the environment", "short_name": "lateral-movement"},
    {"id": "TA0009", "name": "Collection", "description": "Gathering data of interest", "short_name": "collection"},
    {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems", "short_name": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data", "short_name": "exfiltration"},
    {"id": "TA0040", "name": "Impact", "description": "Manipulating, interrupting, or destroying systems", "short_name": "impact"},
]

# Build MITRE_TECHNIQUES from TTP_DATABASE with tactic ID mapping
_TACTIC_NAME_TO_ID = {t["short_name"].replace("-", "_"): t["id"] for t in MITRE_TACTICS}
_TACTIC_NAME_TO_ID["command_and_control"] = "TA0011"


@router.get("/mitre", response_model=MitreEnterpriseResponse, summary="MITRE ATT&CK Enterprise Techniques")
async def mitre_enterprise_short(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
):
    techniques = []
    for t in TTP_DATABASE:
        tactic_ids = [_TACTIC_NAME_TO_ID.get(t["tactic"].replace("-", "_"), "TA0043")]
        techniques.append({
            "id": t["technique_id"], "name": t["name"],
            "description": t.get("description", ""),
            "tactics": tactic_ids,
            "platforms": t.get("platforms", []),
            "is_subtechnique": False, "parent_technique_id": None,
        })
    return {"domain": "enterprise", "version": "15.1",
            "tactics": MITRE_TACTICS, "techniques": techniques}

@router.get("/mitre/enterprise", response_model=MitreEnterpriseResponse)
async def get_mitre_enterprise(
    version: Optional[str] = Query(default=None), current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    techniques = []
    for t in TTP_DATABASE:
        tactic_ids = [_TACTIC_NAME_TO_ID.get(t["tactic"].replace("-", "_"), "TA0043")]
        techniques.append({
            "id": t["technique_id"], "name": t["name"],
            "description": t.get("description", ""),
            "tactics": tactic_ids,
            "platforms": t.get("platforms", []),
            "is_subtechnique": False, "parent_technique_id": None,
        })
    return {"domain": "enterprise", "version": version or "15.1",
            "tactics": MITRE_TACTICS, "techniques": techniques}


@router.get("/mitre/techniques/{technique_id}", response_model=MitreTechniqueDetailResponse)
async def get_mitre_technique(
    technique_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    ttp = next((t for t in TTP_DATABASE if t["technique_id"] == technique_id), None)
    if not ttp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Technique not found")

    detail = TTP_DETAILS.get(technique_id, {})
    tactic_ids = [_TACTIC_NAME_TO_ID.get(ttp["tactic"].replace("-", "_"), "TA0043")]

    return {
        "id": technique_id, "name": ttp["name"],
        "description": ttp.get("description", ""),
        "tactics": tactic_ids,
        "platforms": ttp.get("platforms", []),
        "data_sources": ttp.get("data_sources", []),
        "detection_recommendations": detail.get("detections", []),
        "sub_techniques": detail.get("sub_techniques", []),
        "mitigations": detail.get("mitigations", []),
        "procedure_examples": detail.get("procedure_examples", []),
        "references": detail.get("references", []),
        "related_threat_actors": detail.get("related_actors", []),
    }


@router.get("/mitre/heatmap", response_model=MitreHeatmapResponse)
async def get_mitre_heatmap(
    actor_id: Optional[str] = Query(default=None), campaign_id: Optional[str] = Query(default=None),
    technique_id: Optional[str] = Query(default=None), current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    # Compute heatmap from tenant incidents - count incidents per MITRE technique
    tid = _uuid.UUID(tenant_id)
    from app.models import Incident

    # Query incidents with MITRE techniques from the tenant
    incidents_query = select(Incident.mitre_techniques, Incident.severity).where(
        Incident.tenant_id == tid
    )
    result = await db.execute(incidents_query)
    incident_rows = result.all()

    # Build technique x severity counts
    technique_severity = {}
    for techniques, severity in incident_rows:
        if techniques:
            for tech in techniques:
                if tech not in technique_severity:
                    technique_severity[tech] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                sev = (severity or "medium").lower()
                technique_severity[tech][sev] = technique_severity[tech].get(sev, 0) + 1

    # Build heatmap matrix
    matrix = []
    for ttp in TTP_DATABASE:
        tech_id = ttp["technique_id"]
        sev_counts = technique_severity.get(tech_id, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        total_detections = sum(sev_counts.values())
        if total_detections > 0:
            # Filter by actor/campaign/technique if specified
            if technique_id and tech_id != technique_id:
                continue
            if actor_id:
                actor = next((a for a in THREAT_ACTORS_DB if a["id"] == actor_id), None)
                if actor and tech_id not in actor.get("mitre_techniques", []):
                    continue
            if campaign_id:
                campaign = next((c for c in CAMPAIGNS_DB if c["id"] == campaign_id), None)
                if campaign and tech_id not in campaign.get("mitre_techniques", []):
                    continue

            score = min(100.0, total_detections * 20.0)
            matrix.append({
                "technique_id": tech_id,
                "technique_name": ttp["name"],
                "tactic": ttp["tactic"],
                "score": score,
                "detection_count": total_detections,
                "alert_count": total_detections,
            })

    # Compute coverage percentage
    covered = len([t for t in TTP_DATABASE if t["technique_id"] in technique_severity])
    total_techniques = len(TTP_DATABASE)
    coverage = min(100.0, round(covered / max(1, total_techniques) * 100, 1))

    return {
        "tenant_id": tenant_id,
        "generated_at": datetime.utcnow(),
        "total_techniques": len(matrix),
        "matrix": matrix,
        "coverage_percentage": coverage,
    }


# ═════════════════════════════════════════════════════════════════
# REPUTATION LOOKUPS (IP, Domain, Hash, URL)
# ═════════════════════════════════════════════════════════════════

@router.post("/lookup/ip/{ip}", response_model=IPLookupResponse)
async def lookup_ip(
    ip: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    indicators = (await db.execute(select(ThreatIndicator).where(and_(
        ThreatIndicator.tenant_id == tid, ThreatIndicator.type == "ip", ThreatIndicator.value == ip)))).scalars().all()
    ind_list = list(indicators)
    is_malicious = any(i.confidence >= 0.5 for i in ind_list)
    return {"ip": ip, "is_malicious": is_malicious,
            "reputation_score": max((int(i.confidence * 100) for i in ind_list), default=None),
            "sources": [{"source": i.source, "score": int(i.confidence * 100), "categories": i.tags or [],
                         "last_updated": i.updated_at} for i in ind_list],
            "geolocation": None, "asn": None, "isp": None, "hosting_provider": None,
            "open_ports": [], "related_domains": [], "related_hashes": [], "last_analysis_date": None}


@router.post("/lookup/domain/{domain}", response_model=DomainLookupResponse)
async def lookup_domain(
    domain: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    indicators = (await db.execute(select(ThreatIndicator).where(and_(
        ThreatIndicator.tenant_id == tid, ThreatIndicator.type == "domain", ThreatIndicator.value == domain)))).scalars().all()
    ind_list = list(indicators)
    is_malicious = any(i.confidence >= 0.5 for i in ind_list)
    return {"domain": domain, "is_malicious": is_malicious,
            "reputation_score": max((int(i.confidence * 100) for i in ind_list), default=None),
            "sources": [{"source": i.source, "score": int(i.confidence * 100), "categories": i.tags or [],
                         "last_updated": i.updated_at} for i in ind_list],
            "whois": None, "dns_records": None, "ssl_certificates": None, "subdomains": [],
            "resolved_ips": [], "categories": [], "last_analysis_date": None}


@router.post("/lookup/hash/{hash_value}", response_model=HashLookupResponse)
async def lookup_hash(
    hash_value: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    hash_type = "md5" if len(hash_value) == 32 else "sha1" if len(hash_value) == 40 else "sha256" if len(hash_value) == 64 else "unknown"
    indicators = (await db.execute(select(ThreatIndicator).where(and_(
        ThreatIndicator.tenant_id == tid, ThreatIndicator.type.in_(["hash", "hash_md5", "hash_sha1", "hash_sha256"]),
        ThreatIndicator.value == hash_value)))).scalars().all()
    ind_list = list(indicators)
    is_malicious = any(i.confidence >= 0.5 for i in ind_list)
    return {"hash_value": hash_value, "hash_type": hash_type, "is_malicious": is_malicious,
            "reputation_score": max((int(i.confidence * 100) for i in ind_list), default=None),
            "sources": [{"source": i.source, "score": int(i.confidence * 100), "categories": i.tags or [],
                         "last_updated": i.updated_at} for i in ind_list],
            "file_names": [], "file_type": None, "file_size": None, "malware_family": None,
            "threat_label": None, "first_seen": None, "last_seen": None, "tags": []}


@router.post("/lookup/url/{url:path}", response_model=URLLookupResponse)
async def lookup_url(
    url: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    indicators = (await db.execute(select(ThreatIndicator).where(and_(
        ThreatIndicator.tenant_id == tid, ThreatIndicator.type == "url", ThreatIndicator.value == url)))).scalars().all()
    ind_list = list(indicators)
    is_malicious = any(i.confidence >= 0.5 for i in ind_list)
    return {"url": url, "is_malicious": is_malicious,
            "reputation_score": max((int(i.confidence * 100) for i in ind_list), default=None),
            "sources": [{"source": i.source, "score": int(i.confidence * 100), "categories": i.tags or [],
                         "last_updated": i.updated_at} for i in ind_list],
            "final_url": None, "http_status_code": None, "content_type": None,
            "threat_type": None, "categories": [], "last_analysis_date": None}


# ═════════════════════════════════════════════════════════════════
# REPORTS ENDPOINTS
# ═════════════════════════════════════════════════════════════════

@router.get("/reports", response_model=PaginatedReports)
async def list_reports(
    page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
    report_type: Optional[ReportType] = Query(default=None), status: Optional[ReportStatus] = Query(default=None),
    q: Optional[str] = Query(default=None), current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    filtered = list(REPORTS_DB)
    if report_type:
        filtered = [r for r in filtered if r["report_type"] == report_type.value]
    if status:
        filtered = [r for r in filtered if r["status"] == status.value]
    if q:
        ql = q.lower()
        filtered = [r for r in filtered if ql in r["title"].lower() or ql in r.get("summary", "").lower()]
    total = len(filtered)
    offset = (page - 1) * page_size
    page_items = filtered[offset:offset + page_size]
    report_responses = []
    for r in page_items:
        report_responses.append({
            "id": r["id"], "tenant_id": tenant_id,
            "created_at": r.get("published_at", datetime.utcnow()), "updated_at": r.get("published_at", datetime.utcnow()),
            "created_by": None,
            "title": r["title"], "report_type": r.get("report_type", "tactical"),
            "status": r.get("status", "published"), "author": r.get("author"),
            "summary": r.get("summary"), "tlp": r.get("tlp", "amber"),
            "tags": r.get("tags", []), "published_at": r.get("published_at"),
            "ioc_count": r.get("ioc_count", 0),
        })
    return _paginated(report_responses, total, page, page_size)


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
async def get_report(
    report_id: str, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireSOCAnalyst),
):
    report = next((r for r in REPORTS_DB if r["id"] == report_id), None)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return {
        "id": report["id"], "tenant_id": tenant_id,
        "created_at": report.get("published_at", datetime.utcnow()),
        "updated_at": report.get("published_at", datetime.utcnow()),
        "created_by": None,
        "title": report["title"], "report_type": report.get("report_type", "tactical"),
        "status": report.get("status", "published"), "author": report.get("author"),
        "summary": report.get("summary"), "tlp": report.get("tlp", "amber"),
        "tags": report.get("tags", []), "published_at": report.get("published_at"),
        "ioc_count": report.get("ioc_count", 0),
        "content": report.get("content", {}),
        "stix_bundle": {
            "type": "bundle", "id": f"bundle--{report_id}",
            "spec_version": "2.1", "created": report.get("published_at", datetime.utcnow().isoformat()),
            "objects": []
        },
        "indicators": [],
        "threat_actors": [{"id": a["actor_id"], "tenant_id": tenant_id, "created_at": datetime.utcnow(),
                           "updated_at": datetime.utcnow(), "created_by": None, "name": a["name"],
                           "description": None, "threat_level": "high", "aliases": [],
                           "motivation": None, "first_seen": None, "last_seen": None,
                           "origin_countries": [], "targeted_sectors": [], "campaign_count": 0}
                          for a in report.get("threat_actors", [])],
        "campaigns": [{"id": c["campaign_id"], "tenant_id": tenant_id, "created_at": datetime.utcnow(),
                       "updated_at": datetime.utcnow(), "created_by": None, "name": c["name"],
                       "description": None, "status": "ongoing", "threat_actors": [],
                       "first_seen": None, "last_seen": None, "targeted_sectors": [],
                       "targeted_countries": [], "indicator_count": 0}
                      for c in report.get("campaigns", [])],
        "mitre_techniques": report.get("mitre_techniques", []),
        "external_references": report.get("external_references", []),
    }


@router.post("/reports/generate", response_model=ReportGenerateResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    body: ReportGenerateRequest, current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant), _: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid.UUID(tenant_id)
    report_id = str(_uuid.uuid4())
    now = datetime.utcnow()

    # Aggregate tenant threat data for report generation
    indicators_data = []
    actors_data = []
    campaigns_data = []
    techniques_data = []
    summary_parts = []

    if body.include_indicators:
        indicator_count = (await db.execute(select(func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid))).scalar() or 0
        by_type = {r[0]: r[1] for r in (await db.execute(select(ThreatIndicator.type, func.count(ThreatIndicator.id)).where(ThreatIndicator.tenant_id == tid).group_by(ThreatIndicator.type))).all()}
        summary_parts.append(f"Indicators: {indicator_count} total across {len(by_type)} types ({', '.join(f'{k}:{v}' for k,v in by_type.items())})")

    if body.include_actors:
        matching_actors = [a for a in THREAT_ACTORS_DB if body.threat_actor_ids and a["id"] in body.threat_actor_ids] if body.threat_actor_ids else THREAT_ACTORS_DB[:5]
        if not body.threat_actor_ids:
            actors_data = [{"id": a["id"], "name": a["name"]} for a in matching_actors]
        summary_parts.append(f"Threat Actors: {len(matching_actors)} profiled")

    if body.include_campaigns:
        matching_campaigns = [c for c in CAMPAIGNS_DB if body.campaign_ids and c["id"] in body.campaign_ids] if body.campaign_ids else CAMPAIGNS_DB[:5]
        if body.campaign_ids:
            campaigns_data = matching_campaigns
        else:
            campaigns_data = [{"id": c["id"], "name": c["name"]} for c in matching_campaigns]
        summary_parts.append(f"Campaigns: {len(matching_campaigns)} analyzed")

    if body.include_mitre:
        top_ttps = TTP_DATABASE[:10]
        techniques_data = [{"id": t["technique_id"], "name": t["name"], "tactic": t["tactic"]} for t in top_ttps]
        summary_parts.append(f"MITRE ATT&CK: {len(techniques_data)} techniques covered")

    content = {
        "title": body.title,
        "report_type": body.report_type.value,
        "generated_at": now.isoformat() + "Z",
        "time_range": {"start": body.time_range_start.isoformat() if body.time_range_start else None,
                       "end": body.time_range_end.isoformat() if body.time_range_end else None},
        "summary": "; ".join(summary_parts),
        "indicators_summary": {"total": 0, "by_type": {}},
        "actors": actors_data,
        "campaigns": campaigns_data,
        "mitre_techniques": techniques_data,
    }

    await _audit(db, tenant_id, current_user["user_id"], "generate_report", "Report",
                 resource_id=report_id, details={"title": body.title, "type": body.report_type.value})

    return {"report_id": report_id, "title": body.title, "status": ReportStatus.DRAFT, "created_at": now}
