export interface User {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string;
  roles: string[];
  department?: string | null;
  title?: string | null;
  status: 'active' | 'suspended' | 'locked' | 'inactive';
  mfa_enabled: boolean;
  last_login_at?: string | null;
  created_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  display_name: string;
  domain?: string;
  subscription_tier: 'free' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'deleted';
  quota_assets: number;
  quota_users: number;
  contact_email?: string;
  created_at: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'remediated' | 'closed' | 'reopened';
export type AssetType = 'server' | 'endpoint' | 'container' | 'cloud' | 'network' | 'application' | 'database' | 'iot';
export type AssetOS = 'windows' | 'linux' | 'macos' | 'unknown';

export interface Asset {
  id: string;
  tenant_id: string;
  name: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  type: AssetType;
  os: AssetOS;
  os_version?: string;
  status: 'online' | 'offline' | 'unknown' | 'maintenance';
  risk_level: Severity;
  tags: string[];
  group_id?: string;
  last_seen?: string;
  agent_id?: string;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: IncidentStatus;
  assignee_id?: string;
  assignee_name?: string;
  affected_assets: string[];
  alert_ids: string[];
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  resolution?: string;
  closed_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  severity: Severity;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'dismissed';
  rule_id?: string;
  rule_name?: string;
  source_asset_id?: string;
  source_ip?: string;
  destination_ip?: string;
  indicator_type?: string;
  indicator_value?: string;
  confidence: number;
  created_at: string;
}

export interface Playbook {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  trigger_type: 'alert' | 'incident' | 'schedule' | 'manual' | 'webhook';
  status: 'active' | 'inactive' | 'draft';
  steps_count: number;
  last_executed_at?: string;
  success_rate?: number;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  tenant_id: string;
  cve_id?: string;
  title: string;
  description?: string;
  severity: Severity;
  cvss_score?: number;
  cvss_vector?: string;
  affected_asset_id?: string;
  affected_software?: string;
  status: 'open' | 'in_progress' | 'remediated' | 'accepted_risk' | 'false_positive';
  exploit_available: boolean;
  remediation?: string;
  published_at?: string;
  detected_at: string;
}

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  confidence: number;
  source: string;
  tags: string[];
  first_seen?: string;
  last_seen?: string;
}

export interface AuditLog {
  id: string;
  tenant_id: string;
  user_id?: string;
  user_name?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  status: 'success' | 'failure';
  severity: Severity;
  created_at: string;
}

export interface Report {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  format: 'pdf' | 'excel' | 'csv';
  status: 'pending' | 'generating' | 'completed' | 'failed';
  file_url?: string;
  created_by: string;
  created_at: string;
}

export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    correlation_id?: string;
  };
}

export interface DashboardStats {
  total_assets: number;
  assets_online: number;
  open_incidents: number;
  critical_incidents: number;
  alerts_today: number;
  mean_time_to_resolve: number;
  risk_score: number;
  risk_trend: 'up' | 'down' | 'stable';
}

export type SeverityPalette = Record<Severity, string>;
export const severityColors: SeverityPalette = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};
