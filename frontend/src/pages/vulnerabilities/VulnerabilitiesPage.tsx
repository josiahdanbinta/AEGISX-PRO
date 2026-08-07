import { useState, useEffect, useCallback } from 'react';
import {
  Bug, Search, Plus, ScanLine, AlertTriangle, AlertCircle,
  Shield, Target, Clock, ChevronDown, Filter, X, CheckCircle,
  XCircle, RefreshCw, ExternalLink, BarChart3,
} from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { Table } from '@/components/ui/Table';
import { Loading } from '@/components/ui/Loading';
import { StatCard } from '@/components/dashboards/StatCard';
import { api } from '@/services/api';
import type { Vulnerability, PaginatedResponse, Severity } from '@/types';

const severityVariant: Record<Severity, 'danger' | 'warning' | 'default' | 'info'> = {
  critical: 'danger',
  high: 'warning',
  medium: 'warning',
  low: 'info',
  info: 'default',
};

type VulnStatus = 'open' | 'in_progress' | 'remediated' | 'accepted_risk' | 'false_positive';

const statusVariant: Record<VulnStatus, 'danger' | 'warning' | 'success' | 'info' | 'default'> = {
  open: 'danger',
  in_progress: 'warning',
  remediated: 'success',
  accepted_risk: 'info',
  false_positive: 'default',
};

const statusLabel: Record<VulnStatus, string> = {
  open: 'Open',
  in_progress: 'In Progress',
  remediated: 'Remediated',
  accepted_risk: 'Accepted Risk',
  false_positive: 'False Positive',
};

interface ScanRecord {
  id: string;
  name: string;
  status: 'running' | 'completed' | 'failed' | 'queued';
  started_at: string;
  completed_at: string | null;
  total_assets: number;
  vulnerabilities_found: number;
}

interface VulnStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  exploitable: number;
}

interface Filters {
  severity: string;
  cve: string;
  status: string;
  asset: string;
  startDate: string;
  endDate: string;
}

const severityOptions = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const vulnStatusOptions = [
  { value: '', label: 'All Statuses' },
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'remediated', label: 'Remediated' },
  { value: 'accepted_risk', label: 'Accepted Risk' },
  { value: 'false_positive', label: 'False Positive' },
];

const scanStatusIcon = (status: string) => {
  switch (status) {
    case 'running': return <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />;
    case 'completed': return <CheckCircle className="w-4 h-4 text-emerald-500" />;
    case 'failed': return <XCircle className="w-4 h-4 text-red-500" />;
    case 'queued': return <Clock className="w-4 h-4 text-yellow-500" />;
    default: return <Clock className="w-4 h-4 text-slate-400" />;
  }
};

const scanStatusBadge: Record<string, 'info' | 'success' | 'danger' | 'warning' | 'default'> = {
  running: 'info',
  completed: 'success',
  failed: 'danger',
  queued: 'warning',
};

const cvssColor = (score: number): string => {
  if (score >= 9) return 'text-red-600';
  if (score >= 7) return 'text-orange-600';
  if (score >= 4) return 'text-yellow-600';
  return 'text-blue-600';
};

export function VulnerabilitiesPage() {
  const [data, setData] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [sortBy, setSortBy] = useState('detected_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [filters, setFilters] = useState<Filters>({
    severity: '',
    cve: '',
    status: '',
    asset: '',
    startDate: '',
    endDate: '',
  });
  const [stats, setStats] = useState<VulnStats>({
    total: 0, critical: 0, high: 0, medium: 0, exploitable: 0,
  });
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [scanLoading, setScanLoading] = useState(true);
  const [newScanLoading, setNewScanLoading] = useState(false);

  const buildParams = useCallback(() => {
    const params: Record<string, string> = {
      page: String(page),
      sort_by: sortBy,
      sort_order: sortOrder,
    };
    if (filters.severity) params.severity = filters.severity;
    if (filters.cve) params.cve = filters.cve;
    if (filters.status) params.status = filters.status;
    if (filters.asset) params.asset = filters.asset;
    if (filters.startDate) params.start_date = filters.startDate;
    if (filters.endDate) params.end_date = filters.endDate;
    return params;
  }, [page, sortBy, sortOrder, filters]);

  const fetchVulnerabilities = useCallback(() => {
    setLoading(true);
    setError(null);
    api.get<PaginatedResponse<Vulnerability>>('/vulnerabilities', { params: buildParams() })
      .then((res) => { setData((res as any).items); setTotal(res.total); })
      .catch((err) => setError(err?.error?.message || 'Failed to load vulnerabilities'))
      .finally(() => setLoading(false));
  }, [buildParams]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  useEffect(() => {
    api.get<VulnStats>('/vulnerabilities/stats')
      .then((res) => setStats(res))
      .catch(() => {});
  }, []);

  const fetchScans = useCallback(() => {
    setScanLoading(true);
    api.get<ScanRecord[]>('/vulnerabilities/scans')
      .then((res) => setScans(res))
      .catch(() => {})
      .finally(() => setScanLoading(false));
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  const triggerNewScan = async () => {
    setNewScanLoading(true);
    try {
      await api.post('/vulnerabilities/scans');
      fetchScans();
    } catch (err: unknown) {
      const message = (err as { error?: { message?: string } })?.error?.message || 'Failed to trigger scan';
      setError(message);
    } finally {
      setNewScanLoading(false);
    }
  };

  const handleSort = (key: string, order: 'asc' | 'desc') => {
    setSortBy(key);
    setSortOrder(order);
  };

  const clearFilters = () => {
    setFilters({ severity: '', cve: '', status: '', asset: '', startDate: '', endDate: '' });
    setPage(1);
  };

  const hasActiveFilters =
    filters.severity || filters.cve || filters.status || filters.asset || filters.startDate || filters.endDate;

  const columns = [
    {
      key: 'cve_id',
      header: 'CVE ID',
      width: '120px',
      sortable: true,
      render: (row: Vulnerability) => (
        row.cve_id ? (
          <a
            href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e: React.MouseEvent) => e.stopPropagation()}
            className="inline-flex items-center gap-1 font-mono text-xs font-medium text-brand-600 hover:text-brand-800"
          >
            {row.cve_id}
            <ExternalLink className="w-3 h-3" />
          </a>
        ) : (
          <span className="text-xs text-slate-400">â€”</span>
        )
      ),
    },
    {
      key: 'title',
      header: 'Title',
      sortable: true,
      render: (row: Vulnerability) => (
        <span className="text-sm text-slate-700">{row.title}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      width: '90px',
      sortable: true,
      render: (row: Vulnerability) => (
        <Badge variant={severityVariant[row.severity]} size="sm">{row.severity}</Badge>
      ),
    },
    {
      key: 'cvss_score',
      header: 'CVSS',
      width: '70px',
      sortable: true,
      render: (row: Vulnerability) => (
        <span
          className={`text-sm font-bold tabular-nums ${
            row.cvss_score ? cvssColor(row.cvss_score) : 'text-slate-400'
          }`}
        >
          {row.cvss_score ? row.cvss_score.toFixed(1) : 'â€”'}
        </span>
      ),
    },
    {
      key: 'affected_software',
      header: 'Software',
      width: '140px',
      render: (row: Vulnerability) => (
        <span className="text-xs text-slate-600 truncate block max-w-[130px]">{row.affected_software || 'â€”'}</span>
      ),
    },
    {
      key: 'affected_asset_id',
      header: 'Asset',
      width: '110px',
      render: (row: Vulnerability) => (
        <span className="text-xs text-slate-600">
          {row.affected_asset_id ? `AST-${row.affected_asset_id.substring(0, 6).toUpperCase()}` : 'â€”'}
        </span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      sortable: true,
      render: (row: Vulnerability) => (
        <Badge variant={statusVariant[row.status as VulnStatus]} size="sm">
          {statusLabel[row.status as VulnStatus] || row.status}
        </Badge>
      ),
    },
    {
      key: 'exploit_available',
      header: 'Exploit',
      width: '70px',
      render: (row: Vulnerability) => (
        row.exploit_available ? (
          <Badge variant="danger" size="sm">
            <AlertTriangle className="w-2.5 h-2.5 mr-0.5" />
            Yes
          </Badge>
        ) : (
          <span className="text-xs text-slate-400">â€”</span>
        )
      ),
    },
    {
      key: 'detected_at',
      header: 'Detected',
      width: '110px',
      sortable: true,
      render: (row: Vulnerability) => (
        <span className="text-xs text-slate-500">
          {new Date(row.detected_at).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric',
          })}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Vulnerability Management</h1>
          <p className="text-sm text-slate-500 mt-1">
            {stats.total} total vulnerability entry{stats.total !== 1 ? 'ies' : ''}
            {hasActiveFilters && ' (filtered)'}
          </p>
        </div>
        <Button size="md" onClick={triggerNewScan} loading={newScanLoading}>
          <ScanLine className="w-4 h-4" />
          New Scan
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard label="Total Vulnerabilities" value={String(stats.total)} icon={Shield} />
        <StatCard label="Critical" value={String(stats.critical)} icon={AlertTriangle} />
        <StatCard label="High" value={String(stats.high)} icon={AlertTriangle} />
        <StatCard label="Medium" value={String(stats.medium)} icon={AlertCircle} />
        <StatCard label="Exploitable" value={String(stats.exploitable)} icon={Bug} />
      </div>

      <Card padding="none">
        <div className="p-4 border-b border-slate-100">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Search CVE or title..."
                value={filters.cve}
                onChange={(e) => { setFilters((f) => ({ ...f, cve: e.target.value })); setPage(1); }}
                className="pl-9"
              />
            </div>
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              <select
                value={filters.severity}
                onChange={(e) => { setFilters((f) => ({ ...f, severity: e.target.value })); setPage(1); }}
                className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
              >
                {severityOptions.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
            </div>
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              <select
                value={filters.status}
                onChange={(e) => { setFilters((f) => ({ ...f, status: e.target.value })); setPage(1); }}
                className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
              >
                {vulnStatusOptions.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
            </div>
            <Input
              placeholder="Asset filter..."
              value={filters.asset}
              onChange={(e) => { setFilters((f) => ({ ...f, asset: e.target.value })); setPage(1); }}
              className="w-32"
            />
            <Input
              type="date"
              value={filters.startDate}
              onChange={(e) => { setFilters((f) => ({ ...f, startDate: e.target.value })); setPage(1); }}
              className="w-36"
            />
            <Input
              type="date"
              value={filters.endDate}
              onChange={(e) => { setFilters((f) => ({ ...f, endDate: e.target.value })); setPage(1); }}
              className="w-36"
            />
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="w-3.5 h-3.5" />
                Clear
              </Button>
            )}
          </div>
        </div>

        {error && (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            <AlertCircle className="w-10 h-10 text-red-400" />
            <p className="text-red-600 font-medium">{error}</p>
            <Button variant="secondary" size="sm" onClick={() => { setError(null); fetchVulnerabilities(); }}>
              Retry
            </Button>
          </div>
        )}

        {!error && (
          <Table
            columns={columns}
            data={data}
            keyExtractor={(row) => String(row.id)}
            page={page}
            pageSize={20}
            total={total}
            onPageChange={setPage}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSort={handleSort}
            loading={loading}
          />
        )}
      </Card>

      {/* Scan History */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
          <Button variant="ghost" size="sm" onClick={fetchScans}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        </CardHeader>

        {scanLoading && (
          <div className="flex items-center justify-center py-12">
            <Loading size="sm" text="Loading scans..." />
          </div>
        )}

        {!scanLoading && scans.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <ScanLine className="w-10 h-10 text-slate-300" />
            <p className="text-slate-500 font-medium">No scan history</p>
            <p className="text-sm text-slate-400">Run your first vulnerability scan</p>
            <Button variant="secondary" size="sm" onClick={triggerNewScan}>
              <Plus className="w-4 h-4" />
              Start Scan
            </Button>
          </div>
        )}

        {!scanLoading && scans.length > 0 && (
          <div className="divide-y divide-slate-100">
            {scans.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between py-3 px-1">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${
                    scan.status === 'running' ? 'bg-blue-50' :
                    scan.status === 'completed' ? 'bg-emerald-50' :
                    scan.status === 'failed' ? 'bg-red-50' : 'bg-yellow-50'
                  }`}>
                    {scanStatusIcon(scan.status)}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-900">{scan.name}</p>
                    <p className="text-xs text-slate-400">
                      Started {new Date(scan.started_at).toLocaleString()}
                      {scan.completed_at && ` â€” Completed ${new Date(scan.completed_at).toLocaleString()}`}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <p className="text-xs text-slate-500">{scan.total_assets} assets scanned</p>
                    <p className="text-sm font-medium text-slate-700">{scan.vulnerabilities_found} findings</p>
                  </div>
                  <Badge variant={scanStatusBadge[scan.status] || 'default'} size="sm">
                    {scan.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
