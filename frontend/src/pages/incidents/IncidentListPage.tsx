import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Search, Plus, AlertTriangle, AlertCircle, AlertOctagon,
  Info, BarChart3, ChevronDown, Filter, X,
} from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { Table } from '@/components/ui/Table';
import { Loading } from '@/components/ui/Loading';
import { StatCard } from '@/components/dashboards/StatCard';
import { api } from '@/services/api';
import type { Incident, PaginatedResponse, Severity, IncidentStatus } from '@/types';

const severityVariant: Record<Severity, 'danger' | 'warning' | 'default' | 'info'> = {
  critical: 'danger',
  high: 'warning',
  medium: 'warning',
  low: 'info',
  info: 'default',
};

const statusVariant: Record<IncidentStatus, 'danger' | 'warning' | 'success' | 'info' | 'default'> = {
  new: 'danger',
  investigating: 'warning',
  contained: 'info',
  remediated: 'success',
  closed: 'default',
  reopened: 'danger',
};

const severityIcon: Record<Severity, typeof AlertOctagon> = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Info,
};

const severityStatColors: Record<Severity, string> = {
  critical: 'text-red-600 bg-red-50',
  high: 'text-orange-600 bg-orange-50',
  medium: 'text-yellow-600 bg-yellow-50',
  low: 'text-blue-600 bg-blue-50',
  info: 'text-slate-600 bg-slate-50',
};

interface Filters {
  severity: string;
  status: string;
  search: string;
  startDate: string;
  endDate: string;
}

interface SeverityStat {
  label: string;
  value: number;
  icon: typeof AlertOctagon;
  className: string;
  severity: Severity;
}

const statusOptions: { value: string; label: string }[] = [
  { value: '', label: 'All Statuses' },
  { value: 'new', label: 'New' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'contained', label: 'Contained' },
  { value: 'remediated', label: 'Remediated' },
  { value: 'closed', label: 'Closed' },
  { value: 'reopened', label: 'Reopened' },
];

const severityOptions: { value: string; label: string }[] = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

export function IncidentListPage() {
  const navigate = useNavigate();
  const [data, setData] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [filters, setFilters] = useState<Filters>({
    severity: '',
    status: '',
    search: '',
    startDate: '',
    endDate: '',
  });
  const [severityCounts, setSeverityCounts] = useState<Record<Severity, number>>({
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  });

  const buildParams = useCallback(() => {
    const params: Record<string, string> = {
      page: String(page),
      sort_by: sortBy,
      sort_order: sortOrder,
    };
    if (filters.severity) params.severity = filters.severity;
    if (filters.status) params.status = filters.status;
    if (filters.search) params.search = filters.search;
    if (filters.startDate) params.start_date = filters.startDate;
    if (filters.endDate) params.end_date = filters.endDate;
    return params;
  }, [page, sortBy, sortOrder, filters]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    api.get<{ items: Incident[]; meta: { total_items: number; page: number; page_size: number; total_pages: number } }>('/incidents', { params: buildParams() })
      .then((res) => {
        setData(res.items);
        setTotal(res.meta.total_items);
        setTotalPages(res.meta.total_pages);
      })
      .catch((err) => {
        setLoading(false);
      });
  }, [buildParams]);

  useEffect(() => {
    api.get<{ counts: Record<Severity, number> }>('/incidents/severity-counts')
      .then((res) => setSeverityCounts(res.counts))
      .catch(() => {});
  }, []);

  const handleSort = (key: string, order: 'asc' | 'desc') => {
    setSortBy(key);
    setSortOrder(order);
  };

  const totalIncidents = Object.values(severityCounts).reduce((a, b) => a + b, 0);

  const stats: SeverityStat[] = [
    { label: 'Critical', value: severityCounts.critical, icon: AlertOctagon, className: severityStatColors.critical, severity: 'critical' },
    { label: 'High', value: severityCounts.high, icon: AlertTriangle, className: severityStatColors.high, severity: 'high' },
    { label: 'Medium', value: severityCounts.medium, icon: AlertCircle, className: severityStatColors.medium, severity: 'medium' },
    { label: 'Low', value: severityCounts.low, icon: Info, className: severityStatColors.low, severity: 'low' },
    { label: 'Info', value: severityCounts.info, icon: Info, className: severityStatColors.info, severity: 'info' },
    { label: 'Total', value: totalIncidents, icon: BarChart3, className: 'text-brand-600 bg-brand-50', severity: 'info' },
  ];

  const clearFilters = () => {
    setFilters({ severity: '', status: '', search: '', startDate: '', endDate: '' });
    setPage(1);
  };

  const hasActiveFilters =
    filters.severity || filters.status || filters.search || filters.startDate || filters.endDate;

  const columns = [
    {
      key: 'id',
      header: 'ID',
      width: '120px',
      sortable: true,
      render: (row: Incident) => (
        <span className="font-mono text-xs font-medium text-brand-700">INC-{row.id.substring(0, 8).toUpperCase()}</span>
      ),
    },
    { key: 'title', header: 'Title', sortable: true },
    {
      key: 'severity',
      header: 'Severity',
      width: '100px',
      sortable: true,
      render: (row: Incident) => (
        <Badge variant={severityVariant[row.severity]} size="sm">{row.severity}</Badge>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '120px',
      sortable: true,
      render: (row: Incident) => (
        <Badge variant={statusVariant[row.status]} size="sm">{row.status.replace('_', ' ')}</Badge>
      ),
    },
    {
      key: 'assignee',
      header: 'Assignee',
      width: '130px',
      render: (row: Incident) => (
        <span className="text-slate-600">{row.assignee_name || 'Unassigned'}</span>
      ),
    },
    {
      key: 'affected_assets',
      header: 'Affected Assets',
      width: '130px',
      render: (row: Incident) => (
        <span className="text-slate-600">{row.affected_assets?.length || 0} asset{(row.affected_assets?.length || 0) !== 1 ? 's' : ''}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Created',
      width: '150px',
      sortable: true,
      render: (row: Incident) => (
        <span className="text-slate-500 text-xs">
          {new Date(row.created_at).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
          })}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Incidents</h1>
          <p className="text-sm text-slate-500 mt-1">
            {total} incident{total !== 1 ? 's' : ''} found
            {hasActiveFilters && ' (filtered)'}
          </p>
        </div>
        <Button size="md" onClick={() => navigate('/incidents/new')}>
          <Plus className="w-4 h-4" />
          New Incident
        </Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} padding="sm" hover>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${stat.className}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div>
                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{stat.label}</p>
                  <p className="text-xl font-bold text-slate-900">{stat.value}</p>
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      <Card padding="none">
        <div className="p-4 border-b border-slate-100">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Search incidents..."
                value={filters.search}
                onChange={(e) => { setFilters((f) => ({ ...f, search: e.target.value })); setPage(1); }}
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
                {statusOptions.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
            </div>
            <Input
              type="date"
              value={filters.startDate}
              onChange={(e) => { setFilters((f) => ({ ...f, startDate: e.target.value })); setPage(1); }}
              className="w-36"
              placeholder="Start date"
            />
            <Input
              type="date"
              value={filters.endDate}
              onChange={(e) => { setFilters((f) => ({ ...f, endDate: e.target.value })); setPage(1); }}
              className="w-36"
              placeholder="End date"
            />
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="w-3.5 h-3.5" />
                Clear
              </Button>
            )}
          </div>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-20">
            <Loading size="lg" text="Loading incidents..." />
          </div>
        )}

        {!loading && (
          <Table
            columns={columns}
            data={(data as unknown) as Record<string, unknown>[]}
            keyExtractor={(row) => String(row.id)}
            page={page}
            pageSize={20}
            total={total}
            onPageChange={setPage}
            sortBy={sortBy}
            sortOrder={sortOrder}
            onSort={handleSort}
            onRowClick={(row: Record<string, unknown>) => navigate(`/incidents/${row.id}`)}
          />
        )}
      </Card>
    </div>
  );
}
