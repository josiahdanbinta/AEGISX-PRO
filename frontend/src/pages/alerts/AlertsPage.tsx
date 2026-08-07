import { useState, useEffect, useCallback } from 'react';
import {
  Bell, Search, CheckCircle, XCircle, ArrowUpCircle,
  AlertTriangle, AlertCircle, Clock, Filter, ChevronDown, X,
  CheckSquare, Square,
} from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { Table } from '@/components/ui/Table';
import { Loading } from '@/components/ui/Loading';
import { StatCard } from '@/components/dashboards/StatCard';
import { api } from '@/services/api';
import type { Alert, PaginatedResponse, Severity } from '@/types';

const severityVariant: Record<Severity, 'danger' | 'warning' | 'default' | 'info'> = {
  critical: 'danger',
  high: 'warning',
  medium: 'warning',
  low: 'info',
  info: 'default',
};

type AlertStatus = 'new' | 'acknowledged' | 'dismissed';

const statusVariant: Record<AlertStatus, 'danger' | 'warning' | 'success' | 'info' | 'default'> = {
  new: 'danger',
  acknowledged: 'warning',
  dismissed: 'default',
};

interface Filters {
  severity: string;
  status: string;
  rule: string;
  search: string;
  startDate: string;
  endDate: string;
}

interface AlertStats {
  totalToday: number;
  critical: number;
  dismissed: number;
  avgTriageTime: string;
}

const severityOptions = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const statusOptions = [
  { value: '', label: 'All Statuses' },
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'dismissed', label: 'Dismissed' },
];

export function AlertsPage() {
  const [data, setData] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [stats, setStats] = useState<AlertStats>({
    totalToday: 0,
    critical: 0,
    dismissed: 0,
    avgTriageTime: '0m',
  });
  const [filters, setFilters] = useState<Filters>({
    severity: '',
    status: '',
    rule: '',
    search: '',
    startDate: '',
    endDate: '',
  });

  const buildParams = useCallback(() => {
    const params: Record<string, string> = {
      page: String(page),
      sort_by: sortBy,
      sort_order: sortOrder,
    };
    if (filters.severity) params.severity = filters.severity;
    if (filters.status) params.status = filters.status;
    if (filters.rule) params.rule = filters.rule;
    if (filters.search) params.search = filters.search;
    if (filters.startDate) params.start_date = filters.startDate;
    if (filters.endDate) params.end_date = filters.endDate;
    return params;
  }, [page, sortBy, sortOrder, filters]);

  const fetchAlerts = useCallback(() => {
    setLoading(true);
    setError(null);
    api.get<PaginatedResponse<Alert>>('/detection/alerts', { params: buildParams() })
      .then((res) => {
        setData((res as any).items || (res as any).data || []);
        setTotal((res as any).total || 0);
      })
      .catch((err) => {
        setError(err?.error?.message || 'Failed to load alerts');
      })
      .finally(() => setLoading(false));
  }, [buildParams]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    api.get<AlertStats>('/detection/alerts/stats')
      .then((res) => setStats(res))
      .catch(() => {});
  }, []);

  const toggleSelectAll = () => {
    if (selectedIds.size === data.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(data.map((a) => a.id)));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const performBulkAction = async (action: 'acknowledge' | 'dismiss' | 'escalate') => {
    if (selectedIds.size === 0) return;
    setBulkActionLoading(true);
    try {
      await api.post(`/detection/alerts/bulk/${action}`, { ids: Array.from(selectedIds) });
      setSelectedIds(new Set());
      fetchAlerts();
    } catch (err: unknown) {
      const message = (err as { error?: { message?: string } })?.error?.message || `Failed to ${action} alerts`;
      setError(message);
    } finally {
      setBulkActionLoading(false);
    }
  };

  const handleSingleAction = async (id: string, action: 'acknowledge' | 'dismiss' | 'escalate') => {
    try {
      await api.post(`/detection/alerts/${id}/${action}`);
      fetchAlerts();
    } catch (err: unknown) {
      const message = (err as { error?: { message?: string } })?.error?.message || `Failed to ${action} alert`;
      setError(message);
    }
  };

  const handleSort = (key: string, order: 'asc' | 'desc') => {
    setSortBy(key);
    setSortOrder(order);
  };

  const clearFilters = () => {
    setFilters({ severity: '', status: '', rule: '', search: '', startDate: '', endDate: '' });
    setPage(1);
  };

  const hasActiveFilters =
    filters.severity || filters.status || filters.rule || filters.search || filters.startDate || filters.endDate;

  const columns = [
    {
      key: 'select',
      header: (
        <button onClick={toggleSelectAll} className="inline-flex items-center">
          {selectedIds.size === data.length && data.length > 0 ? (
            <CheckSquare className="w-4 h-4 text-brand-600" />
          ) : (
            <Square className="w-4 h-4 text-slate-400" />
          )}
        </button>
      ),
      width: '48px',
      sortable: false,
      render: (row: Alert) => (
        <button onClick={(e: React.MouseEvent) => { e.stopPropagation(); toggleSelect(row.id); }} className="inline-flex items-center">
          {selectedIds.has(row.id) ? (
            <CheckSquare className="w-4 h-4 text-brand-600" />
          ) : (
            <Square className="w-4 h-4 text-slate-400" />
          )}
        </button>
      ),
    },
    {
      key: 'id',
      header: 'ID',
      width: '110px',
      sortable: true,
      render: (row: Alert) => (
        <span className="font-mono text-xs font-medium text-brand-700">ALT-{row.id.substring(0, 8).toUpperCase()}</span>
      ),
    },
    { key: 'title', header: 'Title', sortable: true },
    {
      key: 'severity',
      header: 'Severity',
      width: '90px',
      sortable: true,
      render: (row: Alert) => (
        <Badge variant={severityVariant[row.severity]} size="sm">{row.severity}</Badge>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      width: '110px',
      sortable: true,
      render: (row: Alert) => (
        <Badge variant={statusVariant[row.status as AlertStatus]} size="sm">{row.status}</Badge>
      ),
    },
    {
      key: 'rule_name',
      header: 'Rule',
      width: '140px',
      render: (row: Alert) => (
        <span className="text-slate-600 text-xs truncate block max-w-[120px]">{row.rule_name || '—'}</span>
      ),
    },
    {
      key: 'source_ip',
      header: 'Source IP',
      width: '120px',
      render: (row: Alert) => (
        <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-700">{row.source_ip || '—'}</code>
      ),
    },
    {
      key: 'source_asset_id',
      header: 'Source Asset',
      width: '130px',
      render: (row: Alert) => (
        <span className="text-slate-600 text-xs">{row.source_asset_id ? `AST-${row.source_asset_id.substring(0, 6).toUpperCase()}` : '—'}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Time',
      width: '130px',
      sortable: true,
      render: (row: Alert) => (
        <span className="text-slate-500 text-xs">
          {new Date(row.created_at).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
          })}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      width: '120px',
      sortable: false,
      render: (row: Alert) => (
        <div className="flex items-center gap-1">
          <button
            onClick={(e: React.MouseEvent) => { e.stopPropagation(); handleSingleAction(row.id, 'acknowledge'); }}
            className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 transition-colors"
            title="Acknowledge"
          >
            <CheckCircle className="w-4 h-4" />
          </button>
          <button
            onClick={(e: React.MouseEvent) => { e.stopPropagation(); handleSingleAction(row.id, 'dismiss'); }}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors"
            title="Dismiss"
          >
            <XCircle className="w-4 h-4" />
          </button>
          <button
            onClick={(e: React.MouseEvent) => { e.stopPropagation(); handleSingleAction(row.id, 'escalate'); }}
            className="p-1.5 rounded-lg text-slate-400 hover:text-brand-600 hover:bg-brand-50 transition-colors"
            title="Escalate to Incident"
          >
            <ArrowUpCircle className="w-4 h-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Alerts & Detection</h1>
          <p className="text-sm text-slate-500 mt-1">
            {stats.totalToday} new alert{stats.totalToday !== 1 ? 's' : ''} today
            {hasActiveFilters && ' (filtered)'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 mr-2">
              <span className="text-sm text-slate-500">{selectedIds.size} selected</span>
              <Button
                variant="secondary"
                size="sm"
                loading={bulkActionLoading}
                onClick={() => performBulkAction('acknowledge')}
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Acknowledge
              </Button>
              <Button
                variant="secondary"
                size="sm"
                loading={bulkActionLoading}
                onClick={() => performBulkAction('dismiss')}
              >
                <XCircle className="w-3.5 h-3.5" />
                Dismiss
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={bulkActionLoading}
                onClick={() => performBulkAction('escalate')}
              >
                <ArrowUpCircle className="w-3.5 h-3.5" />
                Escalate
              </Button>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Today" value={String(stats.totalToday)} icon={Bell} />
        <StatCard label="Critical" value={String(stats.critical)} icon={AlertTriangle} />
        <StatCard label="Dismissed (FP)" value={String(stats.dismissed)} icon={XCircle} />
        <StatCard label="Avg Triage Time" value={stats.avgTriageTime} icon={Clock} />
      </div>

      <Card padding="none">
        <div className="p-4 border-b border-slate-100">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Search alerts..."
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
              placeholder="Rule name..."
              value={filters.rule}
              onChange={(e) => { setFilters((f) => ({ ...f, rule: e.target.value })); setPage(1); }}
              className="w-36"
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
            <Button variant="secondary" size="sm" onClick={() => { setError(null); fetchAlerts(); }}>
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
    </div>
  );
}
