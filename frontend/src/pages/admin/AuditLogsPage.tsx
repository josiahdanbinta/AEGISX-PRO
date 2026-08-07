import { useState, useEffect, useCallback } from 'react';
import { Search, RefreshCw, Activity, AlertCircle, Download } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Loading } from '@/components/ui/Loading';
import { api } from '@/services/api';
import toast from 'react-hot-toast';

interface AuditLog {
  id: string;
  user_name: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  status: string;
  details: string | null;
  created_at: string;
}

interface AuditLogResponse {
  items: AuditLog[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

const statusVariant: Record<string, 'success' | 'danger' | 'warning' | 'default'> = {
  success: 'success',
  failure: 'danger',
  blocked: 'warning',
};

export function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('');

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = { page_size: '20', page: String(page) };
      if (search) params.search = search;
      const res = await api.get<AuditLogResponse>('/audit/logs', { params });
      setLogs(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch (err: unknown) {
      const e = err as { error?: { message?: string } };
      setError(e?.error?.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const handleExport = () => {
    toast.success('Export initiated (this feature requires backend integration)');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Audit Logs</h1>
          <p className="text-sm text-slate-500 mt-1">Complete activity trail for compliance and security</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" icon={Download} onClick={handleExport} size="sm">Export</Button>
          <Button variant="secondary" icon={RefreshCw} onClick={fetchLogs} size="sm">Refresh</Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3 w-full flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                placeholder="Search by user, action, or resource..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="w-full pl-9 pr-4 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500"
              />
            </div>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Actions</option>
              <option value="login">Login</option>
              <option value="create">Create</option>
              <option value="update">Update</option>
              <option value="delete">Delete</option>
              <option value="export">Export</option>
            </select>
          </div>
        </CardHeader>

        {loading ? (
          <div className="flex items-center justify-center py-20"><Loading size="lg" text="Loading audit logs..." /></div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <AlertCircle className="w-10 h-10 text-red-400" />
            <p className="text-red-600 text-sm">{error}</p>
            <Button variant="secondary" size="sm" onClick={fetchLogs}>Retry</Button>
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-2">
            <Activity className="w-10 h-10 text-slate-300" />
            <p className="text-sm text-slate-400">No audit logs found</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Timestamp</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">User</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Action</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Resource</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">IP</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50">
                      <td className="px-4 py-3 text-sm text-slate-500 font-mono">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-slate-900">{log.user_name}</td>
                      <td className="px-4 py-3 text-sm text-slate-600 capitalize">{log.action}</td>
                      <td className="px-4 py-3 text-sm text-slate-500">
                        {log.resource_type}{log.resource_id ? `/${log.resource_id.substring(0, 8)}` : ''}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-500 font-mono">{log.ip_address || '—'}</td>
                      <td className="px-4 py-3">
                        <Badge variant={statusVariant[log.status] || 'default'} size="sm">{log.status}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200">
              <span className="text-sm text-slate-500">Showing {((page - 1) * 20) + 1}–{Math.min(page * 20, total)} of {total}</span>
              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
                <span className="text-sm text-slate-500">Page {page} of {totalPages}</span>
                <Button variant="secondary" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
