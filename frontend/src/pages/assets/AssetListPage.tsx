import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Plus, RefreshCw, Monitor, Wifi, Server, AlertCircle } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { Loading } from '@/components/ui/Loading';
import { StatCard } from '@/components/dashboards/StatCard';
import { api } from '@/services/api';

interface Asset {
  id: string;
  hostname: string;
  type: string;
  os: string | null;
  status: string;
  risk_level: string;
  ip_address: string | null;
  agent_id: string | null;
  created_at: string;
}

interface AssetListResponse {
  items: Asset[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

const statusVariant: Record<string, 'success' | 'warning' | 'danger' | 'default'> = {
  online: 'success',
  offline: 'danger',
  maintenance: 'warning',
};

const riskVariant: Record<string, 'danger' | 'warning' | 'info' | 'default' | 'success'> = {
  critical: 'danger',
  high: 'warning',
  medium: 'warning',
  low: 'info',
};

export function AssetListPage() {
  const navigate = useNavigate();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterStatus, setFilterStatus] = useState('');

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {
        page_size: '20',
        page: String(page),
      };
      if (search) params.search = search;
      const res = await api.get<AssetListResponse>('/assets', { params });
      setAssets(res.items);
      setTotal(res.meta.total_items);
      setTotalPages((res as any).meta?.total_pages);
    } catch (err: unknown) {
      const e = err as { error?: { message?: string } };
      setError(e?.error?.message || 'Failed to load assets');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => { fetchAssets(); }, [fetchAssets]);

  const onlineCount = assets.filter(a => a.status === 'online').length;
  const offlineCount = assets.filter(a => a.status === 'offline').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Asset Management</h1>
          <p className="text-sm text-slate-500 mt-1">Monitor and manage all registered assets</p>
        </div>
        <Button variant="primary" icon={RefreshCw} onClick={fetchAssets} size="sm">
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Total Assets" value={String(total)} icon={Monitor} />
        <StatCard label="Online" value={String(onlineCount)} icon={Wifi} />
        <StatCard label="Offline" value={String(offlineCount)} icon={Server} />
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-3 w-full flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                placeholder="Search by hostname or IP..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="w-full pl-9 pr-4 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500"
              />
            </div>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Types</option>
              <option value="workstation">Workstation</option>
              <option value="server">Server</option>
              <option value="network">Network</option>
              <option value="cloud">Cloud</option>
              <option value="container">Container</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Status</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="maintenance">Maintenance</option>
            </select>
          </div>
        </CardHeader>

        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loading size="lg" text="Loading assets..." />
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <AlertCircle className="w-10 h-10 text-red-400" />
            <p className="text-red-600 text-sm">{error}</p>
            <Button variant="secondary" size="sm" onClick={fetchAssets}>Retry</Button>
          </div>
        ) : assets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-2">
            <Monitor className="w-10 h-10 text-slate-300" />
            <p className="text-sm text-slate-400">No assets found</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Hostname</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Type</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">OS</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Status</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Risk</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">IP</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Agent</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {assets.map((asset) => (
                    <tr
                      key={asset.id}
                      onClick={() => navigate(`/assets/${asset.id}`)}
                      className="hover:bg-slate-50 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3 text-sm font-medium text-slate-900">{asset.hostname}</td>
                      <td className="px-4 py-3 text-sm text-slate-600 capitalize">{asset.type}</td>
                      <td className="px-4 py-3 text-sm text-slate-500">{asset.os || 'â€”'}</td>
                      <td className="px-4 py-3">
                        <Badge variant={statusVariant[asset.status] || 'default'} size="sm">{asset.status}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant={riskVariant[asset.risk_level] || 'default'} size="sm">{asset.risk_level || 'low'}</Badge>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-500 font-mono">{asset.ip_address || 'â€”'}</td>
                      <td className="px-4 py-3 text-sm text-slate-500">{asset.agent_id ? 'Connected' : 'â€”'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200">
              <span className="text-sm text-slate-500">
                Showing {((page - 1) * 20) + 1}â€“{Math.min(page * 20, total)} of {total}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                  Previous
                </Button>
                <span className="text-sm text-slate-500">Page {page} of {totalPages}</span>
                <Button variant="secondary" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
