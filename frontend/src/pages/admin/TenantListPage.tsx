import { useState, useEffect, useCallback } from 'react';
import { Building2, Plus, RefreshCw, Search, AlertCircle, X } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { Loading } from '@/components/ui/Loading';
import { api } from '@/services/api';
import toast from 'react-hot-toast';

interface Tenant {
  id: string;
  name: string;
  display_name: string;
  subscription_tier: string;
  status: string;
  quota_assets: number;
  quota_users: number;
  created_at: string;
}

const statusVariant: Record<string, 'success' | 'warning' | 'danger' | 'default'> = {
  active: 'success',
  suspended: 'danger',
  trial: 'warning',
};

interface TenantListResponse {
  items: Tenant[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export function TenantListPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', display_name: '', subscription_tier: 'enterprise', quota_assets: 1000, quota_users: 100 });
  const [creating, setCreating] = useState(false);

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { page_size: '20', page: String(page) };
      if (search) params.search = search;
      const res = await api.get<TenantListResponse>('/tenants', { params });
      setTenants(res.items);
      setTotal(res.total);
      setTotalPages(res.total_pages);
    } catch {
      setError('Failed to load tenants');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => { fetchTenants(); }, [fetchTenants]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await api.post('/tenants', form);
      toast.success('Tenant created');
      setShowCreate(false);
      setForm({ name: '', display_name: '', subscription_tier: 'enterprise', quota_assets: 1000, quota_users: 100 });
      fetchTenants();
    } catch (err: unknown) {
      const e = err as { error?: { message?: string } };
      toast.error(e?.error?.message || 'Failed to create tenant');
    } finally {
      setCreating(false);
    }
  };

  const toggleStatus = async (tenant: Tenant) => {
    const newStatus = tenant.status === 'active' ? 'suspended' : 'active';
    try {
      await api.patch(`/tenants/${tenant.id}`, { status: newStatus });
      toast.success(`Tenant ${newStatus}`);
      fetchTenants();
    } catch {
      toast.error('Failed to update tenant');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Tenant Management</h1>
          <p className="text-sm text-slate-500 mt-1">Manage all platform tenants</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" icon={RefreshCw} onClick={fetchTenants} size="sm">Refresh</Button>
          <Button variant="primary" icon={Plus} onClick={() => setShowCreate(true)} size="sm">New Tenant</Button>
        </div>
      </div>

      {showCreate && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between w-full">
              <CardTitle>Create Tenant</CardTitle>
              <button onClick={() => setShowCreate(false)}><X className="w-5 h-5 text-slate-400" /></button>
            </div>
          </CardHeader>
          <div className="px-6 pb-6 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Input label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="tenant-slug" />
              <Input label="Display Name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} placeholder="Company Name" />
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-slate-700">Tier</label>
                <select className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm" value={form.subscription_tier} onChange={(e) => setForm({ ...form, subscription_tier: e.target.value })}>
                  <option value="enterprise">Enterprise</option>
                  <option value="professional">Professional</option>
                  <option value="starter">Starter</option>
                  <option value="trial">Trial</option>
                </select>
              </div>
              <Input label="Asset Quota" type="number" value={String(form.quota_assets)} onChange={(e) => setForm({ ...form, quota_assets: Number(e.target.value) })} />
              <Input label="User Quota" type="number" value={String(form.quota_users)} onChange={(e) => setForm({ ...form, quota_users: Number(e.target.value) })} />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button variant="primary" loading={creating} onClick={handleCreate}>Create</Button>
            </div>
          </div>
        </Card>
      )}

      <Card>
        <CardHeader>
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              placeholder="Search tenants..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="w-full pl-9 pr-4 py-2 text-sm border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500"
            />
          </div>
        </CardHeader>

        {loading ? (
          <div className="flex items-center justify-center py-20"><Loading size="lg" text="Loading tenants..." /></div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <AlertCircle className="w-10 h-10 text-red-400" />
            <p className="text-red-600 text-sm">{error}</p>
            <Button variant="secondary" size="sm" onClick={fetchTenants}>Retry</Button>
          </div>
        ) : tenants.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-2">
            <Building2 className="w-10 h-10 text-slate-300" />
            <p className="text-sm text-slate-400">No tenants found</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Name</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Display</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Tier</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Status</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Assets</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Users</th>
                    <th className="text-left text-xs font-medium text-slate-500 uppercase px-4 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {tenants.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-50">
                      <td className="px-4 py-3 text-sm font-medium text-slate-900">{t.name}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{t.display_name}</td>
                      <td className="px-4 py-3"><Badge variant="info" size="sm">{t.subscription_tier}</Badge></td>
                      <td className="px-4 py-3"><Badge variant={statusVariant[t.status] || 'default'} size="sm">{t.status}</Badge></td>
                      <td className="px-4 py-3 text-sm text-slate-500">{t.quota_assets}</td>
                      <td className="px-4 py-3 text-sm text-slate-500">{t.quota_users}</td>
                      <td className="px-4 py-3">
                        <Button variant="secondary" size="sm" onClick={() => toggleStatus(t)}>
                          {t.status === 'active' ? 'Suspend' : 'Activate'}
                        </Button>
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
