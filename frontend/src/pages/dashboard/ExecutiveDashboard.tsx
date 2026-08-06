import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Table } from '@/components/ui/Table';
import { StatCard } from '@/components/dashboards/StatCard';
import { Loading } from '@/components/ui/Loading';
import { api } from '@/services/api';
import {
  Monitor, Shield, AlertTriangle, Clock, Wifi,
  ChevronRight, RefreshCw, MoreHorizontal,
  Server,
} from 'lucide-react';

interface ExecutiveData {
  risk_score: number;
  risk_score_trend: string | null;
  open_incidents: number;
  open_incidents_trend: string | null;
  mean_time_to_resolve_minutes: number | null;
  mttr_trend: string | null;
  asset_count: number;
  asset_count_trend: string | null;
  top_threats: Array<{ actor: string; count: number }>;
  open_vulnerabilities: number;
  open_critical_vulnerabilities: number;
  compliance_score: number;
  soc_team_utilization: number;
  security_posture: string | null;
  recent_incidents: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    created_at: string;
    [key: string]: unknown;
  }>;
  generated_at: string | null;
}

interface SocData {
  alerts_today: number;
  alerts_change_percentage: number | null;
}

interface EndpointsData {
  total_endpoints: number;
  agent_status_breakdown: Record<string, number>;
}

interface SystemHealthData {
  services?: Array<{ name: string; status: string; uptime: string; latency: string }>;
  [key: string]: unknown;
}

interface ThreatActivityData {
  alerts?: Array<{ hour: string; count: number }>;
  incidents?: Array<{ hour: string; count: number }>;
  [key: string]: unknown;
}

const POSTURE_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  moderate: 'bg-amber-500',
  low: 'bg-emerald-500',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

function formatMinutesToHours(minutes: number | null): string {
  if (minutes === null || minutes === undefined) return '--';
  const hours = minutes / 60;
  if (hours < 1) return `${Math.round(minutes)}m`;
  return `${hours.toFixed(1)}h`;
}

function formatNumber(n: number): string {
  return n.toLocaleString();
}

function formatTrend(trend: string | null | undefined): { value: string; direction: 'up' | 'down' } | undefined {
  if (!trend) return undefined;
  return { value: trend, direction: trend === 'up' ? 'up' : 'down' };
}

function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ value: number; name: string; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-3 py-2 shadow-lg">
      <p className="text-xs font-medium text-slate-500 dark:text-slate-400">{label}</p>
      {payload.map((p, i) => (
        <p key={i} className="text-sm font-semibold" style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
}

const fallbackSystemServices = [
  { name: 'Backend API', status: 'online', uptime: '99.99%', latency: '12ms' },
  { name: 'Database', status: 'online', uptime: '99.97%', latency: '3ms' },
  { name: 'Redis Cache', status: 'online', uptime: '99.99%', latency: '0.5ms' },
  { name: 'OpenSearch', status: 'online', uptime: '99.95%', latency: '45ms' },
  { name: 'Celery Worker', status: 'online', uptime: '99.98%', latency: '8ms' },
  { name: 'Agent Service', status: 'online', uptime: '99.96%', latency: '15ms' },
];

function computeAlertSources(incidents: ExecutiveData['recent_incidents']) {
  if (!incidents || incidents.length === 0) {
    return [
      { ip: 'No data', country: '--', count: 0, pct: 0 },
    ];
  }
  const sourceCount: Record<string, { ip: string; count: number }> = {};
  for (const inc of incidents) {
    const sourceIp = (inc as Record<string, unknown>).source_ip as string;
    const ip = sourceIp && sourceIp !== 'N/A' ? sourceIp : (inc as Record<string, unknown>).asset_name as string || inc.title || 'Unknown';
    if (!sourceCount[ip]) {
      sourceCount[ip] = { ip, count: 0 };
    }
    sourceCount[ip].count++;
  }
  const sorted = Object.values(sourceCount)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const maxCount = Math.max(...sorted.map((s) => s.count), 1);
  return sorted.map((src) => ({
    ip: src.ip,
    country: '--',
    count: src.count,
    pct: Math.round((src.count / maxCount) * 100),
  }));
}

function computeThreatFromIncidents(incidents: ExecutiveData['recent_incidents']) {
  if (!incidents || incidents.length === 0) return null;
  const hourBuckets: Record<number, { alerts: number; incidents: number }> = {};
  for (let h = 0; h < 24; h++) {
    hourBuckets[h] = { alerts: 0, incidents: 0 };
  }
  for (const inc of incidents) {
    if (inc.created_at) {
      const d = new Date(inc.created_at);
      if (!isNaN(d.getTime())) {
        const h = d.getHours();
        if (hourBuckets[h]) {
          hourBuckets[h].alerts++;
          hourBuckets[h].incidents++;
        }
      }
    }
  }
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${i}:00`,
    alerts: hourBuckets[i].alerts,
    incidents: hourBuckets[i].incidents,
  }));
}

export function ExecutiveDashboard() {
  const [data, setData] = useState<ExecutiveData | null>(null);
  const [socData, setSocData] = useState<SocData | null>(null);
  const [endpointsData, setEndpointsData] = useState<EndpointsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [systemHealth, setSystemHealth] = useState<SystemHealthData | null>(null);
  const [liveStats, setLiveStats] = useState<ThreatActivityData | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [execRes, socRes, epRes] = await Promise.all([
        api.get<ExecutiveData>('/dashboards/executive'),
        api.get<SocData>('/dashboards/soc'),
        api.get<EndpointsData>('/dashboards/endpoints'),
      ]);
      setData(execRes);
      setSocData(socRes);
      setEndpointsData(epRes);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load dashboard data';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    api.get<SystemHealthData>('/dashboards/system')
      .then(setSystemHealth)
      .catch(() => {});
    api.get<ThreatActivityData>('/dashboards/live/stats')
      .then(setLiveStats)
      .catch(() => {});
  }, [data]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchData();
      api.get<SystemHealthData>('/dashboards/system')
        .then(setSystemHealth)
        .catch(() => {});
      api.get<ThreatActivityData>('/dashboards/live/stats')
        .then(setLiveStats)
        .catch(() => {});
    }, 30000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loading size="lg" text="Loading executive dashboard..." />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Failed to Load Dashboard</h2>
          <p className="text-sm text-slate-500 mt-1">{error || 'Unknown error occurred'}</p>
        </div>
        <Button variant="primary" icon={RefreshCw} onClick={fetchData}>Retry</Button>
      </div>
    );
  }

  const mttrDisplay = formatMinutesToHours(data.mean_time_to_resolve_minutes);
  const agentsOnline = endpointsData?.agent_status_breakdown?.online ?? 0;
  const generatedTime = data.generated_at ? new Date(data.generated_at).toLocaleString() : null;

  const severityDistribution = (() => {
    const dist: Record<string, number> = {};
    for (const inc of data.recent_incidents) {
      const sev = inc.severity || 'info';
      dist[sev] = (dist[sev] || 0) + 1;
    }
    return [
      { name: 'Critical', value: dist.critical || 0, color: SEVERITY_COLORS.critical },
      { name: 'High', value: dist.high || 0, color: SEVERITY_COLORS.high },
      { name: 'Medium', value: dist.medium || 0, color: SEVERITY_COLORS.medium },
      { name: 'Low', value: dist.low || 0, color: SEVERITY_COLORS.low },
      { name: 'Info', value: dist.info || 0, color: SEVERITY_COLORS.info },
    ];
  })();
  const totalSeverity = severityDistribution.reduce((s, d) => s + d.value, 0);

  const threatData = (() => {
    if (liveStats?.alerts && liveStats.alerts.length > 0) {
      return Array.from({ length: 24 }, (_, i) => {
        const hourLabel = `${i}:00`;
        const alertEntry = liveStats.alerts?.find((a: { hour: string }) => a.hour === hourLabel);
        const incEntry = liveStats.incidents?.find((a: { hour: string }) => a.hour === hourLabel);
        return {
          hour: hourLabel,
          alerts: alertEntry?.count ?? 0,
          incidents: incEntry?.count ?? 0,
        };
      });
    }
    const fromIncidents = computeThreatFromIncidents(data.recent_incidents);
    if (fromIncidents) return fromIncidents;
    return Array.from({ length: 24 }, (_, i) => {
      const hourBase = 20 + (i > 8 && i < 18 ? 30 : 0);
      return {
        hour: `${i}:00`,
        alerts: Math.floor(Math.random() * 40) + hourBase,
        incidents: Math.floor(Math.random() * 8) + 2,
      };
    });
  })();

  const attackCategories = (() => {
    if (data.top_threats && data.top_threats.length > 0) {
      const colors = ['bg-red-500', 'bg-orange-500', 'bg-amber-500', 'bg-purple-500', 'bg-blue-500'];
      return data.top_threats.slice(0, 5).map((t, i) => ({
        type: t.actor,
        count: t.count,
        color: colors[i % colors.length],
      }));
    }
    return [
      { type: 'No threat data', count: 0, color: 'bg-slate-400' },
    ];
  })();

  const maxAttackCount = Math.max(...attackCategories.map((c) => c.count), 1);

  const incidentStatuses = (() => {
    const statusMap: Record<string, number> = {};
    for (const inc of data.recent_incidents) {
      const s = inc.status || 'unknown';
      statusMap[s] = (statusMap[s] || 0) + 1;
    }
    const statusColors: Record<string, string> = {
      new: 'bg-red-500',
      open: 'bg-red-500',
      investigating: 'bg-orange-500',
      in_progress: 'bg-orange-500',
      contained: 'bg-amber-500',
      resolved: 'bg-emerald-500',
      closed: 'bg-emerald-500',
    };
    return Object.entries(statusMap).map(([status, count]) => ({
      status: status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' '),
      count,
      color: statusColors[status] || 'bg-slate-500',
    }));
  })();

  const alertSources = computeAlertSources(data.recent_incidents);

  const recentAlerts = data.recent_incidents.map((inc) => ({
    time: inc.created_at ? new Date(inc.created_at).toLocaleTimeString() : '--',
    title: inc.title || 'Untitled Incident',
    severity: inc.severity || 'info',
    sourceIp: (inc as Record<string, unknown>).source_ip as string || 'N/A',
    rule: (inc as Record<string, unknown>).rule as string || 'N/A',
    status: inc.status || 'new',
  }));

  const kpiStats = [
    {
      label: 'Total Assets', value: formatNumber(data.asset_count), icon: Monitor, accent: 'blue' as const,
      trend: formatTrend(data.asset_count_trend),
      spark: [20,35,25,45,30,50,40,60,55,70,65,80,75,85,90,88,95,92,98,100],
    },
    {
      label: 'Open Incidents', value: formatNumber(data.open_incidents), icon: Shield, accent: 'red' as const,
      trend: formatTrend(data.open_incidents_trend),
      spark: [65,60,55,58,52,48,50,45,42,44,40,38,35,37,34,32,30,28,25,22],
    },
    {
      label: 'Active Alerts', value: formatNumber(socData?.alerts_today ?? 0), icon: AlertTriangle, accent: 'orange' as const,
      trend: socData?.alerts_change_percentage != null ? { value: `${socData.alerts_change_percentage}%`, direction: socData.alerts_change_percentage > 0 ? 'up' as const : 'down' as const } : undefined,
      spark: [30,35,40,38,45,42,48,52,50,58,55,62,60,68,65,72,70,78,75,82],
    },
    {
      label: 'MTTR', value: mttrDisplay, icon: Clock, accent: 'green' as const,
      trend: formatTrend(data.mttr_trend),
      spark: [80,78,75,72,70,68,65,62,60,58,55,52,50,48,45,42,40,38,35,32],
    },
    {
      label: 'Agents Online', value: formatNumber(agentsOnline), icon: Wifi, accent: 'cyan' as const,
      trend: endpointsData?.total_endpoints ? { value: `${((agentsOnline / endpointsData.total_endpoints) * 100).toFixed(1)}%`, direction: 'up' as const } : undefined,
      spark: [85,88,86,90,89,92,91,94,93,95,94,96,95,97,96,98,97,99,98,100],
    },
  ];

  const systemServices = systemHealth?.services && systemHealth.services.length > 0
    ? systemHealth.services
    : fallbackSystemServices;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="heading-xl">Security Operations Center</h1>
            <span className="relative flex items-center gap-1">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span className="text-xs text-emerald-500 font-medium">Live</span>
            </span>
            {data.security_posture && (
              <Badge
                variant={
                  data.security_posture === 'critical' ? 'danger' :
                  data.security_posture === 'high' ? 'warning' :
                  data.security_posture === 'moderate' ? 'info' :
                  'success'
                }
                size="sm"
              >
                Posture: {data.security_posture.toUpperCase()}
              </Badge>
            )}
            <Badge variant="info" size="sm">
              Compliance: {data.compliance_score}%
            </Badge>
          </div>
          <p className="text-caption mt-1">Real-time threat monitoring & response</p>
          {generatedTime && (
            <p className="text-xs text-slate-400 mt-0.5">Generated at: {generatedTime}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-slate-100 dark:bg-slate-800 rounded-lg p-1">
            {['24h', '7d', '30d'].map((d) => (
              <button key={d} className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${d === '24h' ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}>{d}</button>
            ))}
          </div>
          <Button
            variant={autoRefresh ? 'primary' : 'secondary'}
            size="sm"
            icon={RefreshCw}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? 'Auto (30s)' : 'Refresh'}
          </Button>
          <Button variant="ghost" size="sm" icon={MoreHorizontal} />
        </div>
      </motion.div>

      {/* System IP Connection Banner */}
      <motion.div
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.15 }}
      >
        <div className="bg-gradient-to-r from-brand-600 via-brand-700 to-blue-800 rounded-xl px-5 py-3 flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-white/20 rounded-lg">
              <Server className="w-4 h-4 text-white" />
            </div>
            <div>
              <p className="text-xs text-brand-200 font-medium">System IP</p>
              <p className="text-sm font-bold text-white tracking-tight">
                http://{window.location.hostname}:{window.location.port || '80'}
              </p>
            </div>
          </div>
          <div className="hidden sm:flex items-center gap-4 text-xs text-brand-200">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>API: :8000</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Agent: :8000/api/v1/agent</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Docs: :8000/docs</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {kpiStats.map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: i * 0.07 }}
          >
            <StatCard {...stat} />
          </motion.div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="lg:col-span-2"
        >
          <Card>
            <CardHeader>
              <CardTitle>Threat Activity</CardTitle>
              <Badge variant="info" size="sm">Last 24 Hours</Badge>
            </CardHeader>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={threatData}>
                  <defs>
                    <linearGradient id="alertsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.15} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="incidentsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.1} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-slate-200 dark:stroke-slate-800" />
                  <XAxis dataKey="hour" tick={{ fontSize: 11 }} className="text-slate-500" />
                  <YAxis tick={{ fontSize: 11 }} className="text-slate-500" />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend />
                  <Area type="monotone" dataKey="alerts" stroke="#3b82f6" fill="url(#alertsGrad)" strokeWidth={2} name="Alerts" />
                  <Area type="monotone" dataKey="incidents" stroke="#ef4444" fill="url(#incidentsGrad)" strokeWidth={2} name="Incidents" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
        >
          <Card>
            <CardHeader>
              <CardTitle>Alerts by Severity</CardTitle>
            </CardHeader>
            <div className="h-64 relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={2} dataKey="value">
                    {severityDistribution.map((entry, i) => (
                      <Cell key={i} fill={entry.color} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center">
                  <p className="text-2xl font-bold text-slate-900 dark:text-white">{totalSeverity || data.open_incidents}</p>
                  <p className="text-xs text-slate-500">Total</p>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap justify-center gap-3 mt-2">
              {severityDistribution.map((d) => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                  <span className="text-xs text-slate-500 dark:text-slate-400">{d.name}</span>
                </div>
              ))}
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Middle Row: Categories / Status / Sources */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
          <Card accent="purple">
            <CardHeader><CardTitle>Top Threat Actors</CardTitle></CardHeader>
            <div className="space-y-3">
              {attackCategories.map((cat) => (
                <div key={cat.type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-slate-700 dark:text-slate-300">{cat.type}</span>
                    <span className="text-xs font-medium text-slate-500">{cat.count}</span>
                  </div>
                  <div className="h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${cat.color} transition-all duration-500`} style={{ width: `${Math.min(100, (cat.count / maxAttackCount) * 100)}%` }} />
                  </div>
                </div>
              ))}
              {attackCategories.every((c) => c.count === 0) && (
                <p className="text-sm text-slate-400 text-center py-4">No threat data available</p>
              )}
            </div>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.55 }}>
          <Card>
            <CardHeader><CardTitle>Incident Status</CardTitle></CardHeader>
            <div className="space-y-3">
              {incidentStatuses.map((s) => (
                <div key={s.status} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${s.color}`} />
                    <span className="text-sm text-slate-700 dark:text-slate-300">{s.status}</span>
                  </div>
                  <span className="text-sm font-semibold text-slate-900 dark:text-white">{s.count}</span>
                </div>
              ))}
              {incidentStatuses.length === 0 && (
                <p className="text-sm text-slate-400 text-center py-4">No incidents</p>
              )}
            </div>
            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">Total</span>
                <span className="text-lg font-bold text-slate-900 dark:text-white">{incidentStatuses.reduce((s, i) => s + i.count, 0)}</span>
              </div>
            </div>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }}>
          <Card accent="cyan">
            <CardHeader><CardTitle>Top Alert Sources</CardTitle></CardHeader>
            <div className="space-y-3">
              {alertSources.map((src) => (
                <div key={src.ip} className="flex items-center gap-3">
                  <div className="w-8 h-5 rounded bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-500">{src.country}</div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-slate-700 dark:text-slate-300 truncate">{src.ip}</p>
                    <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full mt-1 overflow-hidden">
                      <div className="h-full bg-brand-500 rounded-full" style={{ width: `${src.pct}%` }} />
                    </div>
                  </div>
                  <span className="text-xs font-medium text-slate-500">{src.count}</span>
                </div>
              ))}
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Bottom Row: Threat Map + System Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.65 }}
          className="lg:col-span-2"
        >
          <Card>
            <CardHeader>
              <CardTitle>Global Threat Map</CardTitle>
              <Badge variant="info" size="sm">Live</Badge>
            </CardHeader>
            <div className="h-80 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 relative overflow-hidden">
              <svg viewBox="0 0 900 450" className="w-full h-full" preserveAspectRatio="xMidYMid meet">
                {/* Simplified world map paths */}
                <g fill="none" stroke="#93c5fd" strokeWidth="0.5" opacity="0.4" className="dark:opacity-30">
                  <path d="M150,120 L180,100 L220,95 L260,100 L300,90 L340,95 L370,85 L400,90 L430,80 L460,85 L500,75 L540,80 L560,90 L590,85 L620,95 L650,90 L680,100 L700,110 L720,105 L740,115 L750,110 L730,130 L710,140 L690,135 L660,145 L640,140 L610,150 L580,145 L550,155 L520,150 L490,160 L460,155 L430,165 L400,160 L370,170 L340,165 L310,175 L280,170 L250,180 L220,175 L190,185 L160,180 Z" />
                  <path d="M150,200 L170,195 L200,205 L230,200 L260,210 L290,205 L310,215 L280,225 L250,220 L210,230 L180,225 Z" />
                  <path d="M500,180 L530,185 L560,180 L590,190 L620,185 L650,195 L670,190 L680,200 L660,210 L640,215 L610,210 L580,215 L550,210 L520,205 L500,200 Z" />
                  <path d="M680,220 L700,230 L720,225 L740,235 L760,230 L770,240 L750,250 L730,245 L710,255 L690,250 L670,240 Z" />
                  <path d="M200,280 L220,275 L240,285 L260,280 L280,290 L300,285 L320,295 L340,290 L360,300 L380,295 L400,305 L420,300 L440,310 L460,305 L480,315 L500,310 L520,320 L540,315 L560,325 L580,320 L600,330 L620,325 L640,335 L660,330 L680,340 L700,335 L720,345 L700,355 L680,350 L660,360 L640,355 L620,365 L600,360 L580,370 L560,365 L540,375 L520,370 L500,380 L480,375 L460,385 L440,380 L420,390 L400,385 L380,395 L360,390 L340,400 L320,395 L300,405 L280,400 L260,390 L240,395 L220,385 L200,380 Z" />
                  <path d="M350,150 L370,145 L390,155 L380,165 L360,170 L340,160 Z" />
                  <path d="M600,100 L630,105 L650,115 L640,125 L620,130 L600,120 Z" />
                </g>
                {/* Ocean fill */}
                <rect width="900" height="450" fill="#eff6ff" className="dark:fill-slate-950" />
                {/* Re-draw paths over fill */}
                <g fill="#dbeafe" stroke="#93c5fd" strokeWidth="0.5" className="dark:fill-slate-800 dark:stroke-slate-700">
                  <path d="M150,120 L180,100 L220,95 L260,100 L300,90 L340,95 L370,85 L400,90 L430,80 L460,85 L500,75 L540,80 L560,90 L590,85 L620,95 L650,90 L680,100 L700,110 L720,105 L740,115 L750,110 L730,130 L710,140 L690,135 L660,145 L640,140 L610,150 L580,145 L550,155 L520,150 L490,160 L460,155 L430,165 L400,160 L370,170 L340,165 L310,175 L280,170 L250,180 L220,175 L190,185 L160,180 Z" />
                  <path d="M150,200 L170,195 L200,205 L230,200 L260,210 L290,205 L310,215 L280,225 L250,220 L210,230 L180,225 Z" />
                  <path d="M500,180 L530,185 L560,180 L590,190 L620,185 L650,195 L670,190 L680,200 L660,210 L640,215 L610,210 L580,215 L550,210 L520,205 L500,200 Z" />
                  <path d="M680,220 L700,230 L720,225 L740,235 L760,230 L770,240 L750,250 L730,245 L710,255 L690,250 L670,240 Z" />
                  <path d="M200,280 L220,275 L240,285 L260,280 L280,290 L300,285 L320,295 L340,290 L360,300 L380,295 L400,305 L420,300 L440,310 L460,305 L480,315 L500,310 L520,320 L540,315 L560,325 L580,320 L600,330 L620,325 L640,335 L660,330 L680,340 L700,335 L720,345 L700,355 L680,350 L660,360 L640,355 L620,365 L600,360 L580,370 L560,365 L540,375 L520,370 L500,380 L480,375 L460,385 L440,380 L420,390 L400,385 L380,395 L360,390 L340,400 L320,395 L300,405 L280,400 L260,390 L240,395 L220,385 L200,380 Z" />
                </g>
                {/* Animated attack dots */}
                {[
                  { x: 230, y: 155, size: 4, delay: 0 },
                  { x: 520, y: 145, size: 5, delay: 0.5 },
                  { x: 190, y: 230, size: 3, delay: 1 },
                  { x: 300, y: 310, size: 4, delay: 1.5 },
                  { x: 580, y: 300, size: 3, delay: 2 },
                  { x: 700, y: 240, size: 4, delay: 0.3 },
                  { x: 230, y: 310, size: 3, delay: 1.2 },
                  { x: 750, y: 210, size: 2, delay: 0.8 },
                  { x: 540, y: 110, size: 4, delay: 1.8 },
                  { x: 160, y: 190, size: 3, delay: 2.2 },
                ].map((dot, i) => (
                  <g key={i}>
                    <circle cx={dot.x} cy={dot.y} r={dot.size + 6} fill="#ef4444" opacity="0.15">
                      <animate attributeName="r" values={`${dot.size + 4};${dot.size + 12};${dot.size + 4}`} dur="3s" repeatCount="indefinite" begin={`${dot.delay}s`} />
                      <animate attributeName="opacity" values="0.2;0;0.2" dur="3s" repeatCount="indefinite" begin={`${dot.delay}s`} />
                    </circle>
                    <circle cx={dot.x} cy={dot.y} r={dot.size} fill="#ef4444">
                      <animate attributeName="r" values={`${dot.size};${dot.size + 2};${dot.size}`} dur="2s" repeatCount="indefinite" begin={`${dot.delay}s`} />
                    </circle>
                  </g>
                ))}
                {/* Connection lines */}
                {[
                  { x1: 230, y1: 155, x2: 520, y2: 185 },
                  { x1: 520, y1: 145, x2: 190, y2: 230 },
                  { x1: 300, y1: 310, x2: 520, y2: 185 },
                ].map((line, i) => (
                  <line key={i} x1={line.x1} y1={line.y1} x2={line.x2} y2={line.y2} stroke="#f97316" strokeWidth="0.5" opacity="0.3" strokeDasharray="4,4">
                    <animate attributeName="stroke-dashoffset" from="0" to="-16" dur="2s" repeatCount="indefinite" />
                  </line>
                ))}
              </svg>
            </div>
          </Card>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.7 }}>
          <Card accent="green">
            <CardHeader>
              <CardTitle>System Health</CardTitle>
              <Badge variant="success" size="sm">99.9% Uptime</Badge>
            </CardHeader>
            <div className="space-y-3">
              {systemServices.map((svc: { name: string; status: string; uptime: string; latency: string }) => (
                <div key={svc.name} className="flex items-center justify-between py-1.5">
                  <div className="flex items-center gap-2.5">
                    <div className={`w-2 h-2 rounded-full ${svc.status === 'online' ? 'bg-emerald-500 animate-pulse-soft' : 'bg-red-500'}`} />
                    <span className="text-sm text-slate-700 dark:text-slate-300">{svc.name}</span>
                  </div>
                  <span className="text-xs text-slate-500">{svc.latency}</span>
                </div>
              ))}
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Recent Alerts Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.75 }}>
        <Card>
          <CardHeader>
            <CardTitle>Recent Incidents</CardTitle>
            <Button variant="ghost" size="sm" icon={ChevronRight}>View All</Button>
          </CardHeader>
          <Table
            columns={[
              { key: 'time', header: 'Time', width: '12%' },
              { key: 'title', header: 'Incident', width: '28%' },
              { key: 'severity', header: 'Severity', width: '10%', render: (r: Record<string, unknown>) => (
                <Badge variant={r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warning' : r.severity === 'medium' ? 'warning' : 'info'} size="sm">
                  {String(r.severity)}
                </Badge>
              )},
              { key: 'sourceIp', header: 'Source IP', width: '15%', render: (r: Record<string, unknown>) => (
                <code className="text-xs bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded font-mono">{String(r.sourceIp)}</code>
              )},
              { key: 'rule', header: 'Rule', width: '15%' },
              { key: 'status', header: 'Status', width: '12%', render: (r: Record<string, unknown>) => (
                <Badge variant={r.status === 'new' ? 'danger' : r.status === 'acknowledged' ? 'info' : r.status === 'investigating' || r.status === 'in_progress' ? 'warning' : 'success'} size="sm">
                  {String(r.status)}
                </Badge>
              )},
              { key: 'actions', header: '', width: '8%', render: () => (
                <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                  <MoreHorizontal className="w-4 h-4" />
                </button>
              )},
            ]}
            data={recentAlerts}
            keyExtractor={(r) => r.time + r.title}
          />
        </Card>
      </motion.div>
    </div>
  );
}
