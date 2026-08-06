import { useState, useEffect, useCallback } from "react";
import {
  Activity, Shield, Users, Clock, AlertTriangle, AlertCircle,
  Bell, Radio, Server, CheckCircle, XCircle, ArrowUp, ArrowDown,
  Monitor, Wifi, Globe, Zap, RefreshCw, TrendingUp, TrendingDown,
  BarChart3, List, Timer,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Loading } from "@/components/ui/Loading";
import { StatCard } from "@/components/dashboards/StatCard";
import { api } from "@/services/api";

interface SOCDashboardData {
  alerts_today: number;
  active_incidents: number;
  incidents_requiring_attention: number;
  analyst_workload: Array<{ assignee_name: string; incident_count: number }>;
  sla_compliance: Record<string, number>;
  mean_time_to_resolve_minutes: number | null;
  alerts_by_severity: Record<string, number>;
  alert_timeline: Array<{ hour: number; count: number }>;
  unassigned_alerts: number;
}

interface LiveStats {
  active_alerts: number;
  active_incidents: number;
  events_per_second: number;
  active_users: number;
  active_threats: number;
  system_load: number;
}

const severityVariant: Record<string, "danger" | "warning" | "info" | "default" | "success"> = {
  critical: "danger",
  high: "warning",
  medium: "warning",
  low: "info",
  info: "default",
};

const severityDotColor: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-slate-400",
};

const maxBars = 12;

export function SOCDashboard() {
  const [socData, setSocData] = useState<SOCDashboardData | null>(null);
  const [socLoading, setSocLoading] = useState(true);
  const [socError, setSocError] = useState<string | null>(null);

  const [liveStats, setLiveStats] = useState<LiveStats>({
    active_alerts: 0, active_incidents: 0, events_per_second: 0,
    active_users: 0, active_threats: 0, system_load: 0,
  });
  const [liveConnected, setLiveConnected] = useState(true);

  const fetchAllData = useCallback(() => {
    setSocLoading(true);
    setSocError(null);
    api.get<SOCDashboardData>("/dashboards/soc")
      .then((res) => {
        setSocData(res);
      })
      .catch((err) => {
        setSocError(err?.error?.message || "Failed to load SOC data");
      })
      .finally(() => setSocLoading(false));
  }, []);

  const fetchLiveStats = useCallback(() => {
    api.get<LiveStats>("/dashboards/live/stats")
      .then((res) => setLiveStats(res))
      .catch(() => setLiveConnected(false));
  }, []);

  useEffect(() => {
    fetchAllData();
    fetchLiveStats();
  }, [fetchAllData, fetchLiveStats]);

  useEffect(() => {
    const interval = setInterval(fetchLiveStats, 30000);
    return () => clearInterval(interval);
  }, [fetchLiveStats]);

  const workload = socData?.analyst_workload || [];
  const maxWorkload = Math.max(1, ...workload.map((w) => w.incident_count));
  const alertTimeline = socData?.alert_timeline || [];
  const displayBars = alertTimeline.slice(-maxBars);
  const maxVolume = Math.max(1, ...alertTimeline.map((b) => b.count));
  const totalAlerts = socData?.alerts_by_severity ? Object.values(socData.alerts_by_severity).reduce((a, b) => a + b, 0) : 0;

  const slaValues = socData?.sla_compliance ? Object.values(socData.sla_compliance) : [];
  const avgSla = slaValues.length > 0 ? Math.round(slaValues.reduce((a, b) => a + b, 0) / slaValues.length) : 0;

  const formatResponseTime = (minutes: number | null): string => {
    if (minutes === null || minutes === undefined) return "N/A";
    if (minutes < 60) return Math.round(minutes) + "m";
    return Math.round(minutes / 60) + "h";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-slate-900">SOC Operations Center</h1>
            <div className="flex items-center gap-1.5">
              <span className={"relative flex h-2.5 w-2.5"}>
                <span className={"animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 " + (liveConnected ? "bg-emerald-400" : "bg-red-400")} />
                <span className={"relative inline-flex rounded-full h-2.5 w-2.5 " + (liveConnected ? "bg-emerald-500" : "bg-red-500")} />
              </span>
              <span className={"text-xs font-medium " + (liveConnected ? "text-emerald-600" : "text-red-500")}>
                {liveConnected ? "Live" : "Disconnected"}
              </span>
            </div>
          </div>
          <p className="text-sm text-slate-500 mt-1">Real-time security operations monitoring</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => { fetchAllData(); fetchLiveStats(); }}>
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Alerts"
          value={String(socData?.alerts_today ?? 0)}
          icon={Bell}
        />
        <StatCard
          label="Open Incidents"
          value={String(socData?.active_incidents ?? 0)}
          icon={Shield}
        />
        <StatCard
          label="Needs Attention"
          value={String(socData?.incidents_requiring_attention ?? 0)}
          icon={AlertTriangle}
        />
        <StatCard
          label="Avg Response Time"
          value={formatResponseTime(socData?.mean_time_to_resolve_minutes ?? null)}
          icon={Clock}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Live Alerts" value={String(liveStats.active_alerts)} icon={Zap} />
        <StatCard label="Live Incidents" value={String(liveStats.active_incidents)} icon={AlertCircle} />
        <StatCard label="EPS" value={String(liveStats.events_per_second.toFixed(1))} icon={Activity} />
        <StatCard label="System Load" value={liveStats.system_load.toFixed(1) + "%"} icon={Server} />
      </div>

      {socError && (
        <div className="flex flex-col items-center justify-center py-8 gap-2">
          <AlertCircle className="w-8 h-8 text-red-400" />
          <p className="text-red-600 font-medium text-sm">{socError}</p>
          <Button variant="secondary" size="sm" onClick={fetchAllData}>Retry</Button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Alert Volume (Last 24h)</CardTitle>
            <Badge variant="info" size="sm">Hourly</Badge>
          </CardHeader>
          {socLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading chart data..." />
            </div>
          ) : alertTimeline.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <BarChart3 className="w-10 h-10 text-slate-300" />
              <p className="text-sm text-slate-400">No alert data available</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-end gap-1.5 h-40">
                {displayBars.map((bucket, idx) => (
                  <div
                    key={idx}
                    className="flex-1 flex flex-col items-center gap-1 min-w-[20px]"
                    title={`${String(bucket.hour).padStart(2, '0')}:00: ${bucket.count} alerts`}
                  >
                    <div className="w-full flex flex-col justify-end" style={{ height: "140px" }}>
                      <div
                        className="w-full rounded-t bg-brand-500 hover:bg-brand-600 transition-colors cursor-pointer"
                        style={{ height: Math.max(4, (bucket.count / maxVolume) * 140) + "px" }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 font-medium">
                      {String(bucket.hour).padStart(2, '0')}h
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between text-xs text-slate-400 pt-1 border-t border-slate-100">
                <span>24h ago</span>
                <span>Now</span>
              </div>
            </div>
          )}
        </Card>

        <Card padding="none">
          <CardHeader className="px-4 py-3 border-b border-slate-100">
            <CardTitle>Unassigned Alerts</CardTitle>
            <Badge variant="warning" size="sm">{socData?.unassigned_alerts ?? 0} pending</Badge>
          </CardHeader>
          {socLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading..." />
            </div>
          ) : (socData?.unassigned_alerts ?? 0) === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <CheckCircle className="w-10 h-10 text-emerald-300" />
              <p className="text-sm text-slate-400">All alerts triaged</p>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <AlertTriangle className="w-10 h-10 text-amber-300" />
              <p className="text-sm text-slate-500">{socData?.unassigned_alerts} alerts need attention</p>
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Analyst Workload</CardTitle>
            <span className="text-xs text-slate-400">{workload.length} analysts</span>
          </CardHeader>
          {socLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading workload..." />
            </div>
          ) : workload.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <Users className="w-10 h-10 text-slate-300" />
              <p className="text-sm text-slate-400">No analyst data available</p>
            </div>
          ) : (
            <div className="space-y-3">
              {workload.map((analyst) => (
                <div key={analyst.assignee_name} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-brand-100 flex items-center justify-center text-brand-700 font-semibold text-[10px]">
                        {analyst.assignee_name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2)}
                      </div>
                      <span className="text-sm font-medium text-slate-700">{analyst.assignee_name}</span>
                    </div>
                    <span className="text-xs text-slate-500">{analyst.incident_count} incidents</span>
                  </div>
                  <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-brand-500 transition-all"
                      style={{ width: (analyst.incident_count / maxWorkload) * 100 + "%" }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card padding="none">
          <CardHeader className="px-4 py-3 border-b border-slate-100">
            <div className="flex items-center justify-between w-full">
              <CardTitle>SLA Compliance</CardTitle>
              <Badge variant={avgSla >= 90 ? "success" : avgSla >= 70 ? "warning" : "danger"} size="sm">
                {avgSla}%
              </Badge>
            </div>
          </CardHeader>
          {socLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading SLA data..." />
            </div>
          ) : slaValues.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <CheckCircle className="w-10 h-10 text-slate-300" />
              <p className="text-sm text-slate-400">No SLA data available</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto">
              {Object.entries(socData?.sla_compliance || {}).map(([priority, score]) => (
                <div key={priority} className="flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className={"w-2 h-2 rounded-full " + (score >= 90 ? "bg-emerald-500" : score >= 70 ? "bg-amber-500" : "bg-red-500")} />
                    <span className="text-sm font-medium text-slate-700 uppercase">{priority}</span>
                  </div>
                  <Badge variant={score >= 90 ? "success" : score >= 70 ? "warning" : "danger"} size="sm">
                    {score}%
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card padding="none">
        <CardHeader className="px-4 py-3 border-b border-slate-100">
          <CardTitle>Alert Severity Distribution</CardTitle>
          <span className="text-xs text-slate-400">{totalAlerts} total alerts</span>
        </CardHeader>
        {socLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loading size="md" />
          </div>
        ) : totalAlerts === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-2">
            <Shield className="w-10 h-10 text-emerald-300" />
            <p className="text-sm text-slate-400">No alerts recorded</p>
          </div>
        ) : (
          <div className="p-4">
            <div className="flex items-center gap-2 h-6 rounded-full overflow-hidden bg-slate-100">
              {Object.entries(socData?.alerts_by_severity || {}).map(([severity, count]) => {
                const colors: Record<string, string> = {
                  critical: "bg-red-500", high: "bg-orange-500",
                  medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-slate-300",
                };
                return (
                  <div
                    key={severity}
                    className={`h-full ${colors[severity] || "bg-slate-400"}`}
                    style={{ width: (count / totalAlerts) * 100 + "%" }}
                    title={`${severity}: ${count}`}
                  />
                );
              })}
            </div>
            <div className="flex flex-wrap gap-3 mt-3">
              {Object.entries(socData?.alerts_by_severity || {}).map(([severity, count]) => (
                <div key={severity} className="flex items-center gap-1.5">
                  <span className={`w-2.5 h-2.5 rounded-full ${severityDotColor[severity] || "bg-slate-400"}`} />
                  <span className="text-xs text-slate-500 capitalize">{severity}</span>
                  <span className="text-xs font-medium text-slate-700">{count}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
