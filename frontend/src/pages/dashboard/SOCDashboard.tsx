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

interface SOCStats {
  active_alerts: number;
  open_incidents: number;
  agents_online: number;
  total_agents: number;
  avg_response_time: string;
  response_time_trend: "up" | "down";
  alerts_change: number;
  incidents_change: number;
}

interface AlertBucket {
  hour: string;
  count: number;
  severity: string;
}

interface IncidentQueueItem {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: string;
  age_minutes: number;
  sla_deadline?: string;
}

interface AnalystWorkload {
  analyst_name: string;
  incident_count: number;
  open_count: number;
  avatar_initials: string;
}

interface SLATracking {
  id: string;
  title: string;
  severity: string;
  sla_type: string;
  deadline: string;
  remaining_minutes: number;
  breached: boolean;
}

interface AuditEvent {
  id: string;
  user_name: string;
  action: string;
  resource_type: string;
  details: string;
  severity: string;
  created_at: string;
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

const severityBorderColor: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
};

const maxBars = 12;

export function SOCDashboard() {
  const [stats, setStats] = useState<SOCStats>({
    active_alerts: 0, open_incidents: 0, agents_online: 0, total_agents: 0,
    avg_response_time: "0m", response_time_trend: "down", alerts_change: 0, incidents_change: 0,
  });
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);

  const [alertVolume, setAlertVolume] = useState<AlertBucket[]>([]);
  const [volumeLoading, setVolumeLoading] = useState(true);

  const [incidentQueue, setIncidentQueue] = useState<IncidentQueueItem[]>([]);
  const [queueLoading, setQueueLoading] = useState(true);

  const [workload, setWorkload] = useState<AnalystWorkload[]>([]);
  const [workloadLoading, setWorkloadLoading] = useState(true);

  const [slaItems, setSLAItems] = useState<SLATracking[]>([]);
  const [slaLoading, setSLALoading] = useState(true);

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(true);

  const [liveConnected, setLiveConnected] = useState(true);

  const fetchSocData = useCallback(() => {
    setStatsLoading(true);
    setStatsError(null);
    api.get<SOCStats>("/dashboards/live/stats")
      .then((res) => setStats(res))
      .catch((err) => setStatsError(err?.error?.message || "Failed to load stats"))
      .finally(() => setStatsLoading(false));
  }, []);

  const fetchAllData = useCallback(() => {
    fetchSocData();

    setVolumeLoading(true);
    api.get<AlertBucket[]>("/dashboards/soc/alert-volume")
      .then((res) => setAlertVolume(res))
      .catch(() => {})
      .finally(() => setVolumeLoading(false));

    setQueueLoading(true);
    api.get<IncidentQueueItem[]>("/dashboards/soc/incident-queue")
      .then((res) => setIncidentQueue(res))
      .catch(() => {})
      .finally(() => setQueueLoading(false));

    setWorkloadLoading(true);
    api.get<AnalystWorkload[]>("/dashboards/soc/analyst-workload")
      .then((res) => setWorkload(res))
      .catch(() => {})
      .finally(() => setWorkloadLoading(false));

    setSLALoading(true);
    api.get<SLATracking[]>("/dashboards/soc/sla-tracking")
      .then((res) => setSLAItems(res))
      .catch(() => {})
      .finally(() => setSLALoading(false));

    setAuditLoading(true);
    api.get<AuditEvent[]>("/dashboards/soc/activity")
      .then((res) => setAuditEvents(res))
      .catch(() => {})
      .finally(() => setAuditLoading(false));
  }, [fetchSocData]);

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchSocData, 30000);
    return () => clearInterval(interval);
  }, [fetchAllData, fetchSocData]);

  useEffect(() => {
    if (liveConnected) {
      const interval = setInterval(() => {
        api.get<SOCStats>("/dashboards/live/stats")
          .then((res) => setStats(res))
          .catch(() => setLiveConnected(false));
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [liveConnected]);

  const maxVolume = Math.max(1, ...alertVolume.map((b) => b.count));
  const displayBars = alertVolume.slice(-maxBars);

  const breachedCount = slaItems.filter((s) => s.breached).length;
  const warningCount = slaItems.filter((s) => !s.breached && s.remaining_minutes < 30).length;

  const formatAge = (minutes: number): string => {
    if (minutes < 60) return minutes + "m ago";
    if (minutes < 1440) return Math.floor(minutes / 60) + "h ago";
    return Math.floor(minutes / 1440) + "d ago";
  };

  const formatSLA = (minutes: number): string => {
    if (minutes < 0) return "Overdue " + Math.abs(minutes) + "m";
    if (minutes < 60) return minutes + "m left";
    return Math.floor(minutes / 60) + "h " + (minutes % 60) + "m left";
  };

  const maxWorkload = Math.max(1, ...workload.map((w) => w.incident_count));

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
          <p className="text-sm text-slate-500 mt-1">
            Real-time security operations monitoring
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={fetchAllData}>
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Alerts"
          value={String(stats.active_alerts)}
          icon={Bell}
          trend={stats.alerts_change !== 0 ? { value: (stats.alerts_change > 0 ? "+" : "") + stats.alerts_change, direction: stats.alerts_change > 0 ? "up" : "down" } : undefined}
        />
        <StatCard
          label="Open Incidents"
          value={String(stats.open_incidents)}
          icon={Shield}
          trend={stats.incidents_change !== 0 ? { value: (stats.incidents_change > 0 ? "+" : "") + stats.incidents_change, direction: stats.incidents_change > 0 ? "up" : "down" } : undefined}
        />
        <StatCard
          label="Agents Online"
          value={stats.agents_online + "/" + stats.total_agents}
          icon={Radio}
        />
        <StatCard
          label="Avg Response Time"
          value={stats.avg_response_time}
          icon={Clock}
          trend={stats.response_time_trend ? { value: stats.response_time_trend === "up" ? "Slower" : "Faster", direction: stats.response_time_trend === "up" ? "up" : "down" } : undefined}
        />
      </div>

      {statsError && (
        <div className="flex flex-col items-center justify-center py-8 gap-2">
          <AlertCircle className="w-8 h-8 text-red-400" />
          <p className="text-red-600 font-medium text-sm">{statsError}</p>
          <Button variant="secondary" size="sm" onClick={fetchAllData}>Retry</Button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Alert Volume (Last 24h)</CardTitle>
            <Badge variant="info" size="sm">Hourly</Badge>
          </CardHeader>
          {volumeLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading chart data..." />
            </div>
          ) : alertVolume.length === 0 ? (
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
                    title={bucket.hour + ": " + bucket.count + " alerts"}
                  >
                    <div className="w-full flex flex-col justify-end" style={{ height: "140px" }}>
                      <div
                        className="w-full rounded-t bg-brand-500 hover:bg-brand-600 transition-colors cursor-pointer"
                        style={{ height: Math.max(4, (bucket.count / maxVolume) * 140) + "px" }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 font-medium">
                      {bucket.hour.split(" ")[0]}
                    </span>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-between text-xs text-slate-400 pt-1 border-t border-slate-100">
                <span>{displayBars[0]?.hour || "..."}</span>
                <span>{displayBars[displayBars.length - 1]?.hour || "..."}</span>
              </div>
            </div>
          )}
        </Card>

        <Card padding="none">
          <CardHeader className="px-4 py-3 border-b border-slate-100">
            <CardTitle>Incident Queue</CardTitle>
            <Badge variant="warning" size="sm">{incidentQueue.length} unassigned</Badge>
          </CardHeader>
          {queueLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading queue..." />
            </div>
          ) : incidentQueue.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <CheckCircle className="w-10 h-10 text-emerald-300" />
              <p className="text-sm text-slate-400">All incidents assigned</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto">
              {incidentQueue.map((incident) => (
                <div
                  key={incident.id}
                  className={
                    "flex items-start gap-3 px-4 py-3 hover:bg-slate-50 transition-colors cursor-pointer border-l-4 border-l-transparent " +
                    (incident.sla_deadline ? severityBorderColor[incident.severity] || "" : "")
                  }
                >
                  <span className={"w-2 h-2 rounded-full mt-1.5 flex-shrink-0 " + (severityDotColor[incident.severity] || severityDotColor.info)} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-900 truncate">{incident.title}</p>
                    <p className="text-xs text-slate-400">INC-{incident.id.substring(0, 8).toUpperCase()}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge variant={severityVariant[incident.severity] || "default"} size="sm">
                      {incident.severity}
                    </Badge>
                    <span className="text-xs text-slate-400 w-14 text-right">{formatAge(incident.age_minutes)}</span>
                  </div>
                </div>
              ))}
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
          {workloadLoading ? (
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
                <div key={analyst.analyst_name} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-full bg-brand-100 flex items-center justify-center text-brand-700 font-semibold text-[10px]">
                        {analyst.avatar_initials || analyst.analyst_name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2)}
                      </div>
                      <span className="text-sm font-medium text-slate-700">{analyst.analyst_name}</span>
                    </div>
                    <span className="text-xs text-slate-500">
                      {analyst.open_count} open / {analyst.incident_count} total
                    </span>
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
              <CardTitle>SLA Tracking</CardTitle>
              <div className="flex items-center gap-2">
                {breachedCount > 0 && <Badge variant="danger" size="sm">{breachedCount} breached</Badge>}
                {warningCount > 0 && <Badge variant="warning" size="sm">{warningCount} warning</Badge>}
              </div>
            </div>
          </CardHeader>
          {slaLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loading size="md" text="Loading SLA data..." />
            </div>
          ) : slaItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2">
              <CheckCircle className="w-10 h-10 text-emerald-300" />
              <p className="text-sm text-slate-400">No items approaching SLA</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto">
              {slaItems.map((sla) => (
                <div key={sla.id} className="flex items-center justify-between px-4 py-3 hover:bg-slate-50 transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <Timer className={"w-4 h-4 flex-shrink-0 " + (sla.breached ? "text-red-500" : sla.remaining_minutes < 30 ? "text-amber-500" : "text-slate-400")} />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-slate-900 truncate">{sla.title}</p>
                      <div className="flex items-center gap-2">
                        <Badge variant={severityVariant[sla.severity] || "default"} size="sm">{sla.severity}</Badge>
                        <span className="text-xs text-slate-400">{sla.sla_type}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0 ml-3">
                    <p className={"text-xs font-medium " + (sla.breached ? "text-red-600" : sla.remaining_minutes < 30 ? "text-amber-600" : "text-slate-500")}>
                      {formatSLA(sla.remaining_minutes)}
                    </p>
                    <p className="text-[10px] text-slate-400 mt-0.5">
                      {new Date(sla.deadline).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card padding="none">
        <CardHeader className="px-4 py-3 border-b border-slate-100">
          <CardTitle>Recent Activity</CardTitle>
          <span className="text-xs text-slate-400">Last 10 events</span>
        </CardHeader>
        {auditLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loading size="md" text="Loading activity..." />
          </div>
        ) : auditEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-2">
            <Activity className="w-10 h-10 text-slate-300" />
            <p className="text-sm text-slate-400">No recent activity</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto">
            {auditEvents.map((event) => (
              <div key={event.id} className="flex items-start gap-3 px-4 py-3 hover:bg-slate-50 transition-colors">
                <div className="w-8 h-8 rounded-full bg-slate-100 flex items-center justify-center flex-shrink-0">
                  <Activity className="w-4 h-4 text-slate-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-slate-700">
                    <span className="font-medium text-slate-900">{event.user_name}</span>
                    {" "}{event.action}{" "}
                    <span className="text-slate-500">{event.resource_type}</span>
                  </p>
                  {event.details && (
                    <p className="text-xs text-slate-400 mt-0.5 truncate">{event.details}</p>
                  )}
                </div>
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  <span className="text-xs text-slate-400">
                    {new Date(event.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                  <Badge variant={severityVariant[event.severity] || "default"} size="sm">
                    {event.severity}
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
