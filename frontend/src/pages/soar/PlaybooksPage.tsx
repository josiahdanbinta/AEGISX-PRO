import { useState, useEffect, useCallback } from "react";
import {
  Play, Workflow, Plus, Zap, PlayCircle, PauseCircle,
  Activity, Clock, CheckCircle, XCircle, AlertTriangle,
  AlertCircle, ChevronDown, Filter, X, Edit2, Trash2,
  GitBranch, Settings, Webhook, Bell, Shield, Users, Server,
  MessageSquare, Router, Terminal, RefreshCw,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Loading } from "@/components/ui/Loading";
import { Modal } from "@/components/ui/Modal";
import { StatCard } from "@/components/dashboards/StatCard";
import { api } from "@/services/api";

interface PlaybookItem {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  status: string;
  steps_count: number;
  execution_count: number;
  success_rate: number;
  last_executed_at?: string;
  created_at: string;
}

interface PlaybookStep {
  id: string;
  order: number;
  name: string;
  action: string;
  condition?: string;
  status: string;
}

interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name: string;
  trigger_reason: string;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
}

interface PlaybookTemplate {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  steps_count: number;
}

interface Integration {
  id: string;
  name: string;
  type: string;
  status: string;
  connected_at?: string;
}

interface PlaybookStats {
  total_playbooks: number;
  active_playbooks: number;
  total_executions: number;
  success_rate: number;
}

const triggerBadgeVariant: Record<string, "danger" | "warning" | "info" | "success" | "default"> = {
  alert: "danger",
  incident: "warning",
  schedule: "info",
  manual: "default",
  webhook: "success",
};

const statusBadgeVariant: Record<string, "success" | "warning" | "danger" | "info" | "default"> = {
  active: "success",
  inactive: "default",
  draft: "warning",
  running: "info",
  completed: "success",
  failed: "danger",
};

const integrationIcons: Record<string, typeof Settings> = {
  jira: GitBranch,
  servicenow: Server,
  slack: MessageSquare,
  teams: Users,
  splunk: Activity,
  pagerduty: Bell,
  webhook: Webhook,
  custom: Settings,
};

const templatePlaybooks: PlaybookTemplate[] = [
  { id: "tpl-1", name: "Phishing Response", description: "Automated phishing alert triage, email analysis, and user notification", trigger_type: "alert", steps_count: 8 },
  { id: "tpl-2", name: "Malware Containment", description: "Isolate infected endpoint, collect forensic data, notify SOC", trigger_type: "alert", steps_count: 6 },
  { id: "tpl-3", name: "Brute Force Lockout", description: "Detect and block brute force attempts, create incident", trigger_type: "alert", steps_count: 5 },
  { id: "tpl-4", name: "Suspicious Login Investigation", description: "Investigate unusual login patterns and geo-anomalies", trigger_type: "alert", steps_count: 7 },
  { id: "tpl-5", name: "Data Exfiltration Response", description: "Detect large data transfers, block egress, notify DLP team", trigger_type: "alert", steps_count: 9 },
  { id: "tpl-6", name: "Ransomware Containment", description: "Immediate host isolation, snapshot creation, ransomware analysis", trigger_type: "incident", steps_count: 10 },
  { id: "tpl-7", name: "Vulnerability Remediation", description: "Automated patch deployment workflow with approval gates", trigger_type: "schedule", steps_count: 6 },
  { id: "tpl-8", name: "Compliance Audit Workflow", description: "Scheduled compliance check and evidence collection", trigger_type: "schedule", steps_count: 5 },
];

export function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<PlaybookItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<PlaybookStats>({ total_playbooks: 0, active_playbooks: 0, total_executions: 0, success_rate: 0 });

  const [selectedPlaybook, setSelectedPlaybook] = useState<PlaybookItem | null>(null);
  const [steps, setSteps] = useState<PlaybookStep[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [integrationsLoading, setIntegrationsLoading] = useState(true);

  const [showCreatePlaybook, setShowCreatePlaybook] = useState(false);
  const [showAddIntegration, setShowAddIntegration] = useState(false);

  const [newPlaybook, setNewPlaybook] = useState({ name: "", description: "", trigger_type: "alert" });
  const [newIntegration, setNewIntegration] = useState({ type: "slack", api_url: "", api_key: "", name: "" });
  const [createLoading, setCreateLoading] = useState(false);

  const fetchPlaybooks = useCallback(() => {
    setLoading(true);
    setError(null);
    api.get<PlaybookItem[]>("/soar/playbooks")
      .then((res) => setPlaybooks(res))
      .catch((err) => setError(err?.error?.message || "Failed to load playbooks"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchPlaybooks(); }, [fetchPlaybooks]);

  useEffect(() => {
    api.get<PlaybookStats>("/soar/playbooks/stats")
      .then((res) => setStats(res))
      .catch(() => {});
  }, []);

  useEffect(() => {
    setIntegrationsLoading(true);
    api.get<Integration[]>("/soar/integrations")
      .then((res) => setIntegrations(res))
      .catch(() => {})
      .finally(() => setIntegrationsLoading(false));
  }, []);

  const viewPlaybook = (pb: PlaybookItem) => {
    setSelectedPlaybook(pb);
    setDetailLoading(true);
    setDetailError(null);
    Promise.all([
      api.get<PlaybookStep[]>("/soar/playbooks/" + pb.id + "/steps"),
      api.get<PlaybookExecution[]>("/soar/playbooks/" + pb.id + "/executions"),
    ])
      .then(([stepsRes, execsRes]) => {
        setSteps(stepsRes);
        setExecutions(execsRes);
      })
      .catch((err) => setDetailError(err?.error?.message || "Failed to load playbook details"))
      .finally(() => setDetailLoading(false));
  };

  const executePlaybook = async (id: string) => {
    try {
      await api.post("/soar/playbooks/" + id + "/execute");
      fetchPlaybooks();
    } catch (_) {}
  };

  const togglePlaybookStatus = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === "active" ? "inactive" : "active";
    try {
      await api.patch("/soar/playbooks/" + id, { status: newStatus });
      fetchPlaybooks();
    } catch (_) {}
  };

  const createPlaybook = async () => {
    if (!newPlaybook.name) return;
    setCreateLoading(true);
    try {
      await api.post("/soar/playbooks", newPlaybook);
      setShowCreatePlaybook(false);
      setNewPlaybook({ name: "", description: "", trigger_type: "alert" });
      fetchPlaybooks();
    } catch (_) {}
    setCreateLoading(false);
  };

  const addIntegration = async () => {
    if (!newIntegration.name || !newIntegration.api_url) return;
    setCreateLoading(true);
    try {
      await api.post("/soar/integrations", newIntegration);
      setShowAddIntegration(false);
      setNewIntegration({ type: "slack", api_url: "", api_key: "", name: "" });
      setIntegrationsLoading(true);
      api.get<Integration[]>("/soar/integrations")
        .then((res) => setIntegrations(res))
        .catch(() => {})
        .finally(() => setIntegrationsLoading(false));
    } catch (_) {}
    setCreateLoading(false);
  };

  const useTemplate = async (template: PlaybookTemplate) => {
    setCreateLoading(true);
    try {
      await api.post("/soar/playbooks", {
        name: template.name,
        description: template.description,
        trigger_type: template.trigger_type,
        from_template: template.id,
      });
      fetchPlaybooks();
    } catch (_) {}
    setCreateLoading(false);
  };

  const removeIntegration = async (id: string) => {
    try {
      await api.delete("/soar/integrations/" + id);
      setIntegrations((prev) => prev.filter((i) => i.id !== id));
    } catch (_) {}
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">SOAR Playbooks</h1>
          <p className="text-sm text-slate-500 mt-1">
            {stats.active_playbooks} active playbook{stats.active_playbooks !== 1 ? "s" : ""} of {stats.total_playbooks} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          {selectedPlaybook && (
            <Button variant="secondary" size="md" onClick={() => setSelectedPlaybook(null)}>
              <Workflow className="w-4 h-4" />
              All Playbooks
            </Button>
          )}
          <Button size="md" onClick={() => setShowCreatePlaybook(true)}>
            <Plus className="w-4 h-4" />
            New Playbook
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Playbooks" value={String(stats.total_playbooks)} icon={Workflow} />
        <StatCard label="Active" value={String(stats.active_playbooks)} icon={PlayCircle} />
        <StatCard label="Total Executions" value={String(stats.total_executions)} icon={Activity} />
        <StatCard label="Success Rate" value={stats.success_rate + "%"} icon={CheckCircle} />
      </div>

      {!selectedPlaybook && (
        <>
          {error && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{error}</p>
              <Button variant="secondary" size="sm" onClick={fetchPlaybooks}>Retry</Button>
            </div>
          )}

          {loading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading playbooks..." />
            </div>
          )}

          {!loading && !error && playbooks.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Workflow className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No playbooks configured</p>
                <p className="text-sm text-slate-400">Create a playbook or use a template to get started</p>
                <Button variant="secondary" size="sm" onClick={() => setShowCreatePlaybook(true)}>
                  <Plus className="w-4 h-4" />
                  Create Playbook
                </Button>
              </div>
            </Card>
          )}

          {!loading && !error && playbooks.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {playbooks.map((pb) => (
                <Card key={pb.id} hover padding="md">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-brand-50">
                        <Play className="w-4 h-4 text-brand-600" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-slate-900">{pb.name}</h3>
                        <p className="text-xs text-slate-400">{pb.steps_count} step{pb.steps_count !== 1 ? "s" : ""}</p>
                      </div>
                    </div>
                    <Badge variant={statusBadgeVariant[pb.status] || "default"} size="sm">
                      {pb.status}
                    </Badge>
                  </div>
                  <p className="text-sm text-slate-500 mb-3 line-clamp-2">{pb.description || "No description"}</p>
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <Badge variant={triggerBadgeVariant[pb.trigger_type] || "default"} size="sm">
                      {pb.trigger_type}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-slate-500 mb-4">
                    <span className="flex items-center gap-1">
                      <Activity className="w-3 h-3" />
                      {pb.execution_count} runs
                    </span>
                    <span className="flex items-center gap-1">
                      <CheckCircle className="w-3 h-3 text-emerald-500" />
                      {pb.success_rate || 0}% success
                    </span>
                    {pb.last_executed_at && (
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(pb.last_executed_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 pt-3 border-t border-slate-100">
                    <Button variant="primary" size="sm" className="flex-1" onClick={() => executePlaybook(pb.id)}>
                      <PlayCircle className="w-3.5 h-3.5" />
                      Execute
                    </Button>
                    <Button variant="secondary" size="sm" onClick={() => viewPlaybook(pb)}>
                      <GitBranch className="w-3.5 h-3.5" />
                      Details
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => togglePlaybookStatus(pb.id, pb.status)} title={pb.status === "active" ? "Deactivate" : "Activate"}>
                      {pb.status === "active" ? <PauseCircle className="w-4 h-4" /> : <PlayCircle className="w-4 h-4" />}
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}

          <Card>
            <CardHeader>
              <CardTitle>Playbook Templates</CardTitle>
              <span className="text-xs text-slate-400">{templatePlaybooks.length} built-in templates</span>
            </CardHeader>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {templatePlaybooks.map((tpl) => (
                <div key={tpl.id} className="border border-slate-200 rounded-lg p-4 hover:border-brand-300 hover:shadow-sm transition-all">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="w-4 h-4 text-amber-500" />
                    <h4 className="font-medium text-sm text-slate-900">{tpl.name}</h4>
                  </div>
                  <p className="text-xs text-slate-500 mb-3 line-clamp-2">{tpl.description}</p>
                  <div className="flex items-center justify-between mb-3">
                    <Badge variant={triggerBadgeVariant[tpl.trigger_type] || "default"} size="sm">{tpl.trigger_type}</Badge>
                    <span className="text-xs text-slate-400">{tpl.steps_count} steps</span>
                  </div>
                  <Button variant="secondary" size="sm" className="w-full" onClick={() => useTemplate(tpl)} loading={createLoading}>
                    <Plus className="w-3.5 h-3.5" />
                    Use Template
                  </Button>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Integrations</CardTitle>
              <Button size="sm" onClick={() => setShowAddIntegration(true)}>
                <Plus className="w-4 h-4" />
                Add Integration
              </Button>
            </CardHeader>
            {integrationsLoading && (
              <div className="flex items-center justify-center py-12">
                <Loading size="sm" text="Loading integrations..." />
              </div>
            )}
            {!integrationsLoading && integrations.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8 gap-2">
                <Webhook className="w-8 h-8 text-slate-300" />
                <p className="text-sm text-slate-500">No integrations configured</p>
              </div>
            )}
            {!integrationsLoading && integrations.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {integrations.map((intg) => {
                  const Icon = integrationIcons[intg.type] || Settings;
                  return (
                    <div key={intg.id} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-slate-100">
                          <Icon className="w-4 h-4 text-slate-600" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-slate-900">{intg.name}</p>
                          <p className="text-xs text-slate-400 capitalize">{intg.type}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className={"w-2 h-2 rounded-full " + (intg.status === "connected" ? "bg-emerald-500" : "bg-red-400")} />
                        <button onClick={() => removeIntegration(intg.id)} className="p-1 rounded text-slate-400 hover:text-red-600 hover:bg-red-50 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </>
      )}

      {selectedPlaybook && (
        <div className="space-y-6">
          <Card>
            <div className="space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h2 className="text-xl font-bold text-slate-900">{selectedPlaybook.name}</h2>
                    <Badge variant={statusBadgeVariant[selectedPlaybook.status] || "default"} size="sm">{selectedPlaybook.status}</Badge>
                    <Badge variant={triggerBadgeVariant[selectedPlaybook.trigger_type] || "default"} size="sm">{selectedPlaybook.trigger_type}</Badge>
                  </div>
                  <p className="text-sm text-slate-500">{selectedPlaybook.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="primary" size="sm" onClick={() => executePlaybook(selectedPlaybook.id)}>
                    <PlayCircle className="w-4 h-4" />
                    Execute
                  </Button>
                  <Button variant="secondary" size="sm">
                    <Edit2 className="w-4 h-4" />
                    Edit
                  </Button>
                </div>
              </div>
              <div className="flex items-center gap-6 text-sm">
                <span className="flex items-center gap-1 text-slate-500">
                  <Activity className="w-4 h-4" />
                  {selectedPlaybook.execution_count} executions
                </span>
                <span className="flex items-center gap-1 text-slate-500">
                  <CheckCircle className="w-4 h-4 text-emerald-500" />
                  {selectedPlaybook.success_rate || 0}% success rate
                </span>
                {selectedPlaybook.last_executed_at && (
                  <span className="flex items-center gap-1 text-slate-400">
                    <Clock className="w-4 h-4" />
                    Last run: {new Date(selectedPlaybook.last_executed_at).toLocaleString()}
                  </span>
                )}
              </div>
            </div>
          </Card>

          {detailLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading playbook details..." />
            </div>
          )}

          {detailError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{detailError}</p>
              <Button variant="secondary" size="sm" onClick={() => viewPlaybook(selectedPlaybook)}>Retry</Button>
            </div>
          )}

          {!detailLoading && !detailError && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle>Steps</CardTitle>
                  <span className="text-xs text-slate-400">{steps.length} step{steps.length !== 1 ? "s" : ""}</span>
                </CardHeader>
                {steps.length === 0 ? (
                  <p className="text-sm text-slate-400 py-4">No steps defined</p>
                ) : (
                  <div className="space-y-2">
                    {steps.map((step) => (
                      <div key={step.id} className="flex items-start gap-4 p-3 rounded-lg border border-slate-100 hover:bg-slate-50 transition-colors">
                        <div className="w-7 h-7 rounded-full bg-brand-100 text-brand-700 flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5">
                          {step.order}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <p className="text-sm font-medium text-slate-900">{step.name}</p>
                            <Badge variant="info" size="sm">{step.action}</Badge>
                          </div>
                          {step.condition && (
                            <p className="text-xs text-slate-500 mt-0.5">
                              <span className="font-medium">Condition:</span> {step.condition}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card padding="none">
                <CardHeader className="px-4 py-3 border-b border-slate-100">
                  <CardTitle>Recent Executions</CardTitle>
                </CardHeader>
                {executions.length === 0 ? (
                  <div className="px-4 py-8 text-center text-sm text-slate-400">
                    No executions recorded
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50">
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Trigger</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Started</th>
                          <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Duration</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100">
                        {executions.map((exec) => (
                          <tr key={exec.id} className="hover:bg-slate-50 transition-colors">
                            <td className="px-4 py-3 text-sm text-slate-700">{exec.trigger_reason}</td>
                            <td className="px-4 py-3">
                              <Badge variant={statusBadgeVariant[exec.status] || "default"} size="sm">
                                {exec.status}
                              </Badge>
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-500">
                              {new Date(exec.started_at).toLocaleString()}
                            </td>
                            <td className="px-4 py-3 text-xs text-slate-500">
                              {exec.duration_ms ? (exec.duration_ms / 1000).toFixed(1) + "s" : "--"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </>
          )}
        </div>
      )}

      <Modal open={showCreatePlaybook} onClose={() => setShowCreatePlaybook(false)} title="Create Playbook" size="md">
        <div className="space-y-4">
          <Input label="Playbook Name" placeholder="e.g. Phishing Triage" value={newPlaybook.name} onChange={(e) => setNewPlaybook((p) => ({ ...p, name: e.target.value }))} />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Description</label>
            <textarea value={newPlaybook.description} onChange={(e) => setNewPlaybook((p) => ({ ...p, description: e.target.value }))} placeholder="Describe the playbook..." className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 resize-none" rows={3} />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Trigger Type</label>
            <select value={newPlaybook.trigger_type} onChange={(e) => setNewPlaybook((p) => ({ ...p, trigger_type: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              <option value="alert">Alert</option>
              <option value="incident">Incident</option>
              <option value="schedule">Schedule</option>
              <option value="manual">Manual</option>
              <option value="webhook">Webhook</option>
            </select>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowCreatePlaybook(false); setNewPlaybook({ name: "", description: "", trigger_type: "alert" }); }}>
              Cancel
            </Button>
            <Button onClick={createPlaybook} disabled={!newPlaybook.name} loading={createLoading}>
              <Plus className="w-4 h-4" />
              Create Playbook
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={showAddIntegration} onClose={() => setShowAddIntegration(false)} title="Add Integration" size="md">
        <div className="space-y-4">
          <Input label="Integration Name" placeholder="e.g. Production Jira" value={newIntegration.name} onChange={(e) => setNewIntegration((p) => ({ ...p, name: e.target.value }))} />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Type</label>
            <select value={newIntegration.type} onChange={(e) => setNewIntegration((p) => ({ ...p, type: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              <option value="slack">Slack</option>
              <option value="teams">Microsoft Teams</option>
              <option value="jira">Jira</option>
              <option value="servicenow">ServiceNow</option>
              <option value="splunk">Splunk</option>
              <option value="pagerduty">PagerDuty</option>
              <option value="webhook">Webhook</option>
              <option value="custom">Custom</option>
            </select>
          </div>
          <Input label="API URL" placeholder="https://..." value={newIntegration.api_url} onChange={(e) => setNewIntegration((p) => ({ ...p, api_url: e.target.value }))} />
          <Input label="API Key / Token" type="password" placeholder="Enter API key..." value={newIntegration.api_key} onChange={(e) => setNewIntegration((p) => ({ ...p, api_key: e.target.value }))} />
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowAddIntegration(false); setNewIntegration({ type: "slack", api_url: "", api_key: "", name: "" }); }}>Cancel</Button>
            <Button onClick={addIntegration} disabled={!newIntegration.name || !newIntegration.api_url} loading={createLoading}>
              <Plus className="w-4 h-4" />
              Add Integration
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
