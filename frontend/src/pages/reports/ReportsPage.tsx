import { useState, useEffect, useCallback } from "react";
import {
  FileText, Download, Plus, Calendar, Clock, Trash2, Edit2,
  BarChart3, Activity, AlertTriangle, AlertCircle, FileSpreadsheet,
  FileType, RotateCw, ChevronDown, Filter, X, CheckCircle, Copy,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Loading } from "@/components/ui/Loading";
import { Modal } from "@/components/ui/Modal";
import { StatCard } from "@/components/dashboards/StatCard";
import { api } from "@/services/api";

interface ReportItem {
  id: string;
  name: string;
  type: string;
  format: string;
  status: string;
  created_by: string;
  created_at: string;
  file_url?: string;
}

interface ScheduledReport {
  id: string;
  name: string;
  type: string;
  format: string;
  cron_expression: string;
  next_run?: string;
  last_run?: string;
  recipients: string[];
  enabled: boolean;
}

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: string;
  is_system: boolean;
  created_at: string;
}

interface QuickStats {
  reports_generated: number;
  scheduled_reports: number;
  templates_available: number;
}

type TabName = "generated" | "scheduled" | "templates";

const reportTypes = ["Executive", "Incident", "Asset", "Threat", "Vulnerability", "Compliance", "Audit"];
const reportFormats = ["PDF", "Excel", "CSV"];

const statusBadgeVariant: Record<string, "success" | "warning" | "danger" | "info" | "default"> = {
  completed: "success",
  pending: "warning",
  generating: "info",
  failed: "danger",
};

const formatIcon: Record<string, typeof FileText> = {
  pdf: FileType,
  excel: FileSpreadsheet,
  csv: FileText,
};

export function ReportsPage() {
  const [activeTab, setActiveTab] = useState<TabName>("generated");
  const [stats, setStats] = useState<QuickStats>({ reports_generated: 0, scheduled_reports: 0, templates_available: 0 });

  const [reports, setReports] = useState<ReportItem[]>([]);
  const [reportsLoading, setReportsLoading] = useState(true);
  const [reportsError, setReportsError] = useState<string | null>(null);

  const [scheduled, setScheduled] = useState<ScheduledReport[]>([]);
  const [scheduledLoading, setScheduledLoading] = useState(true);
  const [scheduledError, setScheduledError] = useState<string | null>(null);

  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [templatesError, setTemplatesError] = useState<string | null>(null);

  const [showCreateReport, setShowCreateReport] = useState(false);
  const [showCreateSchedule, setShowCreateSchedule] = useState(false);
  const [showCreateTemplate, setShowCreateTemplate] = useState(false);

  const [newReport, setNewReport] = useState({ name: "", type: "Executive", format: "PDF" });
  const [newSchedule, setNewSchedule] = useState({ name: "", type: "Executive", format: "PDF", cron_expression: "", recipients: "" });
  const [newTemplate, setNewTemplate] = useState({ name: "", description: "", type: "Executive" });

  useEffect(() => {
    api.get<QuickStats>("/reports/stats")
      .then((res) => setStats(res))
      .catch(() => {});
  }, []);

  const fetchReports = useCallback(() => {
    setReportsLoading(true);
    setReportsError(null);
    api.get<ReportItem[]>("/reports")
      .then((res) => setReports(res))
      .catch((err) => setReportsError(err?.error?.message || "Failed to load reports"))
      .finally(() => setReportsLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === "generated") fetchReports();
  }, [activeTab, fetchReports]);

  const fetchScheduled = useCallback(() => {
    setScheduledLoading(true);
    setScheduledError(null);
    api.get<ScheduledReport[]>("/reports/scheduled")
      .then((res) => setScheduled(res))
      .catch((err) => setScheduledError(err?.error?.message || "Failed to load scheduled reports"))
      .finally(() => setScheduledLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === "scheduled") fetchScheduled();
  }, [activeTab, fetchScheduled]);

  const fetchTemplates = useCallback(() => {
    setTemplatesLoading(true);
    setTemplatesError(null);
    api.get<ReportTemplate[]>("/reports/templates")
      .then((res) => setTemplates(res))
      .catch((err) => setTemplatesError(err?.error?.message || "Failed to load templates"))
      .finally(() => setTemplatesLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === "templates") fetchTemplates();
  }, [activeTab, fetchTemplates]);

  const createReport = async () => {
    if (!newReport.name) return;
    try {
      await api.post("/reports", newReport);
      setShowCreateReport(false);
      setNewReport({ name: "", type: "Executive", format: "PDF" });
      fetchReports();
    } catch (_) {}
  };

  const createSchedule = async () => {
    if (!newSchedule.name || !newSchedule.cron_expression) return;
    try {
      await api.post("/reports/scheduled", {
        ...newSchedule,
        recipients: newSchedule.recipients.split(",").map((r: string) => r.trim()).filter(Boolean),
      });
      setShowCreateSchedule(false);
      setNewSchedule({ name: "", type: "Executive", format: "PDF", cron_expression: "", recipients: "" });
      fetchScheduled();
    } catch (_) {}
  };

  const createTemplate = async () => {
    if (!newTemplate.name) return;
    try {
      await api.post("/reports/templates", newTemplate);
      setShowCreateTemplate(false);
      setNewTemplate({ name: "", description: "", type: "Executive" });
      fetchTemplates();
    } catch (_) {}
  };

  const deleteScheduled = async (id: string) => {
    try {
      await api.delete("/reports/scheduled/" + id);
      fetchScheduled();
    } catch (_) {}
  };

  const tabs: { key: TabName; label: string }[] = [
    { key: "generated", label: "Generated Reports" },
    { key: "scheduled", label: "Scheduled Reports" },
    { key: "templates", label: "Templates" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Reports & Analytics</h1>
          <p className="text-sm text-slate-500 mt-1">
            {stats.reports_generated} report{stats.reports_generated !== 1 ? "s" : ""} generated this month
          </p>
        </div>
        <div className="flex items-center gap-2">
          {activeTab === "generated" && (
            <Button size="md" onClick={() => setShowCreateReport(true)}>
              <Plus className="w-4 h-4" />
              Generate Report
            </Button>
          )}
          {activeTab === "scheduled" && (
            <Button size="md" onClick={() => setShowCreateSchedule(true)}>
              <Plus className="w-4 h-4" />
              Create Schedule
            </Button>
          )}
          {activeTab === "templates" && (
            <Button size="md" onClick={() => setShowCreateTemplate(true)}>
              <Plus className="w-4 h-4" />
              Create Template
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Generated This Month" value={String(stats.reports_generated)} icon={FileText} />
        <StatCard label="Scheduled Reports" value={String(stats.scheduled_reports)} icon={Clock} />
        <StatCard label="Templates Available" value={String(stats.templates_available)} icon={FileSpreadsheet} />
      </div>

      <div className="flex border-b border-slate-200 gap-1">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={
              "px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px " +
              (activeTab === tab.key
                ? "border-brand-600 text-brand-700"
                : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300")
            }
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "generated" && (
        <div className="space-y-4">
          {reportsError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{reportsError}</p>
              <Button variant="secondary" size="sm" onClick={fetchReports}>Retry</Button>
            </div>
          )}

          {reportsLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading reports..." />
            </div>
          )}

          {!reportsLoading && !reportsError && reports.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <FileText className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No reports generated yet</p>
                <p className="text-sm text-slate-400">Create your first report to get started</p>
                <Button variant="secondary" size="sm" onClick={() => setShowCreateReport(true)}>
                  <Plus className="w-4 h-4" />
                  Generate Report
                </Button>
              </div>
            </Card>
          )}

          {!reportsLoading && !reportsError && reports.length > 0 && (
            <Card padding="none">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50">
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Name</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Format</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Created</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {reports.map((report) => {
                      const FIcon = formatIcon[report.format] || FileText;
                      return (
                        <tr key={report.id} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <FIcon className="w-4 h-4 text-slate-400" />
                              <span className="text-sm font-medium text-slate-900">{report.name}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <Badge variant="info" size="sm">{report.type}</Badge>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-xs font-mono uppercase text-slate-600">{report.format}</span>
                          </td>
                          <td className="px-4 py-3">
                            <Badge variant={statusBadgeVariant[report.status] || "default"} size="sm">
                              {report.status}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-xs text-slate-500">
                              {new Date(report.created_at).toLocaleDateString("en-US", {
                                month: "short", day: "numeric", year: "numeric",
                              })}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            {report.status === "completed" && report.file_url ? (
                              <a
                                href={report.file_url}
                                className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-600 hover:text-brand-800 px-2 py-1.5 rounded-lg hover:bg-brand-50 transition-colors"
                              >
                                <Download className="w-3.5 h-3.5" />
                                Download
                              </a>
                            ) : (
                              <span className="text-xs text-slate-400">--</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      )}

      {activeTab === "scheduled" && (
        <div className="space-y-4">
          {scheduledError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{scheduledError}</p>
              <Button variant="secondary" size="sm" onClick={fetchScheduled}>Retry</Button>
            </div>
          )}

          {scheduledLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading scheduled reports..." />
            </div>
          )}

          {!scheduledLoading && !scheduledError && scheduled.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Clock className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No scheduled reports</p>
                <p className="text-sm text-slate-400">Schedule periodic report generation</p>
                <Button variant="secondary" size="sm" onClick={() => setShowCreateSchedule(true)}>
                  <Plus className="w-4 h-4" />
                  Create Schedule
                </Button>
              </div>
            </Card>
          )}

          {!scheduledLoading && !scheduledError && scheduled.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {scheduled.map((sched) => (
                <Card key={sched.id} hover>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-brand-50">
                        <RotateCw className="w-4 h-4 text-brand-600" />
                      </div>
                      <div>
                        <h3 className="font-medium text-slate-900">{sched.name}</h3>
                        <p className="text-xs text-slate-400">{sched.type} / {sched.format.toUpperCase()}</p>
                      </div>
                    </div>
                    <Badge variant={sched.enabled ? "success" : "default"} size="sm">
                      {sched.enabled ? "Active" : "Paused"}
                    </Badge>
                  </div>
                  <div className="space-y-2 text-sm text-slate-600">
                    <div className="flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-slate-400" />
                      <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono">{sched.cron_expression}</code>
                    </div>
                    {sched.next_run && (
                      <div className="flex items-center gap-2 text-xs">
                        <Calendar className="w-3.5 h-3.5 text-slate-400" />
                        <span>Next: {new Date(sched.next_run).toLocaleString()}</span>
                      </div>
                    )}
                    {sched.last_run && (
                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <Activity className="w-3.5 h-3.5" />
                        <span>Last: {new Date(sched.last_run).toLocaleString()}</span>
                      </div>
                    )}
                    {sched.recipients.length > 0 && (
                      <p className="text-xs text-slate-400 mt-1">Recipients: {sched.recipients.join(", ")}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-100">
                    <Button variant="secondary" size="sm" className="flex-1">
                      <Edit2 className="w-3.5 h-3.5" />
                      Edit
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => deleteScheduled(sched.id)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "templates" && (
        <div className="space-y-4">
          {templatesError && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{templatesError}</p>
              <Button variant="secondary" size="sm" onClick={fetchTemplates}>Retry</Button>
            </div>
          )}

          {templatesLoading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading templates..." />
            </div>
          )}

          {!templatesLoading && !templatesError && templates.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <FileSpreadsheet className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No templates available</p>
                <Button variant="secondary" size="sm" onClick={() => setShowCreateTemplate(true)}>
                  <Plus className="w-4 h-4" />
                  Create Template
                </Button>
              </div>
            </Card>
          )}

          {!templatesLoading && !templatesError && templates.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templates.map((tmpl) => (
                <Card key={tmpl.id} hover>
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-blue-50">
                        <FileText className="w-4 h-4 text-blue-600" />
                      </div>
                      <div>
                        <h3 className="font-medium text-slate-900">{tmpl.name}</h3>
                        <Badge variant="info" size="sm">{tmpl.type}</Badge>
                      </div>
                    </div>
                    {tmpl.is_system && (
                      <Badge variant="default" size="sm">System</Badge>
                    )}
                  </div>
                  {tmpl.description && (
                    <p className="text-sm text-slate-500 mt-2 line-clamp-2">{tmpl.description}</p>
                  )}
                  <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-100">
                    <Button variant="secondary" size="sm" className="flex-1">
                      <Copy className="w-3.5 h-3.5" />
                      Use Template
                    </Button>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      <Modal open={showCreateReport} onClose={() => setShowCreateReport(false)} title="Generate Report" size="md">
        <div className="space-y-4">
          <Input label="Report Name" placeholder="e.g. Monthly Executive Report" value={newReport.name} onChange={(e) => setNewReport((p) => ({ ...p, name: e.target.value }))} />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Report Type</label>
            <select value={newReport.type} onChange={(e) => setNewReport((p) => ({ ...p, type: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              {reportTypes.map((t) => (<option key={t} value={t}>{t}</option>))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Format</label>
            <select value={newReport.format} onChange={(e) => setNewReport((p) => ({ ...p, format: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              {reportFormats.map((f) => (<option key={f} value={f}>{f}</option>))}
            </select>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowCreateReport(false); setNewReport({ name: "", type: "Executive", format: "PDF" }); }}>Cancel</Button>
            <Button onClick={createReport} disabled={!newReport.name}>
              <Plus className="w-4 h-4" />
              Generate
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={showCreateSchedule} onClose={() => setShowCreateSchedule(false)} title="Create Report Schedule" size="md">
        <div className="space-y-4">
          <Input label="Schedule Name" placeholder="e.g. Weekly Incident Report" value={newSchedule.name} onChange={(e) => setNewSchedule((p) => ({ ...p, name: e.target.value }))} />
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Report Type</label>
              <select value={newSchedule.type} onChange={(e) => setNewSchedule((p) => ({ ...p, type: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
                {reportTypes.map((t) => (<option key={t} value={t}>{t}</option>))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Format</label>
              <select value={newSchedule.format} onChange={(e) => setNewSchedule((p) => ({ ...p, format: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
                {reportFormats.map((f) => (<option key={f} value={f}>{f}</option>))}
              </select>
            </div>
          </div>
          <Input label="Cron Expression" placeholder="0 8 * * 1 (every Monday 8 AM)" hint="Standard cron syntax: minute hour day month weekday" value={newSchedule.cron_expression} onChange={(e) => setNewSchedule((p) => ({ ...p, cron_expression: e.target.value }))} />
          <Input label="Recipients" placeholder="email1@org.com, email2@org.com" hint="Comma-separated email addresses" value={newSchedule.recipients} onChange={(e) => setNewSchedule((p) => ({ ...p, recipients: e.target.value }))} />
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowCreateSchedule(false); setNewSchedule({ name: "", type: "Executive", format: "PDF", cron_expression: "", recipients: "" }); }}>Cancel</Button>
            <Button onClick={createSchedule} disabled={!newSchedule.name || !newSchedule.cron_expression}>
              <Plus className="w-4 h-4" />
              Create Schedule
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={showCreateTemplate} onClose={() => setShowCreateTemplate(false)} title="Create Report Template" size="md">
        <div className="space-y-4">
          <Input label="Template Name" placeholder="e.g. Custom Executive Summary" value={newTemplate.name} onChange={(e) => setNewTemplate((p) => ({ ...p, name: e.target.value }))} />
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Type</label>
            <select value={newTemplate.type} onChange={(e) => setNewTemplate((p) => ({ ...p, type: e.target.value }))} className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer">
              {reportTypes.map((t) => (<option key={t} value={t}>{t}</option>))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Description</label>
            <textarea value={newTemplate.description} onChange={(e) => setNewTemplate((p) => ({ ...p, description: e.target.value }))} placeholder="Describe the template..." className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 resize-none" rows={3} />
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowCreateTemplate(false); setNewTemplate({ name: "", description: "", type: "Executive" }); }}>Cancel</Button>
            <Button onClick={createTemplate} disabled={!newTemplate.name}>
              <Plus className="w-4 h-4" />
              Create Template
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
