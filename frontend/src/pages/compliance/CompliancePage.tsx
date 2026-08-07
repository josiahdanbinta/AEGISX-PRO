import { useState, useEffect, useCallback } from "react";
import {
  Shield, Search, Plus, CheckCircle, XCircle, AlertTriangle,
  AlertCircle, ChevronDown, Filter, X, Upload, FileText,
  ClipboardCheck, BarChart3, ExternalLink,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Table } from "@/components/ui/Table";
import { Loading } from "@/components/ui/Loading";
import { Modal } from "@/components/ui/Modal";
import { api } from "@/services/api";

interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  category: string;
  completion_pct: number;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  not_assessed_controls: number;
  status: string;
}

interface AssessmentControl {
  id: string;
  framework_id: string;
  control_id: string;
  title: string;
  category: string;
  status: string;
  evidence_url?: string;
  notes?: string;
  last_assessed?: string;
}

interface ComplianceGap {
  framework_name: string;
  framework_id: string;
  control_id: string;
  title: string;
  category: string;
}

type ViewMode = "frameworks" | "assessment";

const statusBadgeVariant: Record<string, "success" | "danger" | "warning" | "default" | "info"> = {
  passed: "success",
  failed: "danger",
  not_assessed: "default",
  not_applicable: "default",
  in_progress: "warning",
  completed: "success",
  not_started: "default",
};

const statusLabel: Record<string, string> = {
  passed: "Passed",
  failed: "Failed",
  not_assessed: "Not Assessed",
  not_applicable: "N/A",
  in_progress: "In Progress",
  completed: "Completed",
  not_started: "Not Started",
};

const statusCycle: Record<string, string> = {
  passed: "failed",
  failed: "not_applicable",
  not_applicable: "not_assessed",
  not_assessed: "passed",
};

const allFrameworks = ["PCI DSS", "SOC 2", "ISO 27001", "NIST CSF", "HIPAA", "GDPR", "CIS Controls"];

export function CompliancePage() {
  const [viewMode, setViewMode] = useState<ViewMode>("frameworks");
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gaps, setGaps] = useState<ComplianceGap[]>([]);

  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework | null>(null);
  const [controls, setControls] = useState<AssessmentControl[]>([]);
  const [controlsLoading, setControlsLoading] = useState(false);
  const [controlsError, setControlsError] = useState<string | null>(null);
  const [controlSearch, setControlSearch] = useState("");
  const [controlStatusFilter, setControlStatusFilter] = useState("");
  const [controlCategoryFilter, setControlCategoryFilter] = useState("");

  const [showNewAssessment, setShowNewAssessment] = useState(false);
  const [newAssessmentFramework, setNewAssessmentFramework] = useState("");

  const fetchFrameworks = useCallback(() => {
    setLoading(true);
    setError(null);
    api.get<ComplianceFramework[]>("/compliance/frameworks")
      .then((res) => setFrameworks(res))
      .catch((err) => setError(err?.error?.message || "Failed to load frameworks"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchFrameworks();
  }, [fetchFrameworks]);

  useEffect(() => {
    api.get<ComplianceGap[]>("/compliance/gaps")
      .then((res) => setGaps((res as unknown as { items: ComplianceGap[] }).items))
      .catch(() => {});
  }, []);

  const viewAssessment = (framework: ComplianceFramework) => {
    setSelectedFramework(framework);
    setViewMode("assessment");
    setControlsLoading(true);
    setControlsError(null);
    setControlSearch("");
    setControlStatusFilter("");
    setControlCategoryFilter("");
    api.get<AssessmentControl[]>("/compliance/assessments/" + framework.id + "/controls")
      .then((res) => setControls(res))
      .catch((err) => setControlsError(err?.error?.message || "Failed to load controls"))
      .finally(() => setControlsLoading(false));
  };

  const updateControlStatus = async (controlId: string, newStatus: string) => {
    try {
      await api.patch("/compliance/controls/" + controlId, { status: newStatus });
      setControls((prev) =>
        prev.map((c) => (c.id === controlId ? { ...c, status: newStatus } : c))
      );
      if (selectedFramework) {
        const updated = controls.map((c) =>
          c.id === controlId ? { ...c, status: newStatus } : c
        );
        const total = updated.length;
        const passed = updated.filter((c) => c.status === "passed").length;
        const failed = updated.filter((c) => c.status === "failed").length;
        const notAssessed = updated.filter((c) => c.status === "not_assessed").length;
        setSelectedFramework((prev) =>
          prev
            ? {
                ...prev,
                passed_controls: passed,
                failed_controls: failed,
                not_assessed_controls: notAssessed,
                completion_pct: Math.round((passed / total) * 100),
              }
            : prev
        );
      }
    } catch (_) {}
  };

  const updateControlNotes = async (controlId: string, notes: string) => {
    try {
      await api.patch("/compliance/controls/" + controlId, { notes });
      setControls((prev) =>
        prev.map((c) => (c.id === controlId ? { ...c, notes } : c))
      );
    } catch (_) {}
  };

  const startNewAssessment = async () => {
    if (!newAssessmentFramework) return;
    try {
      await api.post("/compliance/assessments", { framework_name: newAssessmentFramework });
      setShowNewAssessment(false);
      setNewAssessmentFramework("");
      fetchFrameworks();
    } catch (_) {}
  };

  const categories = Array.from(new Set(controls.map((c) => c.category)));

  const filteredControls = controls.filter((c) => {
    const searchLower = controlSearch.toLowerCase();
    if (controlSearch && !c.title.toLowerCase().includes(searchLower) && !c.control_id.toLowerCase().includes(searchLower)) return false;
    if (controlStatusFilter && c.status !== controlStatusFilter) return false;
    if (controlCategoryFilter && c.category !== controlCategoryFilter) return false;
    return true;
  });

  const totalPassed = frameworks.reduce((s, f) => s + f.passed_controls, 0);
  const totalControls = frameworks.reduce((s, f) => s + f.total_controls, 0);
  const overallPct = totalControls > 0 ? Math.round((totalPassed / totalControls) * 100) : 0;

  const gapFrameworks = Array.from(new Set(gaps.map((g) => g.framework_id)));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Compliance Management</h1>
          <p className="text-sm text-slate-500 mt-1">
            {frameworks.length} framework{frameworks.length !== 1 ? "s" : ""} tracked
            {viewMode === "assessment" && selectedFramework && " - Viewing " + selectedFramework.name}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {viewMode === "assessment" && (
            <Button variant="secondary" size="md" onClick={() => setViewMode("frameworks")}>
              <BarChart3 className="w-4 h-4" />
              All Frameworks
            </Button>
          )}
          <Button size="md" onClick={() => setShowNewAssessment(true)}>
            <Plus className="w-4 h-4" />
            New Assessment
          </Button>
        </div>
      </div>

      {viewMode === "frameworks" && (
        <>
          <Card>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-700">Overall Compliance Score</span>
                <span className="text-sm font-bold text-slate-900">{overallPct}%</span>
              </div>
              <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className={
                    "h-full rounded-full transition-all duration-500 " +
                    (overallPct >= 80 ? "bg-emerald-500" : overallPct >= 50 ? "bg-amber-500" : "bg-red-500")
                  }
                  style={{ width: overallPct + "%" }}
                />
              </div>
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>{totalPassed} passed of {totalControls} controls</span>
                <span>Target: 80%</span>
              </div>
            </div>
          </Card>

          {error && (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <AlertCircle className="w-10 h-10 text-red-400" />
              <p className="text-red-600 font-medium">{error}</p>
              <Button variant="secondary" size="sm" onClick={fetchFrameworks}>Retry</Button>
            </div>
          )}

          {loading && (
            <div className="flex items-center justify-center py-20">
              <Loading size="lg" text="Loading frameworks..." />
            </div>
          )}

          {!loading && !error && frameworks.length === 0 && (
            <Card>
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Shield className="w-10 h-10 text-slate-300" />
                <p className="text-slate-500 font-medium">No compliance frameworks configured</p>
                <p className="text-sm text-slate-400">Start an assessment to begin tracking compliance</p>
                <Button variant="secondary" size="sm" onClick={() => setShowNewAssessment(true)}>
                  <Plus className="w-4 h-4" />
                  Start Assessment
                </Button>
              </div>
            </Card>
          )}

          {!loading && !error && frameworks.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {frameworks.map((fw) => (
                <Card key={fw.id} hover padding="md">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-brand-600" />
                        <h3 className="font-semibold text-slate-900">{fw.name}</h3>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{fw.category || "General"}</p>
                    </div>
                    <Badge variant={statusBadgeVariant[fw.status] || "default"} size="sm">
                      {statusLabel[fw.status] || fw.status}
                    </Badge>
                  </div>
                  <div className="space-y-2 mb-4">
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>{fw.completion_pct}% complete</span>
                    </div>
                    <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className={
                          "h-full rounded-full transition-all " +
                          (fw.completion_pct >= 80 ? "bg-emerald-500" : fw.completion_pct >= 50 ? "bg-amber-500" : "bg-red-500")
                        }
                        style={{ width: fw.completion_pct + "%" }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-3 mb-4 text-xs">
                    <span className="flex items-center gap-1 text-emerald-600">
                      <CheckCircle className="w-3.5 h-3.5" />
                      {fw.passed_controls} passed
                    </span>
                    <span className="flex items-center gap-1 text-red-500">
                      <XCircle className="w-3.5 h-3.5" />
                      {fw.failed_controls} failed
                    </span>
                    <span className="flex items-center gap-1 text-slate-400">
                      <AlertCircle className="w-3.5 h-3.5" />
                      {fw.not_assessed_controls} remaining
                    </span>
                  </div>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="w-full"
                    onClick={() => viewAssessment(fw)}
                  >
                    <ClipboardCheck className="w-3.5 h-3.5" />
                    View Assessment
                  </Button>
                </Card>
              ))}
            </div>
          )}

          {gaps.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Compliance Gaps</CardTitle>
                <Badge variant="danger" size="sm">{gaps.length} gaps</Badge>
              </CardHeader>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {gapFrameworks.map((fwId) => {
                  const fwGaps = gaps.filter((g) => g.framework_id === fwId);
                  const fwName = fwGaps[0]?.framework_name || fwId;
                  return (
                    <details key={fwId} className="group">
                      <summary className="flex items-center justify-between p-3 rounded-lg bg-slate-50 hover:bg-slate-100 cursor-pointer transition-colors">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-red-500" />
                          <span className="text-sm font-medium text-slate-700">{fwName}</span>
                        </div>
                        <Badge variant="danger" size="sm">{fwGaps.length} failed</Badge>
                      </summary>
                      <div className="mt-1 space-y-1 pl-4">
                        {fwGaps.map((gap) => (
                          <div key={gap.control_id} className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-50 text-sm">
                            <div className="flex items-center gap-2">
                              <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                              <div>
                                <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-600">{gap.control_id}</code>
                                <span className="mx-1 text-slate-300">|</span>
                                <span className="text-slate-700">{gap.title}</span>
                              </div>
                            </div>
                            <Badge variant="default" size="sm">{gap.category}</Badge>
                          </div>
                        ))}
                      </div>
                    </details>
                  );
                })}
              </div>
            </Card>
          )}
        </>
      )}

      {viewMode === "assessment" && selectedFramework && (
        <>
          <Card>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-slate-900">{selectedFramework.name} Assessment</h3>
                  <p className="text-xs text-slate-400">
                    {selectedFramework.passed_controls} of {selectedFramework.total_controls} controls passed
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-bold text-slate-900">{selectedFramework.completion_pct}%</span>
                </div>
              </div>
              <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className={
                    "h-full rounded-full transition-all duration-500 " +
                    (selectedFramework.completion_pct >= 80 ? "bg-emerald-500" : selectedFramework.completion_pct >= 50 ? "bg-amber-500" : "bg-red-500")
                  }
                  style={{ width: selectedFramework.completion_pct + "%" }}
                />
              </div>
            </div>
          </Card>

          <Card padding="none">
            <div className="p-4 border-b border-slate-100">
              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px] max-w-xs">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <Input
                    placeholder="Search controls..."
                    value={controlSearch}
                    onChange={(e) => setControlSearch(e.target.value)}
                    className="pl-9"
                  />
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  <select
                    value={controlStatusFilter}
                    onChange={(e) => setControlStatusFilter(e.target.value)}
                    className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="">All Statuses</option>
                    <option value="passed">Passed</option>
                    <option value="failed">Failed</option>
                    <option value="not_assessed">Not Assessed</option>
                    <option value="not_applicable">Not Applicable</option>
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                </div>
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  <select
                    value={controlCategoryFilter}
                    onChange={(e) => setControlCategoryFilter(e.target.value)}
                    className="appearance-none bg-white border border-slate-200 rounded-lg pl-9 pr-8 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="">All Categories</option>
                    {categories.map((cat) => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                </div>
                {(controlSearch || controlStatusFilter || controlCategoryFilter) && (
                  <Button variant="ghost" size="sm" onClick={() => { setControlSearch(""); setControlStatusFilter(""); setControlCategoryFilter(""); }}>
                    <X className="w-3.5 h-3.5" />
                    Clear
                  </Button>
                )}
              </div>
            </div>

            {controlsError && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <AlertCircle className="w-10 h-10 text-red-400" />
                <p className="text-red-600 font-medium">{controlsError}</p>
                <Button variant="secondary" size="sm" onClick={() => viewAssessment(selectedFramework)}>Retry</Button>
              </div>
            )}

            {controlsLoading && (
              <div className="flex items-center justify-center py-20">
                <Loading size="lg" text="Loading controls..." />
              </div>
            )}

            {!controlsLoading && !controlsError && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50">
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider w-[110px]">Control ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Title</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider w-[130px]">Category</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider w-[120px]">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider w-[100px]">Evidence</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Notes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredControls.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-12 text-center text-slate-400">
                          No controls found
                        </td>
                      </tr>
                    ) : (
                      filteredControls.map((ctrl) => (
                        <tr key={ctrl.id} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-3">
                            <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-700 whitespace-nowrap">
                              {ctrl.control_id}
                            </code>
                          </td>
                          <td className="px-4 py-3">
                            <span className="text-sm text-slate-700">{ctrl.title}</span>
                          </td>
                          <td className="px-4 py-3">
                            <Badge variant="default" size="sm">{ctrl.category}</Badge>
                          </td>
                          <td className="px-4 py-3">
                            <button
                              onClick={() =>
                                updateControlStatus(ctrl.id, statusCycle[ctrl.status] || "passed")
                              }
                              className="cursor-pointer"
                              title="Click to cycle status"
                            >
                              <Badge variant={statusBadgeVariant[ctrl.status] || "default"} size="sm">
                                {statusLabel[ctrl.status] || ctrl.status}
                              </Badge>
                            </button>
                          </td>
                          <td className="px-4 py-3">
                            {ctrl.evidence_url ? (
                              <a
                                href={ctrl.evidence_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 text-xs text-brand-600 hover:text-brand-800"
                              >
                                <FileText className="w-3 h-3" />
                                View
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ) : (
                              <button className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-brand-600 transition-colors">
                                <Upload className="w-3 h-3" />
                                Upload
                              </button>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <input
                              type="text"
                              value={ctrl.notes || ""}
                              onChange={(e) => updateControlNotes(ctrl.id, e.target.value)}
                              placeholder="Add notes..."
                              className="w-full text-xs border border-slate-200 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 bg-transparent"
                            />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}

      <Modal open={showNewAssessment} onClose={() => setShowNewAssessment(false)} title="Start New Assessment" size="md">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1.5">Select Framework</label>
            <select
              value={newAssessmentFramework}
              onChange={(e) => setNewAssessmentFramework(e.target.value)}
              className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
            >
              <option value="">-- Choose framework --</option>
              {allFrameworks.map((fw) => (
                <option key={fw} value={fw}>{fw}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => { setShowNewAssessment(false); setNewAssessmentFramework(""); }}>
              Cancel
            </Button>
            <Button onClick={startNewAssessment} disabled={!newAssessmentFramework}>
              <Plus className="w-4 h-4" />
              Start Assessment
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
