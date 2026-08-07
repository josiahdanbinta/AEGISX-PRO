import React, { useState, useEffect, useCallback } from 'react';
import {
  Monitor, Cpu, HardDrive, MemoryStick, Wifi, Shield, AlertTriangle,
  Bug, Package, Clock, Server, Activity, Terminal, RefreshCw,
  CheckCircle, XCircle, ChevronRight, Download, Usb, Cpu as ChipIcon,
  ArrowUpCircle, Wrench, Zap, Plus, Copy, Check,
} from 'lucide-react';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Loading } from '../../components/ui/Loading';
import { DonutChart, AlertSeverityPie, AgentSummaryRow } from '../../components/charts/DonutCharts';
import { api } from '../../services/api';
import { useTheme } from '../../contexts/ThemeContext';

interface AgentSummary {
  id: string; hostname: string; platform: string; status: string;
  ip_address: string; last_heartbeat?: string; vuln_count: number;
}

interface VulnItem {
  name: string; severity: string; description: string; fix: string;
  fix_command?: string; auto_fix: boolean;
}

export default function AgentDashboard() {
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [stats, setStats] = useState({ total: 0, online: 0, offline: 0, active: 0 });
  const [selectedAgent, setSelectedAgent] = useState<AgentSummary | null>(null);
  const [inventory, setInventory] = useState<any>(null);
  const [vulns, setVulns] = useState<VulnItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showEnroll, setShowEnroll] = useState(false);
  const [enrollCmd, setEnrollCmd] = useState<{ command: string; agent_key: string } | null>(null);
  const [platform, setPlatform] = useState('linux');
  const [copied, setCopied] = useState(false);

  const fetchDashboard = useCallback(async () => {
    try {
      const data = await api.get<any>('/agents/dashboard/summary');
      setAgents(data.agents || []);
      setStats({
        total: data.total_agents || 0,
        online: data.online || 0,
        offline: data.offline || 0,
        active: data.total_vulnerabilities || 0,
      });
    } catch (_) {}
    setLoading(false);
  }, []);

  useEffect(() => { fetchDashboard(); }, [fetchDashboard]);

  const selectAgent = async (agent: AgentSummary) => {
    setSelectedAgent(agent);
    setInventory(null);
    setVulns([]);
    try {
      const [inv, vulnData] = await Promise.all([
        api.get<any>(`/agents/${agent.id}/inventory`),
        api.get<any>(`/agents/${agent.id}/vulnerabilities`),
      ]);
      setInventory(inv);
      setVulns(vulnData.vulnerabilities || []);
    } catch (_) {}
  };

  const getEnrollCmd = async () => {
    try {
      const data = await api.get<any>(`/agents/enroll/command?platform=${platform}`);
      setEnrollCmd(data);
    } catch (_) {}
  };

  const copyCommand = () => {
    if (enrollCmd) {
      navigator.clipboard.writeText(enrollCmd.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="p-4 space-y-4" style={{ background: 'linear-gradient(135deg, #f0f7ff 0%, #e8f4fd 100%)' }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-800">Agent Dashboard</h1>
          <p className="text-sm text-gray-500">Endpoint inventory, hardware, software, and vulnerability management</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => fetchDashboard()} variant="secondary" size="md">
            <RefreshCw className="w-4 h-4" /> Refresh
          </Button>
          <Button onClick={() => setShowEnroll(true)}>
            <Plus className="w-4 h-4" /> Deploy Agent
          </Button>
        </div>
      </div>

      {/* Summary Row */}
      <AgentSummaryRow stats={stats} />

      {loading && <Loading text="Loading agent inventory..." />}

      {/* Agent Grid + Selected Details */}
      {!loading && (
        <div className="grid grid-cols-12 gap-4">
          {/* Agent List */}
          <div className="col-span-4 space-y-2">
            <h2 className="text-sm font-semibold text-gray-600 uppercase tracking-wider">Endpoints ({agents.length})</h2>
            {agents.length === 0 ? (
              <Card className="p-8 text-center">
                <Monitor className="w-10 h-10 text-gray-300 mx-auto mb-2" />
                <p className="text-sm text-gray-500">No agents connected</p>
                <Button size="sm" onClick={() => setShowEnroll(true)} className="mt-3">
                  <Download className="w-3.5 h-3.5" /> Deploy First Agent
                </Button>
              </Card>
            ) : (
              agents.map((agent) => (
                <div key={agent.id} onClick={() => selectAgent(agent)} className="cursor-pointer">
                  <Card
                    className={`p-3 transition-all hover:shadow-md ${
                      selectedAgent?.id === agent.id ? 'border-brand-500 ring-1 ring-brand-200 bg-brand-50' : ''
                    }`}
                  >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${agent.platform === 'windows' ? 'bg-blue-50' : agent.platform === 'darwin' ? 'bg-gray-50' : 'bg-emerald-50'}`}>
                        <Monitor className={`w-4 h-4 ${agent.platform === 'windows' ? 'text-blue-500' : agent.platform === 'darwin' ? 'text-gray-500' : 'text-emerald-500'}`} />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-800">{agent.hostname}</p>
                        <p className="text-xs text-gray-400">{agent.ip_address || 'No IP'} Â· {agent.platform}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {agent.vuln_count > 0 && (
                        <Badge className="text-xs bg-red-50 text-red-600">{agent.vuln_count}</Badge>
                      )}
                      <span className={`w-2 h-2 rounded-full ${agent.status === 'online' ? 'bg-emerald-400' : 'bg-gray-300'}`} />
                    </div>
                    </div>
                  </Card>
                </div>
              ))
            )}
          </div>

          {/* Agent Detail */}
          <div className="col-span-8">
            {!selectedAgent ? (
              <Card className="p-12 text-center">
                <ChipIcon className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                <p className="text-gray-500 font-medium">Select an agent to view details</p>
                <p className="text-sm text-gray-400 mt-1">Hardware, software, vulnerabilities, and fixes</p>
              </Card>
            ) : inventory ? (
              <div className="space-y-4">
                {/* Hardware */}
                <Card className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Cpu className="w-4 h-4 text-brand-500" />
                    <h3 className="text-sm font-semibold text-gray-700">Hardware</h3>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    {inventory.hardware?.cpu && (
                      <div className="bg-gray-50 rounded-lg p-2.5">
                        <span className="text-gray-400">CPU</span>
                        <p className="text-gray-700 font-medium">{inventory.hardware.cpu.model}</p>
                        <p className="text-gray-500">{inventory.hardware.cpu.cores} cores Â· {inventory.hardware.cpu.threads} threads Â· {inventory.hardware.cpu.frequency_mhz}MHz</p>
                      </div>
                    )}
                    {inventory.hardware?.memory && (
                      <div className="bg-gray-50 rounded-lg p-2.5">
                        <span className="text-gray-400">RAM</span>
                        <p className="text-gray-700 font-medium">{inventory.hardware.memory.total_gb} GB</p>
                        {inventory.hardware.memory.modules?.map((m: any, i: number) => (
                          <p key={i} className="text-gray-500">{m.capacity_gb}GB {m.speed_mhz}MHz Â· {m.manufacturer}</p>
                        ))}
                      </div>
                    )}
                    {inventory.hardware?.disks?.map((d: any, i: number) => (
                      <div key={i} className="bg-gray-50 rounded-lg p-2.5">
                        <span className="text-gray-400">Disk {d.device}</span>
                        <p className="text-gray-700 font-medium">{d.size_gb} GB Â· {d.model}</p>
                        <p className="text-gray-500">Health: {d.health || 'OK'} Â· S/N: {d.serial?.slice(0, 12)}</p>
                      </div>
                    ))}
                    {inventory.hardware?.bios && (
                      <div className="bg-gray-50 rounded-lg p-2.5">
                        <span className="text-gray-400">BIOS</span>
                        <p className="text-gray-700 font-medium">{inventory.hardware.bios.vendor} v{inventory.hardware.bios.version}</p>
                        <p className="text-gray-500">{inventory.hardware.bios.date}</p>
                      </div>
                    )}
                    {inventory.hardware?.network_adapters?.slice(0, 2).map((n: any, i: number) => (
                      <div key={i} className="bg-gray-50 rounded-lg p-2.5">
                        <span className="text-gray-400">Network</span>
                        <p className="text-gray-700 font-medium">{n.name}</p>
                        <p className="text-gray-500">MAC: {n.mac?.slice(0, 17)} Â· {n.speed_mbps}Mbps</p>
                      </div>
                    ))}
                  </div>
                </Card>

                {/* Software */}
                <Card className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Package className="w-4 h-4 text-brand-500" />
                    <h3 className="text-sm font-semibold text-gray-700">Software Inventory</h3>
                  </div>
                  <div className="space-y-3">
                    {inventory.software?.installed_apps && (
                      <div>
                        <span className="text-xs text-gray-400 font-medium uppercase">Installed Apps ({inventory.software.installed_apps.length})</span>
                        <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                          {inventory.software.installed_apps.slice(0, 8).map((app: any, i: number) => (
                            <div key={i} className="flex items-center justify-between bg-gray-50 rounded px-2.5 py-1.5 text-xs">
                              <span className="text-gray-700 truncate">{app.name}</span>
                              <span className="text-gray-400 ml-2 flex-shrink-0">{app.version}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Outdated Apps */}
                    {inventory.software?.outdated_apps?.length > 0 && (
                      <div>
                        <span className="text-xs text-amber-500 font-medium uppercase flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> Outdated ({inventory.software.outdated_apps.length})
                        </span>
                        <div className="mt-1.5 space-y-1">
                          {inventory.software.outdated_apps.slice(0, 5).map((app: any, i: number) => (
                            <div key={i} className="flex items-center justify-between bg-amber-50 rounded px-2.5 py-1.5 text-xs border border-amber-100">
                              <div>
                                <span className="text-gray-700 font-medium">{app.name}</span>
                                <span className="text-gray-400 ml-2">{app.current_version} â†’ {app.latest_version}</span>
                              </div>
                              <Button size="sm" className="text-[10px] px-2 py-0.5 h-6">
                                <ArrowUpCircle className="w-3 h-3" /> Update
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Running Services */}
                    {inventory.software?.running_services?.length > 0 && (
                      <div>
                        <span className="text-xs text-gray-400 font-medium uppercase">Running Services ({inventory.software.running_services.length})</span>
                        <div className="mt-1.5 grid grid-cols-2 gap-1.5">
                          {inventory.software.running_services.slice(0, 6).map((svc: any, i: number) => (
                            <div key={i} className={`flex items-center justify-between rounded px-2.5 py-1.5 text-xs ${
                              svc.risk === 'high' ? 'bg-red-50 border border-red-100' : 'bg-gray-50'
                            }`}>
                              <div>
                                <span className="text-gray-700">{svc.name}</span>
                                <span className="text-gray-400 ml-1.5">{svc.status}</span>
                              </div>
                              {svc.risk === 'high' && <Badge className="text-[10px] bg-red-100 text-red-600">HIGH RISK</Badge>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </Card>

                {/* Vulnerabilities with Fixes */}
                {vulns.length > 0 && (
                  <Card className="p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="w-4 h-4 text-red-500" />
                      <h3 className="text-sm font-semibold text-gray-700">Vulnerabilities & Fixes</h3>
                      <Badge className="ml-auto text-xs bg-red-50 text-red-600">{vulns.length} issues</Badge>
                    </div>
                    <div className="space-y-2">
                      {vulns.map((vuln, i) => (
                        <div key={i} className="bg-gray-50 rounded-lg p-3 border border-gray-100">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <Badge className={`text-xs ${
                                  vuln.severity === 'critical' ? 'bg-red-100 text-red-700' :
                                  vuln.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                                  'bg-amber-100 text-amber-700'
                                }`}>{vuln.severity.toUpperCase()}</Badge>
                                <span className="text-sm font-medium text-gray-800">{vuln.name}</span>
                              </div>
                              <p className="text-xs text-gray-500 mt-1">{vuln.description}</p>
                              <p className="text-xs text-emerald-600 mt-1">
                                <Wrench className="w-3 h-3 inline mr-1" /> Fix: {vuln.fix}
                              </p>
                            </div>
                            <div className="flex gap-1.5 ml-3 flex-shrink-0">
                              {vuln.fix_command && (
                                <Button
                                  size="sm"
                                  className="text-[10px] px-2 py-0.5 h-7"
                                  onClick={() => navigator.clipboard.writeText(vuln.fix_command || '')}
                                >
                                  <Terminal className="w-3 h-3" /> Copy Fix CMD
                                </Button>
                              )}
                              {vuln.auto_fix && (
                                <Button size="sm" variant="success" className="text-[10px] px-2 py-0.5 h-7">
                                  <Zap className="w-3 h-3" /> Auto-Fix
                                </Button>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* Donut Chart for Vulns */}
                {vulns.length > 0 && (
                  <AlertSeverityPie
                    data={{
                      critical: vulns.filter(v => v.severity === 'critical').length,
                      high: vulns.filter(v => v.severity === 'high').length,
                      medium: vulns.filter(v => v.severity === 'medium').length,
                      low: vulns.filter(v => v.severity === 'low').length,
                      info: 0,
                    }}
                  />
                )}
              </div>
            ) : (
              <Loading text="Loading agent details..." />
            )}
          </div>
        </div>
      )}

      {/* Enroll Modal */}
      {showEnroll && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowEnroll(false)}>
          <div className="bg-white rounded-modal shadow-modal w-full max-w-lg p-6 space-y-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-lg font-bold text-gray-800">Deploy AEGIS Agent</h2>
            <div className="flex gap-2">
              {['linux', 'windows', 'macos'].map(p => (
                <button key={p} onClick={() => setPlatform(p)} className={`text-sm px-4 py-1.5 rounded-full border transition-colors ${
                  platform === p ? 'border-brand-500 bg-brand-50 text-brand-700' : 'border-gray-200 text-gray-500 hover:border-gray-300'
                }`}>{p === 'darwin' ? 'macOS' : p === 'windows' ? 'Windows' : 'Linux'}</button>
              ))}
            </div>
            <Button onClick={getEnrollCmd} className="w-full">
              <Terminal className="w-4 h-4" /> Generate Enrollment Command
            </Button>
            {enrollCmd && (
              <div className="space-y-2">
                <div className="bg-gray-900 rounded-lg p-3 relative">
                  <code className="text-xs text-green-400 break-all">{enrollCmd.command}</code>
                  <button onClick={copyCommand} className="absolute top-2 right-2 p-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-300">
                    {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-amber-600 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> Agent key shown only once. Save it securely.
                </p>
                <div className="bg-blue-50 rounded-lg p-3 text-xs text-blue-700">
                  <strong>Agent Key:</strong> <code className="text-blue-900">{enrollCmd.agent_key}</code>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
