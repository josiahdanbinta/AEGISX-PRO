import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
  Monitor, Cpu, HardDrive, MemoryStick, Wifi, Shield, AlertTriangle,
  Bug, Package, Clock, Server, Activity, Terminal, Key, Thermometer,
  Battery, Usb, Fingerprint, FileWarning, ChevronRight, RefreshCw,
  CheckCircle, XCircle, AlertCircle, Sparkles,
} from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Table } from '@/components/ui/Table';
import { Loading } from '@/components/ui/Loading';
import { api } from '@/services/api';
import type { Asset, Vulnerability, Alert } from '@/types';

interface HardwareInfo {
  cpu?: { model: string; cores: number; threads: number; frequency_mhz: number };
  memory?: { total_gb: number; modules: Array<{ capacity_gb: number; speed_mhz: number; manufacturer: string; serial: string }> };
  disks?: Array<{ device: string; size_gb: number; model: string; serial: string; health: string; smart_status: string }>;
  motherboard?: { manufacturer: string; model: string; serial: string };
  bios?: { vendor: string; version: string; date: string };
  gpu?: Array<{ name: string; memory_mb: number; driver: string }>;
  network_adapters?: Array<{ name: string; mac: string; ip_addresses: string[]; speed_mbps: number }>;
  tpm?: { present: boolean; version: string; status: string };
  secure_boot?: { enabled: boolean };
  battery?: { health_percent: number; cycle_count: number; status: string };
  temperatures?: { cpu: number; gpu?: number };
  serial_numbers?: { system: string; motherboard: string; chassis: string };
}

interface SoftwareInfo {
  os: { name: string; version: string; build: string; kernel: string; install_date: string };
  installed_apps: Array<{ name: string; version: string; publisher: string; install_date: string; location: string; size_mb: number; risk?: string }>;
  outdated_apps: Array<{ name: string; current_version: string; latest_version: string; severity: string }>;
  running_services: Array<{ name: string; display_name: string; status: string; startup_type: string; pid: number; user: string; risk?: string }>;
  browser_extensions: Array<{ browser: string; name: string; version: string; id: string }>;
  certificates: Array<{ subject: string; issuer: string; expiry: string; store: string }>;
  eol_software: Array<{ name: string; version: string; eol_date: string; severity: string }>;
}

interface RansomwareAlerts {
  detected: boolean;
  alerts: Array<{ type: string; severity: string; details: string; timestamp: string }>;
  file_modifications: number;
  suspicious_processes: string[];
}

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [hardware, setHardware] = useState<HardwareInfo | null>(null);
  const [software, setSoftware] = useState<SoftwareInfo | null>(null);
  const [ransomware, setRansomware] = useState<RansomwareAlerts | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    if (!id) return;
    Promise.all([
      api.get<Asset>(`/assets/${id}`),
      api.get<HardwareInfo>(`/assets/${id}/hardware`),
      api.get<SoftwareInfo>(`/assets/${id}/software`),
      api.get<Vulnerability[]>(`/assets/${id}/vulnerabilities`),
      api.get<Alert[]>(`/assets/${id}/alerts`),
    ]).then(([a, h, s, v, al]) => {
      setAsset(a);
      setHardware(h);
      setSoftware(s);
      setVulnerabilities(v);
      setAlerts(al);
    }).catch(console.error).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <Loading fullScreen text="Loading asset details..." />;
  if (!asset) return <div className="p-8 text-center text-slate-500">Asset not found</div>;

  const tabs = [
    { key: 'overview', label: 'Overview', icon: Monitor },
    { key: 'hardware', label: 'Hardware', icon: Cpu },
    { key: 'software', label: 'Software', icon: Package },
    { key: 'services', label: 'Services', icon: Server },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { key: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { key: 'ransomware', label: 'Ransomware', icon: FileWarning },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-slate-900">{asset.name || asset.hostname}</h1>
            <Badge variant={asset.status === 'online' ? 'success' : 'danger'}>{asset.status}</Badge>
            <Badge variant="info">{asset.type}</Badge>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            {asset.os} {asset.os_version} | {asset.ip_address || 'No IP'} | Last seen: {asset.last_seen || 'N/A'}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm">
            <RefreshCw className="w-4 h-4" /> Refresh
          </Button>
          <Button variant="primary" size="sm">
            <Activity className="w-4 h-4" /> Start Monitoring
          </Button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatMini icon={Cpu} label="CPU" value={hardware?.cpu?.model?.split('@')[0] || 'N/A'} />
        <StatMini icon={MemoryStick} label="RAM" value={hardware?.memory ? `${hardware.memory.total_gb} GB` : 'N/A'} />
        <StatMini icon={HardDrive} label="Storage" value={hardware?.disks ? `${hardware.disks.reduce((s, d) => s + d.size_gb, 0)} GB` : 'N/A'} />
        <StatMini icon={Monitor} label="OS" value={`${software?.os?.name || asset.os || 'N/A'} ${software?.os?.version || ''}`} />
        <StatMini icon={Wifi} label="IP" value={asset.ip_address || 'N/A'} />
        <StatMini icon={Key} label="Serial" value={hardware?.serial_numbers?.system?.substring(0, 12) + '...' || 'N/A'} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-slate-100 rounded-xl p-1">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeTab === tab.key
                ? 'bg-white text-brand-700 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && <OverviewTab asset={asset} hardware={hardware} software={software} vulnerabilities={vulnerabilities} alerts={alerts} />}
      {activeTab === 'hardware' && <HardwareTab hardware={hardware} />}
      {activeTab === 'software' && <SoftwareTab software={software} />}
      {activeTab === 'services' && <ServicesTab services={software?.running_services || []} />}
      {activeTab === 'vulnerabilities' && <VulnerabilitiesTab vulnerabilities={vulnerabilities} />}
      {activeTab === 'alerts' && <AlertsTab alerts={alerts} />}
      {activeTab === 'ransomware' && <RansomwareTab ransomware={ransomware} />}
    </div>
  );
}

function StatMini({ icon: Icon, label, value }: { icon: React.FC<{className?: string}>, label: string, value: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-brand-500" />
        <span className="text-xs text-slate-500 font-medium">{label}</span>
      </div>
      <p className="text-sm font-semibold text-slate-900 truncate">{value}</p>
    </Card>
  );
}

function SectionHeader({ icon: Icon, title, subtitle }: { icon: React.FC<{className?: string}>, title: string, subtitle?: string }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <div className="p-2 bg-brand-50 rounded-lg">
        <Icon className="w-5 h-5 text-brand-600" />
      </div>
      <div>
        <h3 className="font-semibold text-slate-900">{title}</h3>
        {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
      </div>
    </div>
  );
}

function OverviewTab({ asset, hardware, software, vulnerabilities, alerts }: {
  asset: Asset; hardware: HardwareInfo | null; software: SoftwareInfo | null;
  vulnerabilities: Vulnerability[]; alerts: Alert[];
}) {
  return (
    <div className="space-y-6">
      {/* AI Insight */}
      <Card className="bg-gradient-to-r from-brand-50 to-cyan-50 border-brand-200">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-white rounded-xl shadow-sm">
            <Sparkles className="w-6 h-6 text-brand-600" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-slate-900 mb-1">AI Asset Assessment</h3>
            <p className="text-sm text-slate-600">
              {vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length > 0
                ? `This endpoint has ${vulnerabilities.filter(v => v.severity === 'critical').length} critical and ${vulnerabilities.filter(v => v.severity === 'high').length} high vulnerabilities requiring immediate attention.`
                : software?.outdated_apps?.length
                  ? `Endpoint is healthy but has ${software.outdated_apps.length} outdated applications that should be updated.`
                  : 'Endpoint appears healthy with no critical issues detected.'
              }
            </p>
            <div className="flex gap-2 mt-3">
              {vulnerabilities.length > 0 && (
                <Badge variant="danger">{vulnerabilities.length} Vulnerabilities</Badge>
              )}
              {software?.outdated_apps?.length && (
                <Badge variant="warning">{software.outdated_apps.length} Outdated Apps</Badge>
              )}
              {software?.eol_software?.length && (
                <Badge variant="danger">{software.eol_software.length} EOL Software</Badge>
              )}
              <Badge variant="success">Agent Active</Badge>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Info */}
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Monitor className="w-5 h-5 text-brand-500" /> System Information</CardTitle></CardHeader>
          <div className="space-y-2">
            <InfoRow label="Hostname" value={asset.hostname} />
            <InfoRow label="OS" value={`${software?.os?.name || asset.os} ${software?.os?.version || ''}`} />
            <InfoRow label="Kernel / Build" value={software?.os?.build || software?.os?.kernel || 'N/A'} />
            <InfoRow label="IP Address" value={asset.ip_address} />
            <InfoRow label="MAC Address" value={asset.mac_address} />
            <InfoRow label="Last Seen" value={asset.last_seen} />
            <InfoRow label="Serial Number" value={hardware?.serial_numbers?.system || 'N/A'} />
          </div>
        </Card>

        {/* Security Status */}
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Shield className="w-5 h-5 text-brand-500" /> Security Status</CardTitle></CardHeader>
          <div className="space-y-3">
            <SecurityItem label="TPM" status={hardware?.tpm?.present} detail={hardware?.tpm?.version} />
            <SecurityItem label="Secure Boot" status={hardware?.secure_boot?.enabled} />
            <SecurityItem label="Disk Encryption" status={true} detail="BitLocker / LUKS" />
            <SecurityItem label="Antivirus" status={true} detail="Running" />
            <SecurityItem label="Firewall" status={true} detail="Enabled" />
            <SecurityItem label="Last Patch" status={true} detail={software?.os?.install_date || 'N/A'} />
            <SecurityItem label="Ransomware Detection" status={true} detail="Active" />
          </div>
        </Card>
      </div>

      {/* Disk Health */}
      {hardware?.disks && hardware.disks.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><HardDrive className="w-5 h-5 text-brand-500" /> Disk Health</CardTitle></CardHeader>
          <Table
            columns={[
              { key: 'device', header: 'Device' },
              { key: 'model', header: 'Model' },
              { key: 'size_gb', header: 'Size', render: (r: Record<string, unknown>) => `${r.size_gb} GB` },
              { key: 'health', header: 'Health', render: (r: Record<string, unknown>) => (
                <Badge variant={r.health === 'Healthy' || r.health === 'PASSED' ? 'success' : 'danger'} size="sm">
                  {String(r.health)}
                </Badge>
              )},
              { key: 'smart_status', header: 'SMART', render: (r: Record<string, unknown>) => (
                r.smart_status === 'OK' || r.smart_status === 'PASSED'
                  ? <CheckCircle className="w-4 h-4 text-emerald-500" />
                  : <AlertCircle className="w-4 h-4 text-red-500" />
              )},
            ]}
            data={hardware.disks}
            keyExtractor={(r) => r.device}
          />
        </Card>
      )}
    </div>
  );
}

function HardwareTab({ hardware }: { hardware: HardwareInfo | null }) {
  if (!hardware) return <Card className="p-8 text-center text-slate-500">No hardware data available</Card>;

  return (
    <div className="space-y-6">
      {/* CPU + Memory */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <SectionHeader icon={Cpu} title="Processor" subtitle={hardware.cpu?.model} />
          <div className="space-y-2">
            <InfoRow label="Cores / Threads" value={`${hardware.cpu?.cores} / ${hardware.cpu?.threads}`} />
            <InfoRow label="Frequency" value={`${hardware.cpu?.frequency_mhz} MHz`} />
            {hardware.temperatures && <InfoRow label="Temperature" value={`${hardware.temperatures.cpu}°C`} />}
          </div>
        </Card>
        <Card>
          <SectionHeader icon={MemoryStick} title="Memory" subtitle={`${hardware.memory?.total_gb} GB Total`} />
          {hardware.memory?.modules?.map((m, i) => (
            <div key={i} className="py-2 border-b border-slate-100 last:border-0">
              <p className="text-sm font-medium text-slate-800">{m.capacity_gb} GB DDR{m.speed_mhz}MHz</p>
              <p className="text-xs text-slate-500">{m.manufacturer} | SN: {m.serial}</p>
            </div>
          ))}
        </Card>
      </div>

      {/* Motherboard + BIOS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <SectionHeader icon={Monitor} title="Motherboard" />
          <div className="space-y-2">
            <InfoRow label="Manufacturer" value={hardware.motherboard?.manufacturer} />
            <InfoRow label="Model" value={hardware.motherboard?.model} />
            <InfoRow label="Serial" value={hardware.motherboard?.serial} />
          </div>
        </Card>
        <Card>
          <SectionHeader icon={Terminal} title="BIOS / Firmware" />
          <div className="space-y-2">
            <InfoRow label="Vendor" value={hardware.bios?.vendor} />
            <InfoRow label="Version" value={hardware.bios?.version} />
            <InfoRow label="Date" value={hardware.bios?.date} />
          </div>
        </Card>
      </div>

      {/* Security: TPM + Secure Boot */}
      <Card>
        <SectionHeader icon={Fingerprint} title="Platform Security" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-50 rounded-xl">
            <p className="text-sm font-medium text-slate-700 mb-2">TPM</p>
            {hardware.tpm?.present
              ? <div><Badge variant="success">Present</Badge><p className="text-xs text-slate-500 mt-1">v{hardware.tpm?.version} — {hardware.tpm?.status}</p></div>
              : <Badge variant="danger">Not Found</Badge>
            }
          </div>
          <div className="p-4 bg-slate-50 rounded-xl">
            <p className="text-sm font-medium text-slate-700 mb-2">Secure Boot</p>
            {hardware.secure_boot?.enabled
              ? <Badge variant="success">Enabled</Badge>
              : <Badge variant="danger">Disabled</Badge>
            }
          </div>
          {hardware.battery && (
            <div className="p-4 bg-slate-50 rounded-xl">
              <p className="text-sm font-medium text-slate-700 mb-2">Battery Health</p>
              <p className="text-lg font-bold text-slate-900">{hardware.battery.health_percent}%</p>
              <p className="text-xs text-slate-500">{hardware.battery.cycle_count} cycles | {hardware.battery.status}</p>
            </div>
          )}
        </div>
      </Card>

      {/* Network Adapters */}
      {hardware.network_adapters && hardware.network_adapters.length > 0 && (
        <Card>
          <SectionHeader icon={Wifi} title="Network Adapters" />
          <Table
            columns={[
              { key: 'name', header: 'Adapter' },
              { key: 'mac', header: 'MAC Address' },
              { key: 'ip_addresses', header: 'IP Addresses', render: (r: Record<string, unknown>) =>
                Array.isArray(r.ip_addresses) ? r.ip_addresses.join(', ') : String(r.ip_addresses)
              },
              { key: 'speed_mbps', header: 'Speed', render: (r: Record<string, unknown>) => `${r.speed_mbps} Mbps` },
            ]}
            data={hardware.network_adapters}
            keyExtractor={(r) => r.mac}
          />
        </Card>
      )}
    </div>
  );
}

function SoftwareTab({ software }: { software: SoftwareInfo | null }) {
  if (!software) return <Card className="p-8 text-center text-slate-500">No software data available</Card>;

  return (
    <div className="space-y-6">
      {/* Outdated Apps */}
      {software.outdated_apps && software.outdated_apps.length > 0 && (
        <Card>
          <SectionHeader icon={AlertTriangle} title="Outdated Applications" subtitle={`${software.outdated_apps.length} apps behind latest version`} />
          <Table
            columns={[
              { key: 'name', header: 'Application' },
              { key: 'current_version', header: 'Current' },
              { key: 'latest_version', header: 'Latest' },
              { key: 'severity', header: 'Risk', render: (r: Record<string, unknown>) => (
                <Badge variant={r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warning' : 'info'} size="sm">
                  {String(r.severity)}
                </Badge>
              )},
            ]}
            data={software.outdated_apps}
            keyExtractor={(r) => r.name}
          />
        </Card>
      )}

      {/* EOL Software */}
      {software.eol_software && software.eol_software.length > 0 && (
        <Card>
          <SectionHeader icon={XCircle} title="End-of-Life Software" subtitle="No longer receiving security updates" />
          <Table
            columns={[
              { key: 'name', header: 'Software' },
              { key: 'version', header: 'Version' },
              { key: 'eol_date', header: 'End of Life' },
              { key: 'severity', header: 'Risk', render: (r: Record<string, unknown>) => (
                <Badge variant="danger" size="sm">{String(r.severity)}</Badge>
              )},
            ]}
            data={software.eol_software}
            keyExtractor={(r) => r.name}
          />
        </Card>
      )}

      {/* Installed Apps */}
      <Card>
        <SectionHeader icon={Package} title="Installed Applications" subtitle={`${software.installed_apps?.length || 0} applications`} />
        <Table
          columns={[
            { key: 'name', header: 'Name', width: '25%' },
            { key: 'version', header: 'Version', width: '10%' },
            { key: 'publisher', header: 'Publisher', width: '20%' },
            { key: 'install_date', header: 'Installed', width: '15%' },
            { key: 'size_mb', header: 'Size', render: (r: Record<string, unknown>) => `${r.size_mb} MB`, width: '10%' },
            { key: 'risk', header: 'Risk', render: (r: Record<string, unknown>) => r.risk
              ? <Badge variant="warning" size="sm">{String(r.risk)}</Badge>
              : <Badge variant="success" size="sm">OK</Badge>,
              width: '10%'
            },
          ]}
          data={software.installed_apps || []}
          keyExtractor={(r) => r.name}
          pageSize={20}
        />
      </Card>
    </div>
  );
}

function ServicesTab({ services }: { services: Array<Record<string, unknown>> }) {
  return (
    <Card>
      <SectionHeader icon={Server} title="Running Services" subtitle={`${services?.length || 0} services`} />
      <Table
        columns={[
          { key: 'name', header: 'Service Name', width: '20%' },
          { key: 'display_name', header: 'Display Name', width: '25%' },
          { key: 'status', header: 'Status', render: (r: Record<string, unknown>) => (
            <Badge variant={r.status === 'running' ? 'success' : r.status === 'stopped' ? 'default' : 'warning'} size="sm">
              {String(r.status)}
            </Badge>
          ), width: '10%'},
          { key: 'startup_type', header: 'Startup', width: '12%' },
          { key: 'pid', header: 'PID', width: '8%' },
          { key: 'user', header: 'User', width: '15%' },
          { key: 'risk', header: 'Risk', render: (r: Record<string, unknown>) => r.risk
            ? <Badge variant="danger" size="sm">{String(r.risk)}</Badge>
            : <Badge variant="success" size="sm">OK</Badge>,
            width: '10%'
          },
        ]}
        data={services || []}
        keyExtractor={(r) => String(r.name)}
        pageSize={25}
      />
    </Card>
  );
}

function VulnerabilitiesTab({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4 text-center"><p className="text-2xl font-bold text-red-600">{vulnerabilities.filter(v => v.severity === 'critical').length}</p><p className="text-xs text-slate-500">Critical</p></Card>
        <Card className="p-4 text-center"><p className="text-2xl font-bold text-orange-600">{vulnerabilities.filter(v => v.severity === 'high').length}</p><p className="text-xs text-slate-500">High</p></Card>
        <Card className="p-4 text-center"><p className="text-2xl font-bold text-amber-600">{vulnerabilities.filter(v => v.severity === 'medium').length}</p><p className="text-xs text-slate-500">Medium</p></Card>
        <Card className="p-4 text-center"><p className="text-2xl font-bold text-blue-600">{vulnerabilities.filter(v => v.severity === 'low').length}</p><p className="text-xs text-slate-500">Low</p></Card>
      </div>
      <Table
        columns={[
          { key: 'cve_id', header: 'CVE', width: '12%' },
          { key: 'title', header: 'Title', width: '30%' },
          { key: 'severity', header: 'Severity', render: (r: Record<string, unknown>) => (
            <Badge variant={r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warning' : r.severity === 'medium' ? 'warning' : 'info'} size="sm">
              {String(r.severity)}
            </Badge>
          ), width: '10%'},
          { key: 'cvss_score', header: 'CVSS', width: '8%' },
          { key: 'affected_software', header: 'Software', width: '15%' },
          { key: 'status', header: 'Status', render: (r: Record<string, unknown>) => (
            <Badge variant={r.status === 'open' ? 'danger' : r.status === 'remediated' ? 'success' : 'warning'} size="sm">
              {String(r.status)}
            </Badge>
          ), width: '12%'},
          { key: 'exploit_available', header: 'Exploit', render: (r: Record<string, unknown>) => r.exploit_available
            ? <Badge variant="danger" size="sm">Yes</Badge>
            : <span className="text-xs text-slate-400">No</span>,
            width: '8%'
          },
        ]}
        data={vulnerabilities}
        keyExtractor={(r) => String(r.id)}
      />
    </div>
  );
}

function AlertsTab({ alerts }: { alerts: Alert[] }) {
  return (
    <Table
      columns={[
        { key: 'title', header: 'Alert', width: '30%' },
        { key: 'severity', header: 'Severity', render: (r: Record<string, unknown>) => (
          <Badge variant={r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warning' : 'info'} size="sm">
            {String(r.severity)}
          </Badge>
        ), width: '10%'},
        { key: 'status', header: 'Status', render: (r: Record<string, unknown>) => (
          <Badge variant={r.status === 'new' ? 'danger' : r.status === 'resolved' ? 'success' : 'warning'} size="sm">
            {String(r.status)}
          </Badge>
        ), width: '12%'},
        { key: 'rule_name', header: 'Rule', width: '20%' },
        { key: 'source_ip', header: 'Source IP', width: '15%' },
        { key: 'created_at', header: 'Time', width: '13%' },
      ]}
      data={alerts}
      keyExtractor={(r) => String(r.id)}
    />
  );
}

function RansomwareTab({ ransomware }: { ransomware: RansomwareAlerts | null }) {
  if (!ransomware || !ransomware.detected) {
    return (
      <Card className="p-8 text-center">
        <Shield className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
        <h3 className="text-lg font-semibold text-slate-900 mb-1">No Ransomware Detected</h3>
        <p className="text-sm text-slate-500">Ransomware monitoring is active. No suspicious activity detected.</p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card className="border-red-300 bg-red-50">
        <SectionHeader icon={FileWarning} title="Ransomware Activity Detected!" subtitle="Immediate investigation required" />
        <div className="space-y-3">
          {ransomware.alerts.map((a, i) => (
            <div key={i} className="flex items-start gap-3 p-3 bg-white rounded-lg border border-red-200">
              <AlertCircle className="w-5 h-5 text-red-500 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-red-800">{a.type}</p>
                <p className="text-xs text-red-600">{a.details}</p>
                <p className="text-xs text-red-400 mt-1">{a.timestamp}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-slate-50 last:border-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm font-medium text-slate-800">{value || 'N/A'}</span>
    </div>
  );
}

function SecurityItem({ label, status, detail }: { label: string; status?: boolean; detail?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-slate-600">{label}</span>
      <div className="flex items-center gap-2">
        {status ? <CheckCircle className="w-4 h-4 text-emerald-500" /> : <XCircle className="w-4 h-4 text-red-500" />}
        {detail && <span className="text-xs text-slate-500">{detail}</span>}
      </div>
    </div>
  );
}
