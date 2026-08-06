import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { AppLayout } from '@/components/layout/AppLayout';
import { LoginPage } from '@/pages/auth/LoginPage';
import { ExecutiveDashboard } from '@/pages/dashboard/ExecutiveDashboard';
import { SOCDashboard } from '@/pages/dashboard/SOCDashboard';
import { AssetListPage } from '@/pages/assets/AssetListPage';
import { AssetDetailPage } from '@/pages/assets/AssetDetailPage';
import { IncidentListPage } from '@/pages/incidents/IncidentListPage';
import { IncidentDetailPage } from '@/pages/incidents/IncidentDetailPage';
import { AlertsPage } from '@/pages/alerts/AlertsPage';
import { ThreatIntelPage } from '@/pages/threat_intel/ThreatIntelPage';
import { VulnerabilitiesPage } from '@/pages/vulnerabilities/VulnerabilitiesPage';
import { CompliancePage } from '@/pages/compliance/CompliancePage';
import { ReportsPage } from '@/pages/reports/ReportsPage';
import { PlaybooksPage } from '@/pages/soar/PlaybooksPage';
import { UsersPage } from '@/pages/admin/UsersPage';
import { TenantListPage } from '@/pages/admin/TenantListPage';
import { AuditLogsPage } from '@/pages/admin/AuditLogsPage';
import { SettingsPage } from '@/pages/settings/SettingsPage';
import { Loading } from '@/components/ui/Loading';
import { Server } from 'lucide-react';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return <Loading fullScreen />;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <AppLayout>{children}</AppLayout>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  if (isLoading) return <Loading fullScreen />;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />
      <Route path="/dashboard" element={<ProtectedRoute><ExecutiveDashboard /></ProtectedRoute>} />
      <Route path="/soc" element={<ProtectedRoute><SOCDashboard /></ProtectedRoute>} />

      {/* Asset routes */}
      <Route path="/assets" element={<ProtectedRoute><AssetListPage /></ProtectedRoute>} />
      <Route path="/assets/:id" element={<ProtectedRoute><AssetDetailPage /></ProtectedRoute>} />

      <Route path="/incidents" element={<ProtectedRoute><IncidentListPage /></ProtectedRoute>} />
      <Route path="/incidents/:id" element={<ProtectedRoute><IncidentDetailPage /></ProtectedRoute>} />
      <Route path="/detection" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />
      <Route path="/soar" element={<ProtectedRoute><PlaybooksPage /></ProtectedRoute>} />
      <Route path="/threat-intel" element={<ProtectedRoute><ThreatIntelPage /></ProtectedRoute>} />
      <Route path="/vulnerabilities" element={<ProtectedRoute><VulnerabilitiesPage /></ProtectedRoute>} />
      <Route path="/compliance" element={<ProtectedRoute><CompliancePage /></ProtectedRoute>} />
      <Route path="/reports" element={<ProtectedRoute><ReportsPage /></ProtectedRoute>} />
      <Route path="/admin/users" element={<ProtectedRoute><UsersPage /></ProtectedRoute>} />
      <Route path="/admin/tenants" element={<ProtectedRoute><TenantListPage /></ProtectedRoute>} />
      <Route path="/admin/audit" element={<ProtectedRoute><AuditLogsPage /></ProtectedRoute>} />
      <Route path="/deploy" element={<ProtectedRoute><DeploymentPage /></ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />

      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

function PlaceholderPage({ title, icon }: { title: string; icon?: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full py-32">
      <div className="w-16 h-16 rounded-2xl bg-brand-50 flex items-center justify-center mb-6">
        <Server className="w-8 h-8 text-brand-500" />
      </div>
      <h1 className="text-2xl font-bold text-slate-900 mb-2">{title}</h1>
      <p className="text-slate-500">This page is under construction</p>
    </div>
  );
}

function DeploymentPage() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Agent Deployment</h1>
        <p className="text-sm text-slate-500 mt-1">Deploy the AEGISX agent on your endpoints</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <DeploymentCard
          os="Windows"
          description="Deploy on Windows 10/11 and Server 2019+"
          commands={[
            { label: 'PowerShell', cmd: `Invoke-WebRequest -Uri "http://${window.location.hostname}:8000/deploy/install.ps1" -OutFile install.ps1; .\\install.ps1 -Server "http://${window.location.hostname}:8000" -Key "YOUR_REGISTRATION_KEY" -Tenant "YOUR_TENANT_ID"` },
            { label: 'CMD (Quick)', cmd: `curl -o install.cmd http://${window.location.hostname}:8000/deploy/install.cmd && install.cmd "http://${window.location.hostname}:8000" "YOUR_KEY" "YOUR_TENANT"` },
            { label: 'Installer (.exe)', cmd: `Download AEGISX-Agent-Setup.exe from the releases page and run it. Enter your server URL, registration key, and tenant ID when prompted.` },
          ]}
        />
        <DeploymentCard
          os="Linux"
          description="Deploy on Ubuntu, Debian, RHEL, CentOS, Fedora"
          commands={[
            { label: 'cURL (Recommended)', cmd: `curl -sSL http://${window.location.hostname}:8000/deploy/install.sh | sudo bash -s -- --server http://${window.location.hostname}:8000 --key YOUR_REGISTRATION_KEY --tenant YOUR_TENANT_ID` },
            { label: '.deb Package', cmd: `wget http://${window.location.hostname}:8000/deploy/aegisx-agent.deb && sudo dpkg -i aegisx-agent.deb && sudo aegisx-agent register --server http://${window.location.hostname}:8000 --key YOUR_KEY --tenant YOUR_TENANT` },
            { label: '.rpm Package', cmd: `wget http://${window.location.hostname}:8000/deploy/aegisx-agent.rpm && sudo rpm -i aegisx-agent.rpm && sudo aegisx-agent register --server http://${window.location.hostname}:8000 --key YOUR_KEY --tenant YOUR_TENANT` },
          ]}
        />
        <DeploymentCard
          os="macOS"
          description="Deploy on macOS 12+ (Monterey and later)"
          commands={[
            { label: 'cURL (Recommended)', cmd: `curl -sSL http://${window.location.hostname}:8000/deploy/install.sh | bash -s -- --server http://${window.location.hostname}:8000 --key YOUR_REGISTRATION_KEY --tenant YOUR_TENANT_ID` },
            { label: 'Homebrew', cmd: `brew install aegisx/tap/aegisx-agent && aegisx-agent register --server http://${window.location.hostname}:8000 --key YOUR_KEY --tenant YOUR_TENANT` },
            { label: '.pkg Installer', cmd: `Download AEGISX-Agent.pkg. Double-click to install, then run: aegisx-agent register --server http://${window.location.hostname}:8000 --key YOUR_KEY --tenant YOUR_TENANT` },
          ]}
        />
        <DeploymentCard
          os="Docker / Kubernetes"
          description="Deploy as container for Docker and Kubernetes environments"
          commands={[
            { label: 'Docker', cmd: `docker run -d --name aegisx-agent --restart always -e AEGISX_SERVER=http://${window.location.hostname}:8000 -e AEGISX_KEY=YOUR_KEY -e AEGISX_TENANT=YOUR_TENANT ghcr.io/org/aegisx-agent:latest` },
            { label: 'Kubernetes', cmd: `kubectl apply -f http://${window.location.hostname}:8000/deploy/k8s-agent.yaml` },
          ]}
        />
      </div>

      <div className="bg-brand-50 border border-brand-200 rounded-xl p-6">
        <div className="flex items-start gap-4">
          <div className="p-2 bg-brand-100 rounded-lg">
            <Server className="w-5 h-5 text-brand-700" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-900 mb-1">System Connection Info</h3>
            <p className="text-sm text-slate-600">
              AEGISX Dashboard is running on <code className="bg-white px-1.5 py-0.5 rounded text-sm font-mono text-brand-700">{window.location.hostname}:{window.location.port || '3000'}</code>
            </p>
            <p className="text-sm text-slate-600 mt-1">
              Agent enrollment endpoint: <code className="bg-white px-1.5 py-0.5 rounded text-sm font-mono text-brand-700">http://{window.location.hostname}:8000/api/v1/agent/register</code>
            </p>
            <p className="text-xs text-slate-500 mt-2">
              Replace <code className="bg-white px-1 py-0.5 rounded text-xs">YOUR_REGISTRATION_KEY</code> and <code className="bg-white px-1 py-0.5 rounded text-xs">YOUR_TENANT_ID</code> with values from your tenant settings page.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function DeploymentCard({ os, description, commands }: {
  os: string;
  description: string;
  commands: Array<{ label: string; cmd: string }>;
}) {
  const [copied, setCopied] = React.useState<number | null>(null);

  const copyCommand = (idx: number, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(idx);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="card p-5">
      <h3 className="text-lg font-semibold text-slate-900 mb-1">{os}</h3>
      <p className="text-sm text-slate-500 mb-4">{description}</p>
      <div className="space-y-3">
        {commands.map((c, i) => (
          <div key={i}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-slate-600">{c.label}</span>
              <button
                onClick={() => copyCommand(i, c.cmd)}
                className="text-xs text-brand-600 hover:text-brand-700 font-medium"
              >
                {copied === i ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <pre className="bg-slate-900 text-emerald-400 text-xs p-3 rounded-lg overflow-x-auto font-mono whitespace-pre-wrap break-all">
              {c.cmd}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}
