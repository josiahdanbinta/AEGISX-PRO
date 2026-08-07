import { useState, useEffect, useCallback } from "react";
import {
  Settings, User, Shield, Bell, Key, Building, Server,
  Save, Plus, Copy, RefreshCw, Trash2, CheckCircle, XCircle,
  AlertTriangle, AlertCircle, Clock, Eye, EyeOff, Smartphone,
  MessageSquare, AtSign, CopyCheck, QrCode, Monitor, Globe,
  Database, Activity, Cpu, HardDrive,
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Input } from "@/components/ui/Input";
import { Loading } from "@/components/ui/Loading";
import { Modal } from "@/components/ui/Modal";
import { api } from "@/services/api";

interface UserProfile {
  full_name: string;
  email: string;
  phone: string;
  avatar_url?: string;
}

interface SecurityInfo {
  mfa_enabled: boolean;
  mfa_qr_url?: string;
  sso_providers: string[];
}

interface SessionItem {
  id: string;
  device: string;
  ip_address: string;
  location: string;
  last_active: string;
  current: boolean;
}

interface APIKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
  permissions: string[];
}

interface OrgInfo {
  tenant_name: string;
  display_name: string;
  domain?: string;
  subscription_tier: string;
  quota_assets: number;
  quota_users: number;
  quota_storage_gb: number;
  contact_email?: string;
}

interface SystemHealth {
  database: string;
  redis: string;
  opensearch: string;
  version: string;
  api_endpoint: string;
  uptime_hours: number;
}

interface NotificationPrefs {
  email_enabled: boolean;
  sms_enabled: boolean;
  slack_enabled: boolean;
  teams_enabled: boolean;
  severity_threshold: string;
  quiet_hours_start: string;
  quiet_hours_end: string;
}

type SettingsTab = "profile" | "security" | "notifications" | "api_keys" | "organization" | "system";

const healthColor: Record<string, string> = {
  green: "bg-emerald-500",
  yellow: "bg-amber-500",
  red: "bg-red-500",
  grey: "bg-slate-300",
};

const healthBadgeVariant: Record<string, "success" | "warning" | "danger" | "default"> = {
  green: "success",
  yellow: "warning",
  red: "danger",
  grey: "default",
};

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("profile");

  const [profile, setProfile] = useState<UserProfile>({ full_name: "", email: "", phone: "" });
  const [profileLoading, setProfileLoading] = useState(true);
  const [profileSaving, setProfileSaving] = useState(false);

  const [security, setSecurity] = useState<SecurityInfo>({ mfa_enabled: false, sso_providers: [] });
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [securityLoading, setSecurityLoading] = useState(true);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwordForm, setPasswordForm] = useState({ current: "", new: "", confirm: "" });
  const [passwordError, setPasswordError] = useState<string | null>(null);

  const [notifications, setNotifications] = useState<NotificationPrefs>({
    email_enabled: true, sms_enabled: false, slack_enabled: false, teams_enabled: false,
    severity_threshold: "medium", quiet_hours_start: "", quiet_hours_end: "",
  });
  const [notificationsSaving, setNotificationsSaving] = useState(false);

  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [apiKeysLoading, setApiKeysLoading] = useState(true);
  const [showGenerateKey, setShowGenerateKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [keyCopied, setKeyCopied] = useState(false);

  const [orgInfo, setOrgInfo] = useState<OrgInfo | null>(null);
  const [orgLoading, setOrgLoading] = useState(true);

  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  useEffect(() => {
    api.get<UserProfile>("/settings/profile")
      .then((res) => setProfile(res))
      .catch(() => {})
      .finally(() => setProfileLoading(false));
  }, []);

  const loadSecurity = useCallback(() => {
    setSecurityLoading(true);
    Promise.all([
      api.get<SecurityInfo>("/settings/security"),
      api.get<SessionItem[]>("/settings/sessions"),
    ])
      .then(([sec, sess]) => { setSecurity(sec); setSessions(sess); })
      .catch(() => {})
      .finally(() => setSecurityLoading(false));
  }, []);

  useEffect(() => {
    if (activeTab === "security") loadSecurity();
  }, [activeTab, loadSecurity]);

  useEffect(() => {
    if (activeTab === "api_keys") {
      setApiKeysLoading(true);
      api.get<APIKey[]>("/settings/api-keys")
        .then((res) => setApiKeys(res))
        .catch(() => {})
        .finally(() => setApiKeysLoading(false));
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === "organization") {
      setOrgLoading(true);
      api.get<OrgInfo>("/settings/organization")
        .then((res) => setOrgInfo(res))
        .catch(() => {})
        .finally(() => setOrgLoading(false));
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === "system") {
      setHealthLoading(true);
      api.get<SystemHealth>("/settings/system-health")
        .then((res) => setSystemHealth(res))
        .catch(() => {})
        .finally(() => setHealthLoading(false));
    }
  }, [activeTab]);

  const saveProfile = async () => {
    setProfileSaving(true);
    try {
      await api.put("/settings/profile", profile);
    } catch (_) {}
    setProfileSaving(false);
  };

  const changePassword = async () => {
    if (passwordForm.new !== passwordForm.confirm) {
      setPasswordError("Passwords do not match");
      return;
    }
    if (passwordForm.new.length < 8) {
      setPasswordError("Password must be at least 8 characters");
      return;
    }
    setPasswordError(null);
    try {
      await api.put("/settings/password", {
        current_password: passwordForm.current,
        new_password: passwordForm.new,
      });
      setShowPasswordForm(false);
      setPasswordForm({ current: "", new: "", confirm: "" });
    } catch (err: unknown) {
      setPasswordError((err as { error?: { message?: string } })?.error?.message || "Password change failed");
    }
  };

  const toggleMFA = async () => {
    try {
      const res = await api.post<SecurityInfo>("/settings/mfa/toggle");
      setSecurity(res);
    } catch (_) {}
  };

  const revokeSession = async (id: string) => {
    try {
      await api.delete("/settings/sessions/" + id);
      setSessions((prev) => prev.filter((s) => s.id !== id));
    } catch (_) {}
  };

  const saveNotifications = async () => {
    setNotificationsSaving(true);
    try {
      await api.put("/settings/notifications", notifications);
    } catch (_) {}
    setNotificationsSaving(false);
  };

  const generateAPIKey = async () => {
    if (!newKeyName) return;
    try {
      const res = await api.post<{ key: string; key_info: APIKey }>("/settings/api-keys", { name: newKeyName });
      setGeneratedKey(res.key);
      setApiKeys((prev) => [...prev, res.key_info]);
    } catch (_) {}
  };

  const deleteAPIKey = async (id: string) => {
    try {
      await api.delete("/settings/api-keys/" + id);
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (_) {}
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setKeyCopied(true);
    setTimeout(() => setKeyCopied(false), 3000);
  };

  const renderHealthDot = (status: string) => (
    <div className="flex items-center gap-2">
      <span className={"w-2.5 h-2.5 rounded-full " + (healthColor[status] || healthColor.grey)} />
      <Badge variant={healthBadgeVariant[status] || "default"} size="sm">
        {status === "green" ? "Healthy" : status === "yellow" ? "Degraded" : status === "red" ? "Down" : "Unknown"}
      </Badge>
    </div>
  );

  const tabs: { key: SettingsTab; label: string; icon: typeof Settings }[] = [
    { key: "profile", label: "Profile", icon: User },
    { key: "security", label: "Security", icon: Shield },
    { key: "notifications", label: "Notifications", icon: Bell },
    { key: "api_keys", label: "API Keys", icon: Key },
    { key: "organization", label: "Organization", icon: Building },
    { key: "system", label: "System", icon: Server },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
        <p className="text-sm text-slate-500 mt-1">Manage your account and platform configuration</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="space-y-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={
                  "w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors " +
                  (activeTab === tab.key
                    ? "bg-brand-50 text-brand-700"
                    : "text-slate-600 hover:bg-slate-50 hover:text-slate-900")
                }
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>

        <div className="lg:col-span-3 space-y-6">
          {activeTab === "profile" && (
            <Card>
              <CardHeader>
                <CardTitle>Profile Information</CardTitle>
              </CardHeader>
              {profileLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loading size="sm" text="Loading profile..." />
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-4 mb-4">
                    <div className="w-16 h-16 rounded-full bg-brand-100 flex items-center justify-center text-brand-700 font-bold text-xl">
                      {profile.full_name.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2)}
                    </div>
                    <div>
                      <p className="font-medium text-slate-900">{profile.full_name}</p>
                      <p className="text-sm text-slate-500">{profile.email}</p>
                    </div>
                  </div>
                  <Input label="Full Name" value={profile.full_name} onChange={(e) => setProfile((p) => ({ ...p, full_name: e.target.value }))} />
                  <Input label="Email" type="email" value={profile.email} onChange={(e) => setProfile((p) => ({ ...p, email: e.target.value }))} />
                  <Input label="Phone" type="tel" value={profile.phone} onChange={(e) => setProfile((p) => ({ ...p, phone: e.target.value }))} placeholder="+1 (555) 123-4567" />
                  <div className="flex justify-end">
                    <Button onClick={saveProfile} loading={profileSaving}>
                      <Save className="w-4 h-4" />
                      Save Changes
                    </Button>
                  </div>
                </div>
              )}
            </Card>
          )}

          {activeTab === "security" && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Change Password</CardTitle>
                </CardHeader>
                {!showPasswordForm ? (
                  <Button variant="secondary" onClick={() => setShowPasswordForm(true)}>
                    Change Password
                  </Button>
                ) : (
                  <div className="space-y-4">
                    <Input label="Current Password" type="password" value={passwordForm.current} onChange={(e) => setPasswordForm((p) => ({ ...p, current: e.target.value }))} />
                    <Input label="New Password" type="password" value={passwordForm.new} onChange={(e) => setPasswordForm((p) => ({ ...p, new: e.target.value }))} />
                    <Input label="Confirm New Password" type="password" value={passwordForm.confirm} onChange={(e) => setPasswordForm((p) => ({ ...p, confirm: e.target.value }))} />
                    {passwordError && <p className="text-xs text-red-600">{passwordError}</p>}
                    <div className="flex items-center gap-2">
                      <Button onClick={changePassword}>Update Password</Button>
                      <Button variant="ghost" onClick={() => { setShowPasswordForm(false); setPasswordError(null); setPasswordForm({ current: "", new: "", confirm: "" }); }}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Multi-Factor Authentication</CardTitle>
                  <Badge variant={security.mfa_enabled ? "success" : "default"} size="sm">
                    {security.mfa_enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </CardHeader>
                {securityLoading ? (
                  <Loading size="sm" />
                ) : (
                  <div className="space-y-3">
                    {security.mfa_qr_url && !security.mfa_enabled && (
                      <div className="flex items-start gap-4 p-4 bg-brand-50 rounded-lg">
                        <QrCode className="w-10 h-10 text-brand-600 flex-shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-slate-900">Setup MFA</p>
                          <p className="text-xs text-slate-600 mt-1">Scan this QR code with your authenticator app</p>
                          <code className="block mt-2 text-xs bg-white px-3 py-2 rounded border border-brand-200 font-mono text-slate-700 break-all">
                            {security.mfa_qr_url}
                          </code>
                        </div>
                      </div>
                    )}
                    <Button onClick={toggleMFA} variant={security.mfa_enabled ? "danger" : "primary"}>
                      {security.mfa_enabled ? "Disable MFA" : "Enable MFA"}
                    </Button>
                  </div>
                )}
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Active Sessions</CardTitle>
                  <span className="text-xs text-slate-400">{sessions.length} session{sessions.length !== 1 ? "s" : ""}</span>
                </CardHeader>
                {securityLoading ? (
                  <Loading size="sm" text="Loading sessions..." />
                ) : sessions.length === 0 ? (
                  <p className="text-sm text-slate-400 py-4">No active sessions found</p>
                ) : (
                  <div className="space-y-2">
                    {sessions.map((session) => (
                      <div key={session.id} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Monitor className="w-4 h-4 text-slate-400" />
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-medium text-slate-900">{session.device}</p>
                              {session.current && <Badge variant="success" size="sm">Current</Badge>}
                            </div>
                            <p className="text-xs text-slate-400">
                              {session.ip_address} - {session.location} - Active: {new Date(session.last_active).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        {!session.current && (
                          <Button variant="danger" size="sm" onClick={() => revokeSession(session.id)}>
                            <Trash2 className="w-3.5 h-3.5" />
                            Revoke
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>SSO Providers</CardTitle>
                </CardHeader>
                {security.sso_providers.length === 0 ? (
                  <p className="text-sm text-slate-400">No SSO providers configured</p>
                ) : (
                  <div className="space-y-2">
                    {security.sso_providers.map((provider) => (
                      <div key={provider} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-brand-600" />
                          <span className="text-sm font-medium text-slate-900 capitalize">{provider}</span>
                        </div>
                        <Badge variant="success" size="sm">Connected</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {activeTab === "notifications" && (
            <Card>
              <CardHeader>
                <CardTitle>Notification Preferences</CardTitle>
              </CardHeader>
              <div className="space-y-6">
                <div className="space-y-3">
                  <p className="text-sm font-medium text-slate-700">Channels</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      { key: "email_enabled", label: "Email", icon: AtSign },
                      { key: "sms_enabled", label: "SMS", icon: Smartphone },
                      { key: "slack_enabled", label: "Slack", icon: MessageSquare },
                      { key: "teams_enabled", label: "Microsoft Teams", icon: MessageSquare },
                    ].map((channel) => {
                      const ChannelIcon = channel.icon;
                      const enabled = !!(notifications as unknown as Record<string, boolean>)[channel.key];
                      return (
                        <div key={channel.key} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg">
                          <div className="flex items-center gap-3">
                            <div className={"p-2 rounded-lg " + (enabled ? "bg-brand-50" : "bg-slate-100")}>
                              <ChannelIcon className={"w-4 h-4 " + (enabled ? "text-brand-600" : "text-slate-400")} />
                            </div>
                            <span className="text-sm font-medium text-slate-900">{channel.label}</span>
                          </div>
                          <button
                            onClick={() =>
                              setNotifications((p: NotificationPrefs) => ({ ...p, [channel.key]: !(p as unknown as Record<string, boolean>)[channel.key] }))
                            }
                            className={
                              "relative w-10 h-6 rounded-full transition-colors " +
                              (enabled ? "bg-brand-600" : "bg-slate-200")
                            }
                          >
                            <span
                              className={
                                "absolute top-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-transform " +
                                (enabled ? "translate-x-[18px]" : "translate-x-0.5")
                              }
                            />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Alert Severity Threshold</label>
                  <select
                    value={notifications.severity_threshold}
                    onChange={(e) => setNotifications((p) => ({ ...p, severity_threshold: e.target.value }))}
                    className="w-full bg-white border border-slate-200 rounded-lg px-3 py-2 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500 cursor-pointer"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                  <p className="text-xs text-slate-400 mt-1">Only alerts at or above this severity will trigger notifications</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <Input
                    label="Quiet Hours Start"
                    type="time"
                    value={notifications.quiet_hours_start}
                    onChange={(e) => setNotifications((p) => ({ ...p, quiet_hours_start: e.target.value }))}
                  />
                  <Input
                    label="Quiet Hours End"
                    type="time"
                    value={notifications.quiet_hours_end}
                    onChange={(e) => setNotifications((p) => ({ ...p, quiet_hours_end: e.target.value }))}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <Button variant="secondary" size="sm">
                    <Bell className="w-4 h-4" />
                    Test Notification
                  </Button>
                  <Button onClick={saveNotifications} loading={notificationsSaving}>
                    <Save className="w-4 h-4" />
                    Save Preferences
                  </Button>
                </div>
              </div>
            </Card>
          )}

          {activeTab === "api_keys" && (
            <Card>
              <CardHeader>
                <CardTitle>API Keys</CardTitle>
                <Button size="sm" onClick={() => { setShowGenerateKey(true); setGeneratedKey(null); setNewKeyName(""); }}>
                  <Plus className="w-4 h-4" />
                  Generate New Key
                </Button>
              </CardHeader>
              {apiKeysLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loading size="sm" text="Loading API keys..." />
                </div>
              ) : apiKeys.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 gap-3">
                  <Key className="w-10 h-10 text-slate-300" />
                  <p className="text-slate-500 font-medium">No API keys generated</p>
                  <p className="text-sm text-slate-400">Create an API key for programmatic access</p>
                  <Button variant="secondary" size="sm" onClick={() => { setShowGenerateKey(true); setGeneratedKey(null); setNewKeyName(""); }}>
                    <Plus className="w-4 h-4" />
                    Generate Key
                  </Button>
                </div>
              ) : (
                <div className="space-y-2">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="flex items-center justify-between p-3 border border-slate-200 rounded-lg">
                      <div>
                        <p className="text-sm font-medium text-slate-900">{key.name}</p>
                        <p className="text-xs text-slate-400">
                          <code className="font-mono">{key.prefix}...</code>
                          {" - Created " + new Date(key.created_at).toLocaleDateString()}
                          {key.last_used_at && " - Last used: " + new Date(key.last_used_at).toLocaleDateString()}
                          {key.expires_at && " - Expires: " + new Date(key.expires_at).toLocaleDateString()}
                        </p>
                      </div>
                      <Button variant="danger" size="sm" onClick={() => deleteAPIKey(key.id)}>
                        <Trash2 className="w-3.5 h-3.5" />
                        Revoke
                      </Button>
                    </div>
                  ))}
                </div>
              )}

              <Modal open={showGenerateKey} onClose={() => { if (!generatedKey) setShowGenerateKey(false); else { setShowGenerateKey(false); setGeneratedKey(null); } }} title="Generate API Key" size="md">
                {!generatedKey ? (
                  <div className="space-y-4">
                    <Input label="Key Name" placeholder="e.g. CI/CD Pipeline" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} />
                    <div className="flex items-center justify-end gap-2">
                      <Button variant="secondary" onClick={() => setShowGenerateKey(false)}>Cancel</Button>
                      <Button onClick={generateAPIKey} disabled={!newKeyName}>
                        <Plus className="w-4 h-4" />
                        Generate
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-amber-800">Copy this key now</p>
                          <p className="text-xs text-amber-700 mt-1">You will not be able to see it again. Store it securely.</p>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 bg-slate-100 px-3 py-2 rounded-lg text-sm font-mono text-slate-700 break-all select-all">
                        {generatedKey}
                      </code>
                      <Button variant="secondary" size="sm" onClick={() => copyToClipboard(generatedKey)}>
                        {keyCopied ? <CopyCheck className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        {keyCopied ? "Copied" : "Copy"}
                      </Button>
                    </div>
                    <div className="flex justify-end">
                      <Button onClick={() => { setShowGenerateKey(false); setGeneratedKey(null); }}>
                        Done
                      </Button>
                    </div>
                  </div>
                )}
              </Modal>
            </Card>
          )}

          {activeTab === "organization" && (
            <Card>
              <CardHeader>
                <CardTitle>Organization Information</CardTitle>
              </CardHeader>
              {orgLoading ? (
                <div className="flex items-center justify-center py-12">
                  <Loading size="sm" text="Loading organization..." />
                </div>
              ) : orgInfo ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <span className="text-xs font-medium text-slate-500 uppercase">Tenant Name</span>
                      <p className="text-sm font-medium text-slate-900 mt-0.5">{orgInfo.tenant_name}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-slate-500 uppercase">Display Name</span>
                      <p className="text-sm font-medium text-slate-900 mt-0.5">{orgInfo.display_name}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-slate-500 uppercase">Domain</span>
                      <p className="text-sm font-medium text-slate-900 mt-0.5">{orgInfo.domain || "--"}</p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-slate-500 uppercase">Subscription Tier</span>
                      <p className="text-sm font-medium text-slate-900 mt-0.5 capitalize">{orgInfo.subscription_tier}</p>
                    </div>
                  </div>

                  <div>
                    <p className="text-sm font-medium text-slate-700 mb-3">Quotas</p>
                    <div className="grid grid-cols-3 gap-4">
                      <div className="p-3 bg-slate-50 rounded-lg text-center">
                        <p className="text-xs text-slate-500">Assets</p>
                        <p className="text-lg font-bold text-slate-900">{orgInfo.quota_assets.toLocaleString()}</p>
                      </div>
                      <div className="p-3 bg-slate-50 rounded-lg text-center">
                        <p className="text-xs text-slate-500">Users</p>
                        <p className="text-lg font-bold text-slate-900">{orgInfo.quota_users.toLocaleString()}</p>
                      </div>
                      <div className="p-3 bg-slate-50 rounded-lg text-center">
                        <p className="text-xs text-slate-500">Storage</p>
                        <p className="text-lg font-bold text-slate-900">{orgInfo.quota_storage_gb} GB</p>
                      </div>
                    </div>
                  </div>

                  <div>
                    <span className="text-xs font-medium text-slate-500 uppercase">Contact Email</span>
                    <p className="text-sm font-medium text-slate-900 mt-0.5">{orgInfo.contact_email || "--"}</p>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-400">No organization data available</p>
              )}
            </Card>
          )}

          {activeTab === "system" && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>System Health</CardTitle>
                </CardHeader>
                {healthLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <Loading size="sm" text="Checking system health..." />
                  </div>
                ) : systemHealth ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="flex items-center justify-between p-4 border border-slate-200 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Database className="w-5 h-5 text-slate-500" />
                          <span className="text-sm font-medium text-slate-900">Database</span>
                        </div>
                        {renderHealthDot(systemHealth.database)}
                      </div>
                      <div className="flex items-center justify-between p-4 border border-slate-200 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Cpu className="w-5 h-5 text-slate-500" />
                          <span className="text-sm font-medium text-slate-900">Redis</span>
                        </div>
                        {renderHealthDot(systemHealth.redis)}
                      </div>
                      <div className="flex items-center justify-between p-4 border border-slate-200 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Activity className="w-5 h-5 text-slate-500" />
                          <span className="text-sm font-medium text-slate-900">OpenSearch</span>
                        </div>
                        {renderHealthDot(systemHealth.opensearch)}
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-slate-400">Unable to fetch system health</p>
                )}
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Version & Endpoints</CardTitle>
                </CardHeader>
                {healthLoading ? (
                  <Loading size="sm" />
                ) : systemHealth ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <span className="text-xs font-medium text-slate-500 uppercase">Platform Version</span>
                        <p className="text-sm font-medium text-slate-900 mt-0.5">{systemHealth.version}</p>
                      </div>
                      <div>
                        <span className="text-xs font-medium text-slate-500 uppercase">Uptime</span>
                        <p className="text-sm font-medium text-slate-900 mt-0.5">{systemHealth.uptime_hours.toLocaleString()} hours</p>
                      </div>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-slate-500 uppercase">API Endpoint</span>
                      <code className="block mt-1 bg-slate-100 px-3 py-2 rounded-lg text-sm font-mono text-slate-700 break-all">
                        {systemHealth.api_endpoint}
                      </code>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-slate-400">No version data available</p>
                )}
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
