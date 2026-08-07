import React, { useState } from 'react';
import {
  Play, Plus, Trash2, GripVertical, Zap, ArrowRight,
  Mail, Bell, MessageSquare, Globe, Shield, Users, AlertTriangle,
  FolderGit2, Terminal, Save, Settings, X, PlayCircle
} from 'lucide-react';
import { Card } from '../../components/ui/Card';
import { Button } from '../../components/ui/Button';
import { Badge } from '../../components/ui/Badge';
import { Input } from '../../components/ui/Input';
import { Modal } from '../../components/ui/Modal';
import { api } from '../../services/api';

const ACTION_TEMPLATES: Record<string, { icon: typeof Play; label: string; description: string; params: Record<string, any> }> = {
  send_email: { icon: Mail, label: 'Send Email', description: 'Notify via email', params: { to: '', subject: '', body: '' } },
  notify_slack: { icon: MessageSquare, label: 'Slack Notification', description: 'Post to Slack', params: { message: '', webhook_url: '', channel: '' } },
  notify_teams: { icon: Play, label: 'Teams Notification', description: 'Post to MS Teams', params: { message: '', webhook_url: '' } },
  webhook: { icon: Globe, label: 'Webhook', description: 'Call external API', params: { url: '', method: 'POST', payload: {} } },
  create_incident: { icon: Shield, label: 'Create Incident', description: 'Open incident', params: { title: '', description: '', severity: 'medium' } },
  update_ticket: { icon: FolderGit2, label: 'Update Ticket', description: 'Update status', params: { ticket_id: '', status: '' } },
  enrich_ip: { icon: Globe, label: 'Enrich IP', description: 'Threat intel for IP', params: { ip_address: '' } },
  enrich_hash: { icon: Zap, label: 'Enrich Hash', description: 'Lookup file hash', params: { hash: '' } },
  enrich_domain: { icon: Globe, label: 'Enrich Domain', description: 'Lookup domain', params: { domain: '' } },
  add_to_watchlist: { icon: AlertTriangle, label: 'Add to Watchlist', description: 'Add IOC', params: { indicator: '', indicator_type: 'ip', severity: 'high' } },
  execute_script: { icon: Terminal, label: 'Execute Script', description: 'Run CLI command', params: { command: '', timeout_seconds: 60 } },
  force_password_reset: { icon: Users, label: 'Force Password Reset', description: 'Force user PW change', params: { user_id: '' } },
  suspend_user: { icon: Users, label: 'Suspend User', description: 'Disable account', params: { user_id: '' } },
  revoke_session: { icon: Users, label: 'Revoke Sessions', description: 'Logout user', params: { user_id: '' } },
};

const TRIGGERS = [
  { value: 'alert', label: 'On Alert' },
  { value: 'incident', label: 'On Incident' },
  { value: 'schedule', label: 'Scheduled' },
  { value: 'manual', label: 'Manual' },
  { value: 'webhook', label: 'Webhook' },
];

interface PlaybookStep {
  id: string;
  action: string;
  name: string;
  params: Record<string, any>;
  condition?: string;
  onFailure: 'stop' | 'continue' | 'retry';
  retryCount: number;
}

export default function PlaybookBuilderPage() {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [triggerType, setTriggerType] = useState('alert');
  const [steps, setSteps] = useState<PlaybookStep[]>([]);
  const [selectedStep, setSelectedStep] = useState<number | null>(null);
  const [showActionPicker, setShowActionPicker] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dragIdx, setDragIdx] = useState<number | null>(null);

  const addStep = (action: string) => {
    const tmpl = ACTION_TEMPLATES[action];
    const step: PlaybookStep = {
      id: `step-${Date.now()}`,
      action,
      name: tmpl?.label || action,
      params: { ...(tmpl?.params || {}) },
      onFailure: 'stop',
      retryCount: 0,
    };
    setSteps((prev) => [...prev, step]);
    setShowActionPicker(false);
    setSelectedStep(steps.length);
  };

  const removeStep = (idx: number) => {
    setSteps((prev) => prev.filter((_, i) => i !== idx));
    setSelectedStep(null);
  };

  const updateStep = (idx: number, updates: Partial<PlaybookStep>) => {
    setSteps((prev) => prev.map((s, i) => (i === idx ? { ...s, ...updates } : s)));
  };

  const moveStep = (from: number, to: number) => {
    if (from === to || to < 0 || to >= steps.length) return;
    const copy = [...steps];
    const [item] = copy.splice(from, 1);
    copy.splice(to, 0, item);
    setSteps(copy);
    setSelectedStep(to);
  };

  const save = async () => {
    if (!name) return;
    setSaving(true);
    try {
      await api.post('/soar/playbooks', {
        name,
        description,
        trigger_type: triggerType,
        steps: steps.map((s, i) => ({
          order: i + 1,
          name: s.name,
          action: s.action,
          parameters: s.params,
          condition: s.condition || null,
          on_failure: s.onFailure,
          retry_count: s.retryCount,
        })),
      });
      window.location.href = '/soar';
    } catch (_) {}
    setSaving(false);
  };

  return (
    <div className="h-full flex flex-col lg:flex-row gap-4 p-4">
      <div className="flex-1 space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-white">Playbook Builder</h1>
          <div className="flex gap-2">
            <Button onClick={save} loading={saving} disabled={!name || steps.length === 0}>
              <Save className="w-4 h-4" /> Save Playbook
            </Button>
          </div>
        </div>

        <Card className="p-4 space-y-3">
          <Input label="Playbook Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Phishing Triage" />
          <div>
            <label className="text-sm font-medium text-gray-300 mb-1 block">Description</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this playbook do?" className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-500 focus:ring-2 focus:ring-blue-500/30 outline-none resize-none" rows={2} />
          </div>
          <div>
            <label className="text-sm font-medium text-gray-300 mb-1 block">Trigger</label>
            <div className="flex gap-2 flex-wrap">
              {TRIGGERS.map((t) => (
                <button key={t.value} onClick={() => setTriggerType(t.value)} className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${triggerType === t.value ? 'border-blue-500 bg-blue-900/40 text-blue-300' : 'border-gray-700 text-gray-400 hover:border-gray-500'}`}>
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        </Card>

        <div className="space-y-1">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Steps ({steps.length})</h2>
            <Button size="sm" onClick={() => setShowActionPicker(true)}>+ Add Step</Button>
          </div>

          {steps.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 border-2 border-dashed border-gray-700 rounded-lg">
              <Zap className="w-8 h-8 text-gray-600 mb-2" />
              <p className="text-sm text-gray-500">Drag steps to reorder, or add your first step</p>
              <Button size="sm" variant="secondary" onClick={() => setShowActionPicker(true)} className="mt-3">Add First Step</Button>
            </div>
          )}

          {steps.map((step, idx) => (
            <div key={step.id}>
              <div
                draggable
                onDragStart={() => setDragIdx(idx)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => { if (dragIdx !== null) moveStep(dragIdx, idx); setDragIdx(null); }}
                onClick={() => setSelectedStep(idx)}
                className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${selectedStep === idx ? 'border-blue-500 bg-blue-900/20' : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'}`}
              >
                <div className="flex items-center gap-2 mt-0.5">
                  <GripVertical className="w-4 h-4 text-gray-600 cursor-grab" />
                  <span className="w-6 h-6 rounded-full bg-blue-900 text-blue-300 flex items-center justify-center text-xs font-bold">{idx + 1}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-200">{step.name}</span>
                    <Badge className="text-[10px] bg-gray-700 text-gray-400">{step.action}</Badge>
                  </div>
                  {Object.keys(step.params).filter((k) => step.params[k] !== '').length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {Object.entries(step.params).filter(([, v]) => v !== '').slice(0, 3).map(([k, v]) => (
                        <span key={k} className="text-[10px] bg-gray-700 px-1.5 py-0.5 rounded text-gray-500">{k}: {typeof v === 'object' ? '...' : String(v).slice(0, 20)}</span>
                      ))}
                    </div>
                  )}
                </div>
                <button onClick={(e) => { e.stopPropagation(); removeStep(idx); }} className="p-1 rounded text-gray-600 hover:text-red-400 transition-colors">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
              {idx < steps.length - 1 && <div className="flex justify-center py-1"><ArrowRight className="w-4 h-4 text-gray-600 rotate-90" /></div>}
            </div>
          ))}
        </div>
      </div>

      {selectedStep !== null && steps[selectedStep] && (
        <div className="w-96 flex-shrink-0">
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-200">Edit Step</h3>
              <button onClick={() => setSelectedStep(null)} className="p-1 rounded text-gray-500 hover:text-gray-300"><X className="w-4 h-4" /></button>
            </div>
            <Input label="Step Name" value={steps[selectedStep].name} onChange={(e) => updateStep(selectedStep, { name: e.target.value })} />
            <div>
              <label className="text-xs text-gray-500 block mb-1">Action</label>
              <select value={steps[selectedStep].action} onChange={(e) => { const a = e.target.value; const t = ACTION_TEMPLATES[a]; updateStep(selectedStep, { action: a, name: t?.label || a, params: { ...(t?.params || {}) } }); }} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 outline-none">
                {Object.entries(ACTION_TEMPLATES).map(([k, t]) => (<option key={k} value={k}>{t.label}</option>))}
              </select>
            </div>
            {Object.entries(steps[selectedStep].params).map(([key, value]) => (
              <div key={key}>
                <label className="text-[10px] text-gray-500 block mb-0.5">{key}</label>
                {['body', 'message', 'description', 'command'].includes(key) ? (
                  <textarea value={String(value || '')} onChange={(e) => updateStep(selectedStep, { params: { ...steps[selectedStep].params, [key]: e.target.value } })} className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 outline-none resize-none" rows={2} />
                ) : key === 'payload' || key === 'headers' ? (
                  <textarea value={typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value || '')} onChange={(e) => { try { updateStep(selectedStep, { params: { ...steps[selectedStep].params, [key]: JSON.parse(e.target.value) } }); } catch (_) { updateStep(selectedStep, { params: { ...steps[selectedStep].params, [key]: e.target.value } }); } }} className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 font-mono outline-none resize-none" rows={3} />
                ) : (
                  <Input value={String(value || '')} onChange={(e) => updateStep(selectedStep, { params: { ...steps[selectedStep].params, [key]: e.target.value } })} className="text-xs" />
                )}
              </div>
            ))}
            <Input label="Condition (optional)" value={steps[selectedStep].condition || ''} onChange={(e) => updateStep(selectedStep, { condition: e.target.value || undefined })} placeholder="e.g. severity == 'critical'" />
            <div>
              <label className="text-xs text-gray-500 block mb-1">On Failure</label>
              <select value={steps[selectedStep].onFailure} onChange={(e) => updateStep(selectedStep, { onFailure: e.target.value as 'stop' | 'continue' | 'retry' })} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 outline-none">
                <option value="stop">Stop Playbook</option>
                <option value="continue">Continue</option>
                <option value="retry">Retry</option>
              </select>
            </div>
          </Card>
        </div>
      )}

      <Modal open={showActionPicker} onClose={() => setShowActionPicker(false)} title="Add Action" size="lg">
        <div className="grid grid-cols-2 gap-2 max-h-96 overflow-y-auto">
          {Object.entries(ACTION_TEMPLATES).map(([key, tmpl]) => {
            const Icon = tmpl.icon;
            return (
              <button key={key} onClick={() => addStep(key)} className="flex items-start gap-3 p-3 rounded-lg border border-gray-700 hover:border-blue-500 hover:bg-blue-900/20 transition-colors text-left">
                <div className="p-2 rounded-lg bg-gray-800"><Icon className="w-4 h-4 text-blue-400" /></div>
                <div>
                  <p className="text-sm font-medium text-gray-200">{tmpl.label}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{tmpl.description}</p>
                </div>
              </button>
            );
          })}
        </div>
      </Modal>
    </div>
  );
}
