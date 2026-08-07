import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, Clock, User, AlertTriangle, Plus, RefreshCw } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Loading } from '@/components/ui/Loading';
import { api } from '@/services/api';
import toast from 'react-hot-toast';

interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  assignee_id: string | null;
  assignee_name: string | null;
  affected_assets: Array<{ id: string; hostname: string }>;
  mitre_techniques: string[] | null;
  created_at: string;
  updated_at: string;
}

interface TimelineEntry {
  id: string;
  entry_type: string;
  description: string;
  user_name: string;
  created_at: string;
}

interface Note {
  id: string;
  content: string;
  user_name: string;
  created_at: string;
}

const severityVariant: Record<string, 'danger' | 'warning' | 'info' | 'default'> = {
  critical: 'danger', high: 'warning', medium: 'warning', low: 'info',
};
const statusVariant: Record<string, 'success' | 'warning' | 'danger' | 'info' | 'default'> = {
  open: 'warning', in_progress: 'info', resolved: 'success', closed: 'default',
};

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'timeline' | 'notes'>('overview');
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [noteContent, setNoteContent] = useState('');
  const [addingNote, setAddingNote] = useState(false);

  const fetchIncident = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const data = await api.get<Incident>(`/incidents/${id}`);
      setIncident(data);
    } catch {
      setError('Failed to load incident');
    } finally {
      setLoading(false);
    }
  }, [id]);

  const fetchTimeline = useCallback(async () => {
    if (!id) return;
    try {
      const data = await api.get<TimelineEntry[]>(`/incidents/${id}/timeline`);
      setTimeline(data);
    } catch {}
  }, [id]);

  const fetchNotes = useCallback(async () => {
    if (!id) return;
    try {
      const data = await api.get<Note[]>(`/incidents/${id}/notes`);
      setNotes(data);
    } catch {}
  }, [id]);

  useEffect(() => { fetchIncident(); }, [fetchIncident]);
  useEffect(() => { fetchTimeline(); }, [fetchTimeline, tab]);
  useEffect(() => { fetchNotes(); }, [fetchNotes, tab]);

  const handleAction = async (action: string, body?: Record<string, unknown>) => {
    if (!id) return;
    try {
      await api.post(`/incidents/${id}/${action}`, body);
      toast.success(`Incident ${action}d`);
      fetchIncident();
    } catch {
      toast.error(`Failed to ${action} incident`);
    }
  };

  const handleAddNote = async () => {
    if (!id || !noteContent.trim()) return;
    setAddingNote(true);
    try {
      await api.post(`/incidents/${id}/notes`, { content: noteContent });
      toast.success('Note added');
      setNoteContent('');
      fetchNotes();
    } catch {
      toast.error('Failed to add note');
    } finally {
      setAddingNote(false);
    }
  };

  if (loading) return <div className="flex items-center justify-center min-h-[60vh]"><Loading size="lg" /></div>;
  if (error || !incident) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <AlertTriangle className="w-12 h-12 text-red-400" />
        <p className="text-red-600">{error || 'Incident not found'}</p>
        <Button variant="secondary" onClick={() => navigate('/incidents')}>Back to Incidents</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate('/incidents')} className="text-slate-400 hover:text-slate-600">
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-slate-900">{incident.title}</h1>
          <p className="text-xs text-slate-400 mt-1">INC-{incident.id.substring(0, 8).toUpperCase()}</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {(incident.status === 'open' || incident.status === 'in_progress') && (
            <>
              <Button variant="primary" size="sm" onClick={() => handleAction('close', { resolution: 'Resolved' })}>Close</Button>
              <Button variant="secondary" size="sm" onClick={() => handleAction('escalate', { reason: 'Escalating' })}>Escalate</Button>
            </>
          )}
          {incident.status === 'closed' && (
            <Button variant="secondary" size="sm" onClick={() => handleAction('reopen', { reason: 'Reopening' })}>Reopen</Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatBadgeCard label="Severity" value={incident.severity} variant={severityVariant[incident.severity] || 'default'} icon={Shield} />
        <StatBadgeCard label="Status" value={incident.status.replace('_', ' ')} variant={statusVariant[incident.status] || 'default'} icon={AlertTriangle} />
        <StatBadgeCard label="Assignee" value={incident.assignee_name || 'Unassigned'} variant="default" icon={User} />
        <StatBadgeCard label="Created" value={new Date(incident.created_at).toLocaleDateString()} variant="default" icon={Clock} />
      </div>

      <div className="flex items-center gap-4 border-b border-slate-200">
        {(['overview', 'timeline', 'notes'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors capitalize ${
              tab === t ? 'border-brand-500 text-brand-600' : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <Card>
          <CardHeader><CardTitle>Details</CardTitle></CardHeader>
          <div className="px-4 pb-4 space-y-3">
            <p className="text-sm text-slate-600">{incident.description || 'No description provided'}</p>
            {incident.affected_assets && incident.affected_assets.length > 0 && (
              <div>
                <h4 className="text-xs font-medium text-slate-500 uppercase mb-2">Affected Assets</h4>
                <div className="flex flex-wrap gap-2">
                  {incident.affected_assets.map((a) => (
                    <Badge key={a.id} variant="info">{a.hostname}</Badge>
                  ))}
                </div>
              </div>
            )}
            {incident.mitre_techniques && incident.mitre_techniques.length > 0 && (
              <div>
                <h4 className="text-xs font-medium text-slate-500 uppercase mb-2">MITRE ATT&CK</h4>
                <div className="flex flex-wrap gap-2">
                  {incident.mitre_techniques.map((t) => (
                    <Badge key={t} variant="warning" size="sm">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {tab === 'timeline' && (
        <Card padding="none">
          <div className="divide-y divide-slate-100 max-h-[500px] overflow-y-auto">
            {timeline.length === 0 ? (
              <div className="flex flex-col items-center py-12 gap-2">
                <Clock className="w-8 h-8 text-slate-300" />
                <p className="text-sm text-slate-400">No timeline entries</p>
              </div>
            ) : (
              timeline.map((entry) => (
                <div key={entry.id} className="flex items-start gap-3 px-4 py-3">
                  <div className="w-2 h-2 rounded-full bg-brand-500 mt-1.5 flex-shrink-0" />
                  <div className="flex-1">
                    <p className="text-sm text-slate-700">{entry.description}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-slate-500">{entry.user_name}</span>
                      <span className="text-xs text-slate-400">{new Date(entry.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <Badge variant="info" size="sm">{entry.entry_type}</Badge>
                </div>
              ))
            )}
          </div>
        </Card>
      )}

      {tab === 'notes' && (
        <div className="space-y-4">
          <Card>
            <div className="flex gap-2 p-4">
              <input
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                placeholder="Add a note..."
                className="flex-1 border border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500/20 focus:border-brand-500"
              />
              <Button variant="primary" size="sm" loading={addingNote} onClick={handleAddNote} icon={Plus}>
                Add
              </Button>
            </div>
          </Card>
          <Card padding="none">
            <div className="divide-y divide-slate-100 max-h-[400px] overflow-y-auto">
              {notes.length === 0 ? (
                <div className="flex flex-col items-center py-12 gap-2">
                  <p className="text-sm text-slate-400">No notes yet</p>
                </div>
              ) : (
                notes.map((note) => (
                  <div key={note.id} className="px-4 py-3">
                    <p className="text-sm text-slate-700">{note.content}</p>
                    <p className="text-xs text-slate-400 mt-1">
                      {note.user_name} — {new Date(note.created_at).toLocaleString()}
                    </p>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

function StatBadgeCard({ label, value, variant, icon: Icon }: { label: string; value: string; variant: 'success' | 'warning' | 'danger' | 'info' | 'default'; icon: React.ComponentType<{ className?: string }> }) {
  return (
    <Card>
      <div className="flex items-center gap-3 px-4 py-3">
        <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center">
          <Icon className="w-5 h-5 text-slate-500" />
        </div>
        <div>
          <p className="text-xs text-slate-400">{label}</p>
          <Badge variant={variant} size="md" className="capitalize">{value}</Badge>
        </div>
      </div>
    </Card>
  );
}
