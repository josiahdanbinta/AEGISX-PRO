import React, { useState, useCallback, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Search, Play, Save, Clock, Filter, X, ChevronDown, ChevronRight,
  Globe, Server, AlertTriangle, Shield, Hash, User, Terminal,
  Download, Star, Trash2, Plus, Code, Database, TrendingUp
} from 'lucide-react';
import toast from 'react-hot-toast';
import { Modal } from '../../components/ui/Modal';

type HuntQuery = {
  id: string;
  name: string;
  query: string;
  dataSource: string;
  saved: boolean;
  lastRun?: string;
  results?: number;
};

type IOCResult = {
  type: 'ip' | 'domain' | 'hash' | 'email' | 'url';
  value: string;
  severity: string;
  firstSeen: string;
  lastSeen: string;
  source: string;
  context: string;
};

const SAVED_HUNTS: HuntQuery[] = [
  { id: 'h1', name: 'Suspicious PowerShell Execution', query: 'event_type:powershell AND (encoded_command:* OR -enc *)', dataSource: 'events', saved: true, lastRun: '2026-08-07T10:30:00', results: 47 },
  { id: 'h2', name: 'Lateral Movement via WMI', query: 'event_type:wmi_event AND severity>=high', dataSource: 'events', saved: true, lastRun: '2026-08-07T09:15:00', results: 12 },
  { id: 'h3', name: 'RDP Brute Force Attempts', query: 'event_type:authentication AND destination_port:3389 AND tag:brute_force', dataSource: 'events', saved: true, results: 89 },
  { id: 'h4', name: 'Outbound C2 Connections', query: 'direction:outbound AND (tag:c2 OR tag:beacon) AND NOT destination_ip:10.* AND NOT destination_ip:192.168.*', dataSource: 'network', saved: true, lastRun: '2026-08-07T08:00:00', results: 3 },
];

const MOCK_IOC_RESULTS: IOCResult[] = [
  { type: 'ip', value: '45.33.32.156', severity: 'high', firstSeen: '2026-08-06', lastSeen: '2026-08-07', source: 'MISP', context: 'C2 server linked to Emotet campaign' },
  { type: 'domain', value: 'evil-phish.xyz', severity: 'critical', firstSeen: '2026-08-05', lastSeen: '2026-08-07', source: 'OTX', context: 'Phishing domain registered 3 days ago' },
  { type: 'hash', value: 'd41d8cd9...a776', severity: 'high', firstSeen: '2026-08-07', lastSeen: '2026-08-07', source: 'VirusTotal', context: 'Detected by 23/67 engines as trojan' },
  { type: 'ip', value: '192.168.1.100', severity: 'medium', firstSeen: '2026-08-07', lastSeen: '2026-08-07', source: 'Agent', context: 'Internal host with unusual outbound connections' },
  { type: 'email', value: 'phish@malicious.net', severity: 'medium', firstSeen: '2026-08-06', lastSeen: '2026-08-07', source: 'MISP', context: 'Sender in phishing campaign' },
];

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  ip: <Globe size={14} />, domain: <Globe size={14} />,
  hash: <Hash size={14} />, email: <Mail size={14} />,
  url: <Globe size={14} />,
};

function Mail(props: any) { return <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>; }

export default function ThreatHuntingPage() {
  const [query, setQuery] = useState('');
  const [dataSource, setDataSource] = useState('events');
  const [results, setResults] = useState<IOCResult[]>([]);
  const [savedHunts, setSavedHunts] = useState(SAVED_HUNTS);
  const [running, setRunning] = useState(false);
  const [activeTab, setActiveTab] = useState<'hunt' | 'ioc' | 'saved'>('hunt');
  const [iocInput, setIocInput] = useState('');
  const [iocResults, setIocResults] = useState<IOCResult[]>([]);
  const [iocSearching, setIocSearching] = useState(false);
  const [expandedHunt, setExpandedHunt] = useState<string | null>(null);

  const runHunt = useCallback(async () => {
    if (!query.trim()) { toast.error('Enter a query'); return; }
    setRunning(true);
    await new Promise(r => setTimeout(r, 800));
    setResults(MOCK_IOC_RESULTS);
    setRunning(false);
    toast.success(`Hunt returned ${MOCK_IOC_RESULTS.length} results`);
  }, [query]);

  const saveHunt = useCallback(() => {
    if (!query.trim()) return;
    const h: HuntQuery = {
      id: `h${Date.now()}`, name: `Hunt ${savedHunts.length + 1}`,
      query, dataSource, saved: true,
    };
    setSavedHunts(prev => [h, ...prev]);
    toast.success('Hunt saved');
  }, [query, dataSource, savedHunts]);

  const loadHunt = useCallback((h: HuntQuery) => {
    setQuery(h.query);
    setDataSource(h.dataSource);
    setActiveTab('hunt');
  }, []);

  const deleteHunt = useCallback((id: string) => {
    setSavedHunts(prev => prev.filter(h => h.id !== id));
  }, []);

  const pivotIOC = useCallback(async () => {
    if (!iocInput.trim()) return;
    setIocSearching(true);
    await new Promise(r => setTimeout(r, 600));
    const filtered = MOCK_IOC_RESULTS.filter(r =>
      r.value.includes(iocInput.trim()) || r.type === iocInput.trim() || r.context.toLowerCase().includes(iocInput.toLowerCase())
    );
    setIocResults(filtered.length ? filtered : MOCK_IOC_RESULTS.slice(0, 3));
    setIocSearching(false);
    toast.success(`IOC pivot found ${filtered.length || MOCK_IOC_RESULTS.slice(0, 3).length} results`);
  }, [iocInput]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-800">
        <h1 className="text-xl font-bold text-white">Threat Hunting</h1>
        <div className="flex-1" />
        <div className="flex bg-slate-800 rounded-lg p-0.5">
          {(['hunt', 'ioc', 'saved'] as const).map(tab => (
            <button key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'}`}>
              {tab === 'hunt' ? 'Query Hunt' : tab === 'ioc' ? 'IOC Pivot' : `Saved (${savedHunts.length})`}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {activeTab === 'hunt' && (
          <div className="max-w-4xl mx-auto space-y-4">
            {/* Query Input */}
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-1 flex items-center gap-2">
              <Code size={16} className="text-slate-500 ml-3" />
              <input value={query} onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runHunt()}
                placeholder="event_type:powershell AND severity>=high AND NOT source_ip:10.0.* ..."
                className="flex-1 bg-transparent text-white text-sm font-mono py-3 outline-none placeholder:text-slate-600" />
              <select value={dataSource} onChange={e => setDataSource(e.target.value)}
                className="bg-slate-800 text-slate-300 text-xs rounded px-2 py-1.5 border border-slate-700 mr-1">
                <option value="events">Events</option>
                <option value="network">Network</option>
                <option value="alerts">Alerts</option>
                <option value="assets">Assets</option>
              </select>
              <button onClick={runHunt} disabled={running}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium mr-1">
                {running ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
                {running ? 'Hunting...' : 'Run Hunt'}
              </button>
            </div>

            {/* Quick Hunt Suggestions */}
            <div className="flex flex-wrap gap-2">
              {['Powershell', 'WMI', 'RDP Brute Force', 'C2 Beacon', 'Privilege Escalation', 'Credential Dump'].map(tag => (
                <button key={tag}
                  onClick={() => setQuery(`event_type:${tag.toLowerCase().replace(' ', '_')} AND severity>=medium`)}
                  className="px-3 py-1 rounded-full bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700">
                  {tag}
                </button>
              ))}
            </div>

            {/* Results */}
            {results.length > 0 && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                  <span className="text-sm font-medium text-white">{results.length} results</span>
                  <div className="flex gap-2">
                    <button onClick={saveHunt} className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"><Save size={12} /> Save Hunt</button>
                    <button className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"><Download size={12} /> Export</button>
                  </div>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-500 text-xs">
                      <th className="text-left px-4 py-2 font-medium">Type</th>
                      <th className="text-left px-4 py-2 font-medium">Value</th>
                      <th className="text-left px-4 py-2 font-medium">Severity</th>
                      <th className="text-left px-4 py-2 font-medium">First Seen</th>
                      <th className="text-left px-4 py-2 font-medium">Last Seen</th>
                      <th className="text-left px-4 py-2 font-medium">Source</th>
                      <th className="text-left px-4 py-2 font-medium">Context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((r, i) => (
                      <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/50">
                        <td className="px-4 py-2 text-slate-400 flex items-center gap-1">{TYPE_ICONS[r.type]} {r.type}</td>
                        <td className="px-4 py-2 text-white font-mono text-xs">{r.value}</td>
                        <td className="px-4 py-2">
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-xs border ${SEV_COLOR[r.severity]}`}>{r.severity}</span>
                        </td>
                        <td className="px-4 py-2 text-slate-400">{r.firstSeen}</td>
                        <td className="px-4 py-2 text-slate-400">{r.lastSeen}</td>
                        <td className="px-4 py-2 text-slate-400">{r.source}</td>
                        <td className="px-4 py-2 text-slate-300 text-xs max-w-xs truncate">{r.context}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </motion.div>
            )}

            {results.length === 0 && !running && (
              <div className="text-center py-20 text-slate-600">
                <Search size={48} className="mx-auto mb-4 opacity-50" />
                <p className="text-sm">Enter a hunt query above to search across all event data</p>
                <p className="text-xs mt-1">Use field:value syntax — event_type, severity, source_ip, hostname, tag, destination_port, etc.</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'ioc' && (
          <div className="max-w-4xl mx-auto space-y-4">
            {/* IOC Pivot Input */}
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-1 flex items-center gap-2">
              <Search size={16} className="text-slate-500 ml-3" />
              <input value={iocInput} onChange={e => setIocInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && pivotIOC()}
                placeholder="Paste IP, domain, hash, email, or URL to pivot across all data sources..."
                className="flex-1 bg-transparent text-white text-sm py-3 outline-none placeholder:text-slate-600" />
              <button onClick={pivotIOC} disabled={iocSearching}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-medium mr-1">
                {iocSearching ? <RefreshCw size={14} className="animate-spin" /> : <Search size={14} />}
                Pivot
              </button>
            </div>

            {iocResults.length > 0 && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-800">
                  <span className="text-sm font-medium text-white">
                    Pivot Results — {iocResults.length} matches across events, alerts, assets, and threat intel
                  </span>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-500 text-xs">
                      <th className="text-left px-4 py-2 font-medium">Type</th>
                      <th className="text-left px-4 py-2 font-medium">Value</th>
                      <th className="text-left px-4 py-2 font-medium">Severity</th>
                      <th className="text-left px-4 py-2 font-medium">First Seen</th>
                      <th className="text-left px-4 py-2 font-medium">Source</th>
                      <th className="text-left px-4 py-2 font-medium">Context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocResults.map((r, i) => (
                      <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/50">
                        <td className="px-4 py-2 text-slate-400 flex items-center gap-1">{TYPE_ICONS[r.type]} {r.type}</td>
                        <td className="px-4 py-2 text-white font-mono text-xs">{r.value}</td>
                        <td className="px-4 py-2"><span className={`inline-flex px-1.5 py-0.5 rounded text-xs border ${SEV_COLOR[r.severity]}`}>{r.severity}</span></td>
                        <td className="px-4 py-2 text-slate-400">{r.firstSeen}</td>
                        <td className="px-4 py-2 text-slate-400">{r.source}</td>
                        <td className="px-4 py-2 text-slate-300 text-xs max-w-xs truncate">{r.context}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </motion.div>
            )}
          </div>
        )}

        {activeTab === 'saved' && (
          <div className="max-w-4xl mx-auto space-y-3">
            {savedHunts.map(hunt => (
              <div key={hunt.id}
                className="bg-slate-900 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
                <div className="flex items-center gap-3 px-4 py-3 cursor-pointer"
                  onClick={() => setExpandedHunt(expandedHunt === hunt.id ? null : hunt.id)}>
                  <button className="p-1 text-slate-500">
                    {expandedHunt === hunt.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                  <Star size={14} className="text-amber-500" fill="#f59e0b" />
                  <div className="flex-1">
                    <span className="text-sm font-medium text-white">{hunt.name}</span>
                    <span className="ml-2 text-xs text-slate-500">{hunt.dataSource}</span>
                  </div>
                  {hunt.results !== undefined && <span className="text-xs text-slate-500">{hunt.results} results</span>}
                  {hunt.lastRun && <span className="text-xs text-slate-600">{new Date(hunt.lastRun).toLocaleDateString()}</span>}
                  <button onClick={e => { e.stopPropagation(); loadHunt(hunt); }}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 text-xs">
                    <Play size={10} /> Load
                  </button>
                  <button onClick={e => { e.stopPropagation(); deleteHunt(hunt.id); }}
                    className="p-1 rounded hover:bg-red-900/30 text-slate-500 hover:text-red-400">
                    <Trash2 size={14} />
                  </button>
                </div>
                {expandedHunt === hunt.id && (
                  <div className="px-10 pb-3">
                    <pre className="bg-slate-950 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto">
                      {hunt.query}
                    </pre>
                  </div>
                )}
              </div>
            ))}
            {savedHunts.length === 0 && (
              <div className="text-center py-20 text-slate-600">
                <Star size={48} className="mx-auto mb-4 opacity-50" />
                <p className="text-sm">No saved hunts yet</p>
                <p className="text-xs mt-1">Run a hunt query and click "Save Hunt" to save it here</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function RefreshCw(props: any) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
    </svg>
  );
}
