import React, { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play, Plus, Trash2, Save, ArrowRight, GitBranch, Zap,
  X, Move, GripVertical, ChevronDown, Settings, Clock,
  AlertTriangle, Mail, MessageSquare, Globe, Terminal,
  Shield, UserCheck, FileText, RefreshCw
} from 'lucide-react';
import toast from 'react-hot-toast';
import { Modal } from '../../components/ui/Modal';

const ACTION_ICONS: Record<string, React.ReactNode> = {
  send_email: <Mail size={14} />,
  send_slack: <MessageSquare size={14} />,
  send_teams: <MessageSquare size={14} />,
  webhook: <Globe size={14} />,
  run_script: <Terminal size={14} />,
  block_ip: <Shield size={14} />,
  isolate_host: <Shield size={14} />,
  quarantine_file: <Shield size={14} />,
  assign_user: <UserCheck size={14} />,
  create_ticket: <FileText size={14} />,
  send_notification: <Zap size={14} />,
  escalate: <AlertTriangle size={14} />,
  wait: <Clock size={14} />,
  close_alert: <Shield size={14} />,
  enrich_ip: <Globe size={14} />,
};

const ACTION_LABELS: Record<string, string> = {
  send_email: 'Send Email', send_slack: 'Post to Slack',
  send_teams: 'Post to Teams', webhook: 'Call Webhook',
  run_script: 'Run Script', block_ip: 'Block IP',
  isolate_host: 'Isolate Host', quarantine_file: 'Quarantine File',
  assign_user: 'Assign Analyst', create_ticket: 'Create Ticket',
  send_notification: 'Notify', escalate: 'Escalate',
  wait: 'Wait / Delay', close_alert: 'Close Alert',
  enrich_ip: 'Enrich IP',
};

type PlaybookNode = {
  id: string;
  type: 'trigger' | 'condition' | 'action';
  label: string;
  actionType?: string;
  condition?: string;
  x: number;
  y: number;
  branches?: string[];
};

type PlaybookEdge = {
  from: string;
  to: string;
  label?: string;
  branchId?: string;
};

type Playbook = {
  id: string;
  name: string;
  description: string;
  triggerType: string;
  nodes: PlaybookNode[];
  edges: PlaybookEdge[];
  status: string;
};

const NODE_COLORS = {
  trigger: 'border-emerald-500 bg-emerald-500/10',
  condition: 'border-amber-500 bg-amber-500/10',
  action: 'border-blue-500 bg-blue-500/10',
};

const INITIAL_NODES: PlaybookNode[] = [
  { id: 'trigger-1', type: 'trigger', label: 'Alert Received', x: 300, y: 20 },
  { id: 'action-1', type: 'action', label: 'Enrich IP', actionType: 'enrich_ip', x: 300, y: 140 },
];

const INITIAL_EDGES: PlaybookEdge[] = [
  { from: 'trigger-1', to: 'action-1' },
];

function nodeId() { return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`; }

export default function PlaybookEditor({ playbook: initial, onSave, onClose }: {
  playbook?: Playbook;
  onSave?: (p: Playbook) => void;
  onClose?: () => void;
}) {
  const [nodes, setNodes] = useState<PlaybookNode[]>(initial?.nodes || INITIAL_NODES);
  const [edges, setEdges] = useState<PlaybookEdge[]>(initial?.edges || INITIAL_EDGES);
  const [name, setName] = useState(initial?.name || 'New Playbook');
  const [desc, setDesc] = useState(initial?.description || '');
  const [selected, setSelected] = useState<string | null>(null);
  const [trigger, setTrigger] = useState(initial?.triggerType || 'alert');
  const [showActionPicker, setShowActionPicker] = useState<string | null>(null);
  const [editingNode, setEditingNode] = useState<string | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);
  const [linking, setLinking] = useState<string | null>(null);
  const [nodeLabel, setNodeLabel] = useState('');
  const canvasRef = useRef<HTMLDivElement>(null);
  const dragOffset = useRef({ x: 0, y: 0 });

  const selectedNode = nodes.find(n => n.id === selected);

  const addNode = useCallback((type: PlaybookNode['type'], actionType?: string) => {
    const label = type === 'trigger' ? 'New Trigger'
      : type === 'condition' ? 'New Condition'
      : (actionType ? ACTION_LABELS[actionType] || 'New Action' : 'New Action');
    const newNode: PlaybookNode = {
      id: nodeId(), type, label, actionType,
      x: 150 + Math.random() * 400, y: 60 + nodes.length * 120,
    };
    setNodes(prev => [...prev, newNode]);
    if (selected) {
      setEdges(prev => [...prev, { from: selected, to: newNode.id }]);
    }
    toast.success(`${type} node added`);
  }, [nodes, selected]);

  const deleteNode = useCallback((id: string) => {
    setNodes(prev => prev.filter(n => n.id !== id));
    setEdges(prev => prev.filter(e => e.from !== id && e.to !== id));
    if (selected === id) setSelected(null);
  }, [selected]);

  const handleMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    if (e.target instanceof HTMLButtonElement || e.target instanceof HTMLSelectElement
        || e.target instanceof HTMLInputElement) return;
    e.stopPropagation();
    setSelected(nodeId);
    setDragging(nodeId);
    const rect = canvasRef.current?.getBoundingClientRect();
    if (rect) {
      const node = nodes.find(n => n.id === nodeId);
      if (node) {
        dragOffset.current = { x: e.clientX - rect.left - node.x, y: e.clientY - rect.top - node.y };
      }
    }
  }, [nodes]);

  useEffect(() => {
    if (!dragging) return;
    const handleMove = (e: MouseEvent) => {
      const rect = canvasRef.current?.getBoundingClientRect();
      if (!rect) return;
      const x = e.clientX - rect.left - dragOffset.current.x;
      const y = e.clientY - rect.top - dragOffset.current.y;
      setNodes(prev => prev.map(n => n.id === dragging ? { ...n, x: Math.max(0, Math.min(1000, x)), y: Math.max(0, y) } : n));
    };
    const handleUp = () => setDragging(null);
    window.addEventListener('mousemove', handleMove);
    window.addEventListener('mouseup', handleUp);
    return () => { window.removeEventListener('mousemove', handleMove); window.removeEventListener('mouseup', handleUp); };
  }, [dragging]);

  const startLink = useCallback((nodeId: string) => {
    setLinking(nodeId);
  }, []);

  const completeLink = useCallback((targetId: string) => {
    if (linking && linking !== targetId) {
      setEdges(prev => {
        if (prev.some(e => e.from === linking && e.to === targetId)) return prev;
        return [...prev, { from: linking, to: targetId }];
      });
    }
    setLinking(null);
  }, [linking]);

  const removeEdge = useCallback((from: string, to: string) => {
    setEdges(prev => prev.filter(e => !(e.from === from && e.to === to)));
  }, []);

  const handleSave = useCallback(() => {
    const p: Playbook = {
      id: initial?.id || nodeId(),
      name, description: desc,
      triggerType: trigger,
      nodes, edges, status: 'draft',
    };
    onSave?.(p);
    toast.success('Playbook saved');
  }, [name, desc, trigger, nodes, edges, initial, onSave]);

  const edgeLines = useMemo(() => edges.map(edge => {
    const from = nodes.find(n => n.id === edge.from);
    const to = nodes.find(n => n.id === edge.to);
    if (!from || !to) return null;
    const fx = from.x + 90, fy = from.y + 80;
    const tx = to.x + 90, ty = to.y;
    const mx = (fx + tx) / 2;
    const d = fy < ty
      ? `M${fx} ${fy} C${fx} ${fy + 40}, ${tx} ${ty - 40}, ${tx} ${ty}`
      : `M${fx} ${fy} C${fx} ${fy + 20}, ${tx} ${ty - 20}, ${tx} ${ty}`;
    return { key: `${edge.from}-${edge.to}`, d, from: edge.from, to: edge.to, mx, my: (fy + ty) / 2, fromObj: from, toObj: to };
  }).filter(Boolean), [edges, nodes]);

  return (
    <div className="flex flex-col h-full bg-slate-950">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800">
        <input
          value={name} onChange={e => setName(e.target.value)}
          className="bg-transparent text-lg font-semibold text-white outline-none border-b border-transparent focus:border-blue-500 w-64"
          placeholder="Playbook Name"
        />
        <select value={trigger} onChange={e => setTrigger(e.target.value)}
          className="bg-slate-800 text-slate-300 text-sm rounded px-2 py-1 border border-slate-700">
          <option value="alert">On Alert</option>
          <option value="incident">On Incident</option>
          <option value="schedule">Scheduled</option>
          <option value="manual">Manual</option>
          <option value="webhook">Webhook</option>
        </select>
        <div className="flex-1" />
        <button onClick={() => addNode('action')}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm">
          <Plus size={14} /> Add Action
        </button>
        <button onClick={() => addNode('condition')}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white text-sm">
          <GitBranch size={14} /> Add Condition
        </button>
        <button onClick={handleSave}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-sm">
          <Save size={14} /> Save
        </button>
        {onClose && (
          <button onClick={onClose} className="p-1.5 rounded hover:bg-slate-800 text-slate-400">
            <X size={18} />
          </button>
        )}
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Canvas */}
        <div ref={canvasRef} className="flex-1 relative overflow-auto bg-slate-950"
          style={{ backgroundImage: 'radial-gradient(circle, #1e293b 1px, transparent 1px)', backgroundSize: '24px 24px' }}
          onClick={(e) => { if (e.target === canvasRef.current) { setSelected(null); setLinking(null); } }}>
          {/* Edge lines */}
          <svg className="absolute inset-0 pointer-events-none" style={{ width: '2000px', height: '2000px' }}>
            {edgeLines.map(line => line && (
              <g key={line.key}>
                <path d={line.d} stroke={linking && (line.from === linking || line.to === linking) ? '#3b82f6' : '#475569'} strokeWidth={2} fill="none" markerEnd="url(#arrowhead)" />
                <circle cx={line.mx} cy={line.my} r={4} fill="#475569" className="cursor-pointer pointer-events-auto"
                  onClick={(e) => { e.stopPropagation(); removeEdge(line.from, line.to); }} />
              </g>
            ))}
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#475569" />
              </marker>
            </defs>
          </svg>

          {/* Nodes */}
          {nodes.map(node => (
            <motion.div key={node.id}
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className={`absolute w-[180px] rounded-lg border-2 cursor-pointer select-none group ${NODE_COLORS[node.type]} ${selected === node.id ? 'ring-2 ring-blue-400' : ''} ${linking ? 'hover:ring-2 hover:ring-blue-400' : ''}`}
              style={{ left: node.x, top: node.y }}
              onMouseDown={e => handleMouseDown(e, node.id)}
              onClick={() => { if (linking) completeLink(node.id); }}>
              {/* Node header */}
              <div className="flex items-center gap-1 px-2 py-1.5 border-b border-slate-700/50">
                <GripVertical size={12} className="text-slate-600" />
                <span className="text-xs font-medium text-slate-400 uppercase">{node.type}</span>
                <div className="flex-1" />
                <button onClick={e => { e.stopPropagation(); startLink(node.id); }}
                  className={`p-0.5 rounded hover:bg-slate-700 ${linking === node.id ? 'text-blue-400' : 'text-slate-500'}`} title="Link">
                  <ArrowRight size={12} />
                </button>
                <button onClick={e => { e.stopPropagation(); deleteNode(node.id); }}
                  className="p-0.5 rounded hover:bg-red-900/50 text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100">
                  <Trash2 size={12} />
                </button>
              </div>
              {/* Node body */}
              <div className="px-3 py-2">
                {node.type === 'action' ? (
                  <select
                    value={node.actionType || ''}
                    onChange={e => {
                      const at = e.target.value;
                      setNodes(prev => prev.map(n => n.id === node.id ? {
                        ...n,
                        actionType: at,
                        label: ACTION_LABELS[at] || n.label,
                      } : n));
                    }}
                    onClick={e => e.stopPropagation()}
                    className="w-full bg-slate-800 text-white text-xs rounded px-1.5 py-1 border border-slate-700">
                    <option value="">Select action...</option>
                    {Object.entries(ACTION_LABELS).map(([k, v]) => (
                      <option key={k} value={k}>{v}</option>
                    ))}
                  </select>
                ) : node.type === 'condition' ? (
                  <input
                    value={node.condition || ''}
                    onChange={e => setNodes(prev => prev.map(n => n.id === node.id ? { ...n, condition: e.target.value } : n))}
                    onClick={e => e.stopPropagation()}
                    className="w-full bg-slate-800 text-white text-xs rounded px-1.5 py-1 border border-slate-700"
                    placeholder="e.g. severity == critical"
                  />
                ) : (
                  <div className="flex items-center gap-2 text-sm text-white">
                    {ACTION_ICONS[node.actionType || ''] || <Zap size={14} />}
                    <span className="truncate">{node.label}</span>
                  </div>
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Sidebar */}
        {selectedNode && (
          <motion.div
            initial={{ x: 300 }} animate={{ x: 0 }}
            className="w-72 border-l border-slate-800 bg-slate-900 p-4 flex flex-col gap-3 overflow-y-auto">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white capitalize">{selectedNode.type} Properties</h3>
              <button onClick={() => setSelected(null)} className="p-1 rounded hover:bg-slate-800 text-slate-400"><X size={14} /></button>
            </div>
            <label className="text-xs text-slate-400">Label</label>
            <input value={selectedNode.label}
              onChange={e => setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, label: e.target.value } : n))}
              className="w-full bg-slate-800 text-white text-sm rounded px-2 py-1.5 border border-slate-700" />
            {selectedNode.type === 'action' && (
              <>
                <label className="text-xs text-slate-400">Action Type</label>
                <select value={selectedNode.actionType || ''}
                  onChange={e => setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, actionType: e.target.value, label: ACTION_LABELS[e.target.value] || n.label } : n))}
                  className="w-full bg-slate-800 text-white text-sm rounded px-2 py-1.5 border border-slate-700">
                  <option value="">Select...</option>
                  {Object.entries(ACTION_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </>
            )}
            {selectedNode.type === 'condition' && (
              <>
                <label className="text-xs text-slate-400">Condition Expression</label>
                <input value={selectedNode.condition || ''}
                  onChange={e => setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, condition: e.target.value } : n))}
                  className="w-full bg-slate-800 text-white text-sm rounded px-2 py-1.5 border border-slate-700 font-mono"
                  placeholder="severity == 'critical'" />
              </>
            )}
            <button onClick={() => deleteNode(selectedNode.id)}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-600/20 hover:bg-red-600/40 text-red-400 text-sm mt-2">
              <Trash2 size={14} /> Delete Node
            </button>
          </motion.div>
        )}
      </div>
    </div>
  );
}
