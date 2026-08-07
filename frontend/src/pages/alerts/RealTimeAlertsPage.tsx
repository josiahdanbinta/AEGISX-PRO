import React, { useState, useMemo } from 'react';
import { useAlertWebSocket } from '../../hooks/useWebSocket';
import { Card } from '../../components/ui/Card';
import { Badge } from '../../components/ui/Badge';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';

const severityColors: Record<string, string> = {
  critical: 'bg-red-900 text-red-200 border-red-700',
  high: 'bg-orange-900 text-orange-200 border-orange-700',
  medium: 'bg-yellow-900 text-yellow-200 border-yellow-700',
  low: 'bg-blue-900 text-blue-200 border-blue-700',
  info: 'bg-gray-700 text-gray-300 border-gray-600',
};

function AlertCard({ alert, onAck, onDismiss }: { alert: any; onAck: (id: string) => void; onDismiss: (id: string) => void }) {
  const sev = alert.severity || 'info';
  const time = alert.timestamp || alert.created_at;
  const formattedTime = time
    ? new Date(time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '--:--:--';

  return (
    <div className="border border-gray-700 bg-gray-800/50 rounded-lg p-3 hover:bg-gray-800 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
            sev === 'critical' ? 'bg-red-500 animate-pulse' :
            sev === 'high' ? 'bg-orange-500' :
            sev === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
          }`} />
          <span className="text-xs text-gray-500 font-mono flex-shrink-0">{formattedTime}</span>
          <Badge className={`text-xs ${severityColors[sev] || severityColors.info}`}>{sev.toUpperCase()}</Badge>
        </div>
        <div className="flex gap-1 flex-shrink-0">
          <button onClick={() => onAck(alert.id)} className="text-xs px-2 py-0.5 rounded bg-green-800 text-green-200 hover:bg-green-700" title="Acknowledge">ACK</button>
          <button onClick={() => onDismiss(alert.id)} className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 hover:bg-gray-600" title="Dismiss">X</button>
        </div>
      </div>
      <div className="mt-1.5 text-sm text-gray-200 font-medium truncate">{alert.title || alert.rule_name || 'Untitled Alert'}</div>
      {alert.description && (
        <div className="mt-0.5 text-xs text-gray-400 line-clamp-2">{alert.description}</div>
      )}
      <div className="mt-1.5 flex flex-wrap gap-1">
        {alert.source_ip && <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded text-gray-400 font-mono">{alert.source_ip}</span>}
        {alert.hostname && <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded text-gray-400 font-mono">{alert.hostname}</span>}
        {alert.rule_name && <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded text-blue-400">{alert.rule_name}</span>}
        {alert.confidence != null && (
          <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded text-purple-400">{(alert.confidence * 100).toFixed(0)}%</span>
        )}
      </div>
    </div>
  );
}

export default function RealTimeAlertsPage() {
  const { alerts, connected, status, clearAlerts } = useAlertWebSocket();
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [paused, setPaused] = useState(false);

  const filteredAlerts = useMemo(() => {
    let result = paused ? [...alerts] : alerts;
    if (severityFilter !== 'all') {
      result = result.filter((a) => a.severity === severityFilter);
    }
    if (filter) {
      const q = filter.toLowerCase();
      result = result.filter(
        (a) =>
          (a.title || '').toLowerCase().includes(q) ||
          (a.rule_name || '').toLowerCase().includes(q) ||
          (a.source_ip || '').includes(q) ||
          (a.hostname || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [alerts, severityFilter, filter, paused]);

  const counts = useMemo(() => ({
    total: alerts.length,
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
  }), [alerts]);

  return (
    <div className="h-full flex flex-col p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Real-Time Alert Dashboard</h1>
          <p className="text-sm text-gray-400">Live streaming alerts via WebSocket</p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 text-xs ${
            status === 'open' ? 'text-green-400' : status === 'connecting' ? 'text-yellow-400' : 'text-red-400'
          }`}>
            <span className={`w-2 h-2 rounded-full ${
              status === 'open' ? 'bg-green-400 animate-pulse' :
              status === 'connecting' ? 'bg-yellow-400' : 'bg-red-400'
            }`} />
            {status === 'open' ? 'LIVE' : status === 'connecting' ? 'Connecting...' : 'Disconnected'}
          </span>
          <Button onClick={() => setPaused(!paused)} variant="outline" size="sm">
            {paused ? 'Resume' : 'Pause'}
          </Button>
          <Button onClick={clearAlerts} variant="outline" size="sm">Clear</Button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total', value: counts.total, color: 'text-gray-400' },
          { label: 'Critical', value: counts.critical, color: 'text-red-400' },
          { label: 'High', value: counts.high, color: 'text-orange-400' },
          { label: 'Medium', value: counts.medium, color: 'text-yellow-400' },
          { label: 'Low', value: counts.low, color: 'text-blue-400' },
        ].map((stat) => (
          <Card key={stat.label} className="p-3 text-center">
            <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-xs text-gray-500">{stat.label}</div>
          </Card>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        <Input
          placeholder="Filter alerts..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-64"
        />
        {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            className={`text-xs px-3 py-1 rounded border transition-colors ${
              severityFilter === sev
                ? 'border-blue-500 bg-blue-900/30 text-blue-300'
                : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            {sev === 'all' ? 'All' : sev.toUpperCase()}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {filteredAlerts.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <p className="text-gray-500 text-sm">
              {connected ? 'Waiting for alerts...' : 'Connecting to live feed...'}
            </p>
          </div>
        ) : (
          filteredAlerts.map((alert, i) => (
            <AlertCard
              key={alert.id || i}
              alert={alert}
              onAck={(id) => console.log('ACK', id)}
              onDismiss={(id) => console.log('DISMISS', id)}
            />
          ))
        )}
      </div>
    </div>
  );
}
