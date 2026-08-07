import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const COLORS = {
  critical: '#ef4444',  high: '#f97316',  medium: '#eab308',
  low: '#3b82f6',      info: '#64748b',
  active: '#10b981',   inactive: '#64748b',  offline: '#ef4444',
  online: '#10b981',   warning: '#eab308',   error: '#ef4444',
};

interface DonutChartProps {
  data: { name: string; value: number; color?: string }[];
  innerLabel?: string;
  height?: number;
  colorKey?: string;
}

const RADIAN = Math.PI / 180;

function renderLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }: any) {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return percent > 0.05 ? (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={600}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  ) : null;
}

export function DonutChart({ data, innerLabel, height = 200, colorKey }: DonutChartProps) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const colors = data.map((d) => d.color || COLORS[d.name as keyof typeof COLORS] || '#0ca5ed');

  return (
    <div className="relative" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%" cy="50%" innerRadius={55} outerRadius={80}
            paddingAngle={3} dataKey="value" labelLine={false} label={renderLabel}
          >
            {data.map((_, i) => (
              <Cell key={i} fill={colors[i]} stroke="transparent" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: '#fff', border: '1px solid #e2e8f0',
              borderRadius: '8px', fontSize: '12px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      {innerLabel && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-700">{total}</div>
            <div className="text-[10px] text-gray-400 font-medium">{innerLabel}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// Wazuh-style summary row with donut charts
export function AgentSummaryRow({ stats }: { stats: { total: number; online: number; offline: number; active: number } }) {
  return (
    <div className="grid grid-cols-4 gap-4">
      <div className="bg-white rounded-card border border-gray-100 shadow-card p-4 flex items-center gap-4">
        <DonutChart
          data={[{ name: 'online', value: stats.online }, { name: 'offline', value: stats.offline }]}
          height={100} innerLabel="Agents"
        />
        <div>
          <div className="text-kpi text-brand-600">{stats.total}</div>
          <div className="text-xs text-gray-400">Total Agents</div>
          <div className="flex gap-3 mt-1">
            <span className="text-xs text-emerald-500">{stats.online} online</span>
            <span className="text-xs text-red-400">{stats.offline} offline</span>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-card border border-gray-100 shadow-card p-4">
        <div className="text-xs text-gray-400 mb-1">Active Alerts</div>
        <div className="text-kpi text-red-500">{stats.active || 0}</div>
      </div>

      <div className="bg-white rounded-card border border-gray-100 shadow-card p-4">
        <div className="text-xs text-gray-400 mb-1">Vulnerabilities</div>
        <div className="text-kpi text-amber-500">{stats.total || 0}</div>
      </div>

      <div className="bg-white rounded-card border border-gray-100 shadow-card p-4">
        <div className="text-xs text-gray-400 mb-1">Compliance Score</div>
        <div className="text-kpi text-emerald-500">{stats.active || 92}%</div>
      </div>
    </div>
  );
}

export function AlertSeverityPie({ data }: { data: { critical: number; high: number; medium: number; low: number; info: number } }) {
  const chartData = [
    { name: 'critical', value: data.critical },
    { name: 'high', value: data.high },
    { name: 'medium', value: data.medium },
    { name: 'low', value: data.low },
    { name: 'info', value: data.info },
  ].filter((d) => d.value > 0);

  return (
    <div className="bg-white rounded-card border border-gray-100 shadow-card p-4">
      <h3 className="text-sm font-semibold text-gray-700 mb-2">Alert Severity Distribution</h3>
      <div className="flex items-center gap-4">
        <div className="flex-1"><DonutChart data={chartData} height={180} innerLabel="Alerts" /></div>
        <div className="space-y-1.5">
          {chartData.map((d) => (
            <div key={d.name} className="flex items-center gap-2 text-xs">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: COLORS[d.name as keyof typeof COLORS] || '#0ca5ed' }} />
              <span className="text-gray-500 capitalize">{d.name}</span>
              <span className="text-gray-700 font-medium ml-auto">{d.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function EventTypePie({ data }: { data: Record<string, number> }) {
  const chartData = Object.entries(data).map(([name, value]) => ({ name, value }));

  return (
    <div className="bg-white rounded-card border border-gray-100 shadow-card p-4">
      <h3 className="text-sm font-semibold text-gray-700 mb-2">Event Types</h3>
      <DonutChart data={chartData} height={180} />
    </div>
  );
}
