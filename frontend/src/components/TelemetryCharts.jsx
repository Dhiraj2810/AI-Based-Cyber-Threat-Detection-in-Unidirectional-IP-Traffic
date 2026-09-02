import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar
} from 'recharts';
import { Activity, BarChart2, Hash } from 'lucide-react';

const THREAT_COLORS = {
  ddos: '#ef4444',
  c2_beaconing: '#a855f7',
  dga_dns_tunnel: '#10b981',
  encrypted_malware: '#f59e0b',
  port_scan: '#06b6d4',
  exfiltration: '#f97316'
};

export default function TelemetryCharts({ telemetryHistory, telemetryCurrent }) {
  // Format telemetry history for charts
  const chartData = (telemetryHistory || []).map((t, index) => ({
    time: index,
    fps: t.flows_per_sec || 0,
    entropy: t.src_ip_entropy || 0,
    pps: t.total_pps || 0
  }));

  // Threat distribution data for Pie Chart
  const threatDist = telemetryCurrent?.threat_distribution || {};
  const pieData = Object.entries(threatDist).map(([key, val]) => ({
    name: key.replace(/_/g, ' ').toUpperCase(),
    value: val,
    color: THREAT_COLORS[key] || '#94a3b8'
  })).filter(d => d.value > 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
      {/* Chart 1: Source IP Shannon Entropy Over Time */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <Hash className="w-4 h-4 text-cyan-400" />
            Source IP Shannon Entropy H(X)
          </h3>
          <span className="text-xs font-bold text-cyan-400 font-mono">
            {telemetryCurrent?.src_ip_entropy || "0.00"}
          </span>
        </div>
        <p className="text-[10px] text-slate-400 mb-3">
          Low entropy indicates targeted botnet pool; high entropy indicates random spoofed flood.
        </p>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <XAxis dataKey="time" hide />
              <YAxis domain={[0, 8]} stroke="#64748b" fontSize={10} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Line type="monotone" dataKey="entropy" stroke="#06b6d4" strokeWidth={3} dot={{ r: 2, fill: '#06b6d4' }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: Flow Ingress Rate (Flows/sec & Packets/sec) */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-emerald-400" />
            Passive Ingress Flow Rate (Flows/s)
          </h3>
          <span className="text-xs font-bold text-emerald-400 font-mono">
            {telemetryCurrent?.flows_per_sec || 0} fps
          </span>
        </div>
        <p className="text-[10px] text-slate-400 mb-3">
          Sustained processing throughput across the sliding stream window.
        </p>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <XAxis dataKey="time" hide />
              <YAxis domain={[0, 'auto']} stroke="#64748b" fontSize={10} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
              />
              <Line type="monotone" dataKey="fps" stroke="#10b981" strokeWidth={3} dot={{ r: 2, fill: '#10b981' }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 3: Detected Threat Category Breakdown */}
      <div className="glass-panel p-4 rounded-2xl border border-slate-800 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <BarChart2 className="w-4 h-4 text-amber-400" />
            Detected Threat Class Breakdown
          </h3>
          <span className="text-xs font-bold text-amber-400 font-mono">
            {telemetryCurrent?.total_alerts_generated || 0} Alerts
          </span>
        </div>
        <p className="text-[10px] text-slate-400 mb-3">
          Distribution across 6 passive threat detection modules.
        </p>

        <div className="h-44 w-full flex items-center justify-center">
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={35}
                  outerRadius={65}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, idx) => (
                    <Cell key={`cell-${idx}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center text-slate-500 text-xs">
              No threat alerts generated yet.<br />Inject an attack vector above!
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
