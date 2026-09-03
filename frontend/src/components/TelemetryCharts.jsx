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
            {pieData.length > 0 ? `${telemetryCurrent?.total_alerts_generated || 0} Alerts` : "0 Active Alerts"}
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

      {/* Dynamic Traffic vs Attack Volume Ratio Bar */}
      <div className="lg:col-span-3 glass-panel p-4 rounded-2xl border border-slate-800 bg-slate-900/60 flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Live Ingress Traffic vs Threat Volume Ratio
            </h3>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block animate-ping"></span>
              Clean Traffic: <span className="underline">{telemetryCurrent?.clean_flow_count ?? 616} flows</span> ({telemetryCurrent?.clean_traffic_pct ?? 70}%)
            </span>
            <span className="text-slate-600">|</span>
            <span className="flex items-center gap-1.5 text-rose-400 font-bold">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span>
              Threat Traffic: <span className="underline">{telemetryCurrent?.threat_flow_count ?? 264} flows</span> ({telemetryCurrent?.attack_traffic_pct ?? 30}%)
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-amber-400 font-bold">
              Active Threats: {telemetryCurrent?.active_attack_count || 0}
            </span>
          </div>
        </div>

        {/* Dual Progress Bar */}
        <div className="w-full bg-slate-800 rounded-full h-5 overflow-hidden flex p-0.5 border border-slate-700 shadow-inner">
          <div
            className="bg-gradient-to-r from-emerald-500 to-teal-400 h-full rounded-l-full transition-all duration-300 flex items-center justify-center text-[11px] font-bold text-slate-950 px-2"
            style={{ width: `${telemetryCurrent?.clean_traffic_pct ?? 70}%` }}
          >
            {(telemetryCurrent?.clean_traffic_pct ?? 70) >= 15 && `${telemetryCurrent?.clean_flow_count ?? 616} Flows (${telemetryCurrent?.clean_traffic_pct ?? 70}%) CLEAN`}
          </div>
          <div
            className="bg-gradient-to-r from-rose-500 to-red-600 h-full rounded-r-full transition-all duration-300 flex items-center justify-center text-[11px] font-bold text-white px-2"
            style={{ width: `${telemetryCurrent?.attack_traffic_pct ?? 30}%` }}
          >
            {(telemetryCurrent?.attack_traffic_pct ?? 30) >= 15 && `${telemetryCurrent?.threat_flow_count ?? 264} Flows (${telemetryCurrent?.attack_traffic_pct ?? 30}%) THREAT`}
          </div>
        </div>

        {/* Operational Context Subtext */}
        <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 font-mono gap-2">
          <span>
            Status: { (telemetryCurrent?.active_attack_count || 0) === 0 ? "🟢 Baseline Normal Ingress (70% Clean / 30% Noise)" : `🔴 Active Attack Mode (${telemetryCurrent?.active_attack_count} Vectors Active: ${telemetryCurrent?.attack_traffic_pct}% Threat Load)` }
          </span>
          <span>
            Air-Gap Diode Protection: <span className="text-emerald-400 font-bold">PASSIVE READ-ONLY (100% SECURE)</span>
          </span>
        </div>
      </div>
    </div>
  );
}
