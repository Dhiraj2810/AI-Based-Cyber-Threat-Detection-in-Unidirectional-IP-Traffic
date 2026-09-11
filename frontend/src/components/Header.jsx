import React from 'react';
import { ShieldCheck, Lock, Activity, Zap, Cpu, ArrowUpRight } from 'lucide-react';

export default function Header({ status, telemetry }) {
  const current = telemetry?.current || {};
  const activeAttacks = status?.active_attacks?.length > 0 
    ? status.active_attacks 
    : (status?.active_attack ? [status.active_attack] : []);
  const isActiveAttack = activeAttacks.length > 0;

  return (
    <header className="glass-panel border-b border-slate-800 px-6 py-4 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Title & Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap sm:flex-nowrap">
              <h1 className="text-lg sm:text-xl font-bold tracking-wider text-slate-100 uppercase whitespace-nowrap">
                <span className="text-cyan-400 font-extrabold">VajraRaksha</span>
                <span className="text-slate-400 mx-2 font-normal">:</span>
                <span>Passive-Diode AI Enclave</span>
              </h1>
              <span className="px-2.5 py-0.5 text-[11px] font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 whitespace-nowrap shrink-0">
                v1.0 REAL-TIME
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Hardware Data Diode Ingress (Strictly Read-Only, 0 Write-Back Path)</span>
            </p>
          </div>
        </div>

        {/* Live Metrics & Diode Status Pill */}
        <div className="flex items-center gap-4 flex-wrap justify-end">
          {/* Active Attack Alert Badge */}
          {isActiveAttack && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-500/50 text-rose-400 text-xs font-semibold animate-pulse">
              <Zap className="w-4 h-4" />
              <span>
                ATTACK INJECTED: {activeAttacks.length > 1 ? `${activeAttacks.length} VECTORS ACTIVE (${activeAttacks.map(a => a.toUpperCase()).join(', ')})` : activeAttacks[0].toUpperCase()}
              </span>
            </div>
          )}

          {/* Diode Hardware Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
            <span className="text-slate-300 font-medium">Link Status:</span>
            <span className="text-emerald-400 font-semibold">{status?.diode_status || "ONLINE"}</span>
          </div>

          {/* Flows / sec */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">Flows/s:</span>
            <span className="text-slate-100 font-bold">{current.flows_per_sec || 0}</span>
          </div>

          {/* Total Processed */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
            <Cpu className="w-4 h-4 text-indigo-400" />
            <span className="text-slate-400">Total Flows:</span>
            <span className="text-slate-100 font-bold">{current.total_processed_flows || 0}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
