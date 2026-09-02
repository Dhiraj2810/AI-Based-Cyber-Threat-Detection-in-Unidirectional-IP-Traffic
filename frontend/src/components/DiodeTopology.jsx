import React from 'react';
import { Server, ArrowRight, ShieldCheck, Lock, Eye, AlertOctagon } from 'lucide-react';

export default function DiodeTopology() {
  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Eye className="w-4 h-4 text-cyan-400" />
          Unidirectional Physical Link & Enclave Chain of Custody
        </h2>
        <span className="text-xs text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5">
          <Lock className="w-3.5 h-3.5" /> Physical Optical Diode (1-Way Ingress)
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 items-center text-center">
        {/* Node 1: Production Core Network */}
        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 flex flex-col items-center">
          <Server className="w-6 h-6 text-slate-400 mb-1" />
          <span className="text-xs font-bold text-slate-200">Production Core Network</span>
          <span className="text-[10px] text-slate-500 mt-1">Live Monitored Links / Mirror TAP</span>
        </div>

        {/* Arrow 1 */}
        <div className="hidden md:flex flex-col items-center justify-center text-cyan-500">
          <span className="text-[10px] uppercase font-mono text-cyan-400 mb-1">Mirror Packets</span>
          <ArrowRight className="w-6 h-6 animate-pulse" />
        </div>

        {/* Node 2: Hardware Data Diode */}
        <div className="bg-cyan-950/40 p-4 rounded-xl border border-cyan-500/40 flex flex-col items-center relative overflow-hidden">
          <div className="absolute -right-4 -bottom-4 w-12 h-12 bg-cyan-500/10 rounded-full blur-xl"></div>
          <Lock className="w-6 h-6 text-cyan-400 mb-1" />
          <span className="text-xs font-bold text-cyan-300">Hardware Data Diode</span>
          <span className="text-[10px] text-cyan-500 font-semibold mt-1">Tx Only Optical Transmitter</span>
        </div>

        {/* Arrow 2 with NO-RETURN symbol */}
        <div className="hidden md:flex flex-col items-center justify-center text-emerald-400">
          <div className="flex items-center gap-1 text-[10px] font-mono text-rose-400 mb-1">
            <AlertOctagon className="w-3 h-3" /> NO Return Path
          </div>
          <ArrowRight className="w-6 h-6 animate-pulse" />
        </div>

        {/* Node 3: AI Detection Enclave */}
        <div className="bg-indigo-950/40 p-4 rounded-xl border border-indigo-500/40 flex flex-col items-center">
          <ShieldCheck className="w-6 h-6 text-indigo-400 mb-1" />
          <span className="text-xs font-bold text-indigo-200">Isolated Monitoring Enclave</span>
          <span className="text-[10px] text-indigo-400 mt-1">6-Vector AI Pipeline + SHAP</span>
        </div>
      </div>
    </div>
  );
}
