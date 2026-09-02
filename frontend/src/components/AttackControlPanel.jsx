import React, { useState } from 'react';
import { Zap, Play, Square, Gauge, Terminal, CheckCircle2, Flame, AlertTriangle, Upload, FileCheck } from 'lucide-react';

const THREAT_VECTOR_BUTTONS = [
  { id: 'ddos', name: 'Volumetric DDoS', color: 'bg-red-500/20 hover:bg-red-500/30 text-red-400 border-red-500/40', desc: 'SYN/UDP Floods + Source IP Entropy' },
  { id: 'c2_beaconing', name: 'Botnet C2 Beacon', color: 'bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 border-purple-500/40', desc: 'Low-Variance Inter-Arrival Timing' },
  { id: 'dga_dns_tunnel', name: 'DGA / DNS Tunnel', color: 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border-emerald-500/40', desc: 'High-Entropy Query & TXT Encoding' },
  { id: 'encrypted_malware', name: 'Encrypted Malware', color: 'bg-amber-500/20 hover:bg-amber-500/30 text-amber-400 border-amber-500/40', desc: 'JA3 / JA4 Threat Feed + TLS Metadata' },
  { id: 'port_scan', name: 'Port / Host Scan', color: 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border-cyan-500/40', desc: 'Fan-out Multi-Host & Multi-Port Sweep' },
  { id: 'exfiltration', name: 'Data Exfiltration', color: 'bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 border-orange-500/40', desc: 'Asymmetric Outbound Byte Ratio' },
];

export default function AttackControlPanel({ activeAttack, activeAttacks = [], onStartAttack, onStartAllAttacks, onStopAttack, onRunBenchmark }) {
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [loadingBench, setLoadingBench] = useState(false);
  const [pcapUploading, setPcapUploading] = useState(false);
  const [pcapResult, setPcapResult] = useState(null);

  const handlePcapUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setPcapUploading(true);
    setPcapResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/traffic/upload_pcap', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      setPcapResult(data);
    } catch (err) {
      setPcapResult({ error: 'Failed to upload and parse PCAP file.' });
    } finally {
      setPcapUploading(false);
    }
  };

  const activeSet = new Set(activeAttacks.length > 0 ? activeAttacks : (activeAttack ? [activeAttack] : []));

  const handleBenchmarkClick = async (simulateFail = false) => {
    setLoadingBench(true);
    setBenchmarkResult(null);
    try {
      const res = await onRunBenchmark(simulateFail);
      setBenchmarkResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingBench(false);
    }
  };

  const isPassed = benchmarkResult && Boolean(benchmarkResult.pass_target_high_throughput || benchmarkResult.flows_per_second >= 10000);

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800 mb-6">
      {/* Title Header */}
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Passive Multi-Attack Simulator & Benchmark Engine
          </h2>
          {activeSet.size > 0 && (
            <span className="text-[10px] bg-amber-950/80 text-amber-400 border border-amber-500/40 font-bold px-2 py-0.5 rounded">
              {activeSet.size} Attack{activeSet.size > 1 ? 's' : ''} Active Simultaneously
            </span>
          )}
        </div>
        <p className="text-xs text-slate-400 hidden sm:block">
          Click attack cards to toggle multiple threat vectors concurrently
        </p>
      </div>

      {/* Main 2-Column Split: 3x2 Attack Cards Grid on Left | Vertical Action Buttons on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        
        {/* Left Side: 3x2 Grid of 6 Attack Cards (8 cols on desktop) */}
        <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-3">
          {THREAT_VECTOR_BUTTONS.map((btn) => {
            const isSelected = activeSet.has(btn.id);
            return (
              <button
                key={btn.id}
                onClick={() => onStartAttack(btn.id)}
                className={`p-3.5 rounded-xl border text-left transition flex flex-col justify-between min-h-[96px] cursor-pointer relative group ${btn.color} ${
                  isSelected 
                    ? 'ring-2 ring-amber-400 shadow-xl shadow-amber-500/20 scale-[1.02] bg-slate-900/95 border-amber-500/60' 
                    : 'opacity-80 hover:opacity-100 hover:border-slate-600 bg-slate-900/40'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold">{btn.name}</span>
                    {isSelected ? (
                      <CheckCircle2 className="w-4 h-4 text-amber-400 fill-amber-400/20 shrink-0" />
                    ) : (
                      <div className="w-4 h-4 rounded-md border border-slate-600 bg-slate-950/60 shrink-0 group-hover:border-slate-400" />
                    )}
                  </div>
                  <p className="text-[10px] text-slate-300 opacity-90 leading-tight">{btn.desc}</p>
                </div>
                <div className="mt-2.5 flex items-center justify-between text-[10px] font-semibold tracking-wide uppercase">
                  <span className="flex items-center gap-1">
                    <Play className="w-3 h-3" />
                    {isSelected ? 'ACTIVE IN TRAFFIC' : 'CLICK TO SELECT'}
                  </span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${isSelected ? 'bg-amber-400/20 text-amber-300 border border-amber-400/40' : 'bg-slate-800 text-slate-400'}`}>
                    {isSelected ? 'ON' : 'OFF'}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Side: Vertical Stack of Control Buttons (4 cols on desktop) */}
        <div className="lg:col-span-4 flex flex-col justify-between gap-2.5 pl-0 lg:pl-3 lg:border-l lg:border-slate-800">
          
          {/* Button 1: Launch ALL 6 Vectors Simultaneously */}
          <button
            onClick={onStartAllAttacks}
            className="w-full flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-rose-600 hover:from-amber-500 hover:to-rose-500 text-white text-xs font-bold shadow-lg shadow-rose-500/20 border border-rose-400/30 transition min-h-[42px]"
          >
            <Flame className="w-4 h-4 text-amber-200" />
            <span>Launch ALL 6 Vectors Simultaneously</span>
          </button>

          {/* Button 2: Run Throughput Benchmark */}
          <button
            onClick={() => handleBenchmarkClick(false)}
            disabled={loadingBench}
            className="w-full flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold shadow-lg shadow-cyan-500/20 border border-cyan-400/30 transition disabled:opacity-50 min-h-[42px]"
          >
            <Gauge className="w-4 h-4 text-cyan-200" />
            <span>{loadingBench ? "Benchmarking..." : "Run Throughput Benchmark"}</span>
          </button>

          {/* Button 3: Test Fail-Case */}
          <button
            onClick={() => handleBenchmarkClick(true)}
            disabled={loadingBench}
            className="w-full flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-rose-950/90 hover:bg-rose-900/90 text-rose-300 text-xs font-bold border border-rose-500/50 shadow-md transition disabled:opacity-50 min-h-[42px]"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>Test Fail-Case</span>
          </button>

          {/* Button 4: Reset Baseline / Stop All Attacks (ALWAYS VISIBLE) */}
          <button
            onClick={onStopAttack}
            className={`w-full flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl text-xs font-bold border transition min-h-[42px] cursor-pointer ${
              activeSet.size > 0 
                ? 'bg-rose-950/90 hover:bg-rose-900 text-rose-200 border-rose-500/80 shadow-lg shadow-rose-950/50 animate-pulse' 
                : 'bg-slate-900/90 hover:bg-slate-800 text-slate-300 border-slate-700'
            }`}
          >
            <Square className="w-4 h-4 text-rose-400 fill-rose-400/20" />
            <span>{activeSet.size > 0 ? `Stop All ${activeSet.size} Attacks & Reset Baseline` : 'Reset to Benign Baseline (Stop All Attacks)'}</span>
          </button>

          {/* Button 5: Upload PCAP File */}
          <label className="w-full flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-indigo-950/80 hover:bg-indigo-900 text-indigo-300 text-xs font-bold border border-indigo-500/40 shadow-md transition cursor-pointer min-h-[42px]">
            <Upload className="w-4 h-4 text-indigo-400" />
            <span>{pcapUploading ? "Parsing PCAP..." : "Upload PCAP Capture File (.pcap/.pcapng)"}</span>
            <input type="file" accept=".pcap,.pcapng,.cap" onChange={handlePcapUpload} className="hidden" disabled={pcapUploading} />
          </label>

        </div>

      </div>

      {/* PCAP File Upload Result Banner */}
      {pcapResult && (
        <div className="mt-4 p-4 rounded-xl bg-indigo-950/40 border border-indigo-500/40 text-xs text-slate-200">
          <div className="flex items-center justify-between mb-2 pb-2 border-b border-indigo-500/30">
            <span className="font-bold text-indigo-300 flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-indigo-400" /> PCAP Ingestion Analysis ({pcapResult.filename})
            </span>
            <span className="text-[10px] px-2.5 py-0.5 rounded font-mono font-bold bg-indigo-900/60 text-indigo-200 border border-indigo-500/30">
              {pcapResult.parsed_flows || 0} Flows Extracted
            </span>
          </div>

          {pcapResult.error ? (
            <p className="text-rose-400 font-semibold">{pcapResult.error}</p>
          ) : (
            <div className="flex items-center justify-between text-[11px] font-mono">
              <span>File Size: {((pcapResult.file_size_bytes || 0) / 1024).toFixed(1)} KB</span>
              <span className="text-emerald-400 font-bold">
                {pcapResult.alerts_detected || 0} Threat Alerts Detected & Broadcasted
              </span>
            </div>
          )}
        </div>
      )}

      {/* Throughput Benchmark Result Modal / Banner */}
      {benchmarkResult && (
        <div className="mt-4 p-4 rounded-xl bg-slate-900/90 border border-cyan-500/40 text-xs">
          <div className="flex items-center justify-between mb-2 pb-2 border-b border-slate-800">
            <span className="font-bold text-cyan-400 flex items-center gap-2">
              <Terminal className="w-4 h-4" /> Throughput Benchmark Results
              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                isPassed ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40' : 'bg-rose-950/80 text-rose-400 border border-rose-500/40'
              }`}>
                {isPassed ? 'PASSED 10k FPS TARGET' : 'TARGET 10k FPS NOT MET'}
              </span>
            </span>
            <span className={`font-bold px-2.5 py-0.5 rounded border ${
              isPassed ? 'text-emerald-400 bg-emerald-950/60 border-emerald-500/30' : 'text-rose-400 bg-rose-950/60 border-rose-500/30'
            }`}>
              {benchmarkResult.flows_per_second} flows/sec
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px]">Tested Flows:</span>
              <span className="font-semibold">{benchmarkResult.total_flows_tested}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Bandwidth Throughput:</span>
              <span className="font-semibold">{benchmarkResult.throughput_mbps} Mbps</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Avg Latency per Flow:</span>
              <span className="font-semibold">{benchmarkResult.avg_latency_per_flow_microseconds} µs</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">Execution Time:</span>
              <span className="font-semibold">{benchmarkResult.execution_time_seconds}s</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
