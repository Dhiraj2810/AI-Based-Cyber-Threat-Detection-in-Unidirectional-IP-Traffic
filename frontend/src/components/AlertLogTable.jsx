import React, { useState, useEffect } from 'react';
import { Search, Filter, Download, ExternalLink, ShieldCheck, Link2, ShieldAlert, RefreshCw, AlertOctagon, CheckCircle2 } from 'lucide-react';

export default function AlertLogTable({ alerts, onSelectAlert }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedThreat, setSelectedThreat] = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');

  // Chain of Custody Forensic State
  const [chainReport, setChainReport] = useState(null);
  const [loadingChain, setLoadingChain] = useState(false);

  const fetchChainStatus = async (includeArchive = false) => {
    setLoadingChain(true);
    try {
      const res = await fetch(`/api/chain/verify?include_archive=${includeArchive}`);
      const data = await res.json();
      setChainReport(data);
    } catch (err) {
      console.error("Failed to verify chain of custody:", err);
    } finally {
      setLoadingChain(false);
    }
  };

  useEffect(() => {
    fetchChainStatus(false);
    const interval = setInterval(() => fetchChainStatus(false), 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateTamper = async () => {
    setLoadingChain(true);
    try {
      await fetch('/api/chain/tamper_test?sequence_number=1', { method: 'POST' });
      await fetchChainStatus();
    } catch (err) {
      console.error("Failed to trigger tamper test:", err);
    } finally {
      setLoadingChain(false);
    }
  };

  const handleResetChain = async () => {
    setLoadingChain(true);
    try {
      await fetch('/api/chain/reset', { method: 'POST' });
      await fetchChainStatus();
    } catch (err) {
      console.error("Failed to reset chain:", err);
    } finally {
      setLoadingChain(false);
    }
  };

  const handleArchiveChain = async () => {
    setLoadingChain(true);
    try {
      await fetch('/api/chain/archive', { method: 'POST' });
      await fetchChainStatus();
    } catch (err) {
      console.error("Failed to trigger chain archiving:", err);
    } finally {
      setLoadingChain(false);
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.threat_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.flow_id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesThreat = selectedThreat === 'ALL' || alert.threat_class === selectedThreat;
    const matchesSeverity = selectedSeverity === 'ALL' || alert.severity === selectedSeverity;

    return matchesSearch && matchesThreat && matchesSeverity;
  });

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredAlerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `unidirectional_threat_alerts_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800">
      
      {/* Cryptographic Chain of Custody Forensic Banner */}
      <div className="mb-5 p-4 rounded-xl bg-slate-950/80 border border-slate-800 shadow-inner">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 mb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-950/80 text-indigo-400 border border-indigo-500/30">
              <Link2 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                Cryptographic Forensic Chain of Custody (Segmented SHA-256 Hash Chain)
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Every alert log entry is cryptographically linked. Live chain stays fast while historical entries are preserved in <code className="text-cyan-400 font-mono">chain_of_custody_archive.db</code>.
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => fetchChainStatus(true)}
              disabled={loadingChain}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-semibold border border-slate-700 transition"
              title="Re-verify entire SHA-256 hash chain"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingChain ? 'animate-spin' : ''}`} />
              <span>Verify Chain</span>
            </button>

            <button
              onClick={handleArchiveChain}
              disabled={loadingChain}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 text-cyan-300 text-xs font-semibold border border-cyan-500/40 transition"
              title="Move older live entries to chain_of_custody_archive.db"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Trigger Segmentation Archive</span>
            </button>

            <button
              onClick={handleSimulateTamper}
              disabled={loadingChain}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 text-rose-300 text-xs font-semibold border border-rose-500/40 transition"
              title="Simulate insider evidence tampering attack"
            >
              <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
              <span>Simulate Tamper</span>
            </button>
          </div>
        </div>

        {/* Status Indicator Pill & Detailed Segmentation Stats */}
        {chainReport && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 flex-wrap">
              {chainReport.is_valid ? (
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-500/50 flex items-center gap-1.5 shadow-lg shadow-emerald-950/50">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  Chain Status: VERIFIED ✓
                </span>
              ) : (
                <span className="px-3 py-1 rounded-full text-xs font-bold bg-rose-950/90 text-rose-300 border border-rose-500/80 flex items-center gap-1.5 animate-pulse shadow-lg shadow-rose-950/80">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  TAMPERING DETECTED at entry #{chainReport.broken_sequence_number}
                </span>
              )}

              {/* Segmentation Breakdown Badges */}
              <div className="flex items-center gap-1.5 font-mono text-[11px] ml-1">
                <span className="px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-700">
                  Live: <strong className="text-slate-100">{chainReport.live_entries ?? chainReport.total_entries}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-900 text-indigo-400 border border-slate-700">
                  Archived: <strong className="text-slate-100">{chainReport.archived_entries ?? 0}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-900 text-amber-400 border border-slate-700">
                  Total Persisted: <strong className="text-slate-100">{chainReport.total_entries}</strong>
                </span>
              </div>
            </div>

            <span className="text-[11px] font-mono text-slate-400">
              {chainReport.details}
            </span>
          </div>
        )}
      </div>

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            Standardized Alert Audit Log ({filteredAlerts.length} Detections)
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Full compliance audit log formatted with standardized JSON evidence schema.
          </p>
        </div>

        {/* Filter Bar & Export */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search flow ID or threat..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-xs text-slate-200 rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-44"
            />
          </div>

          {/* Threat Filter */}
          <select
            value={selectedThreat}
            onChange={(e) => setSelectedThreat(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Threat Classes</option>
            <option value="ddos">DDoS</option>
            <option value="c2_beaconing">C2 Beaconing</option>
            <option value="dga_dns_tunnel">DGA / DNS Tunnel</option>
            <option value="encrypted_malware">Encrypted Malware</option>
            <option value="port_scan">Port Scan</option>
            <option value="exfiltration">Exfiltration</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-xs text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
          </select>

          {/* Export JSON Button */}
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" /> Export Audit Log
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/90 text-slate-400 font-mono text-[11px] uppercase border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Timestamp (UTC)</th>
              <th className="py-2.5 px-3">MITRE ATT&CK</th>
              <th className="py-2.5 px-3">Threat Category</th>
              <th className="py-2.5 px-3">Flow Identifier</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Confidence</th>
              <th className="py-2.5 px-3 text-right">SHAP Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-6 text-center text-slate-500">
                  No matching threat alert records found.
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert, idx) => (
                <tr key={idx} className="hover:bg-slate-900/60 transition">
                  <td className="py-2.5 px-3 text-slate-400">{(alert.timestamp || new Date().toISOString()).split('T')[1]?.slice(0, 8) || 'N/A'}</td>
                  <td className="py-2.5 px-3">
                    {alert.mitre_attack_id ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-500/40">
                        {alert.mitre_attack_id}
                      </span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-cyan-400">{alert.threat_class}</td>
                  <td className="py-2.5 px-3 text-slate-200 truncate max-w-xs">{alert.flow_id}</td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      alert.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-slate-100">
                    {(alert.confidence_score * 100).toFixed(1)}%
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={() => onSelectAlert(alert)}
                      className="text-cyan-400 hover:text-cyan-300 font-semibold underline inline-flex items-center gap-1"
                    >
                      Inspect Evidence <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
