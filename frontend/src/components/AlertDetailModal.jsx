import React from 'react';
import { X, ShieldAlert, FileText, BarChart3, Lock, Copy, Check } from 'lucide-react';

export default function AlertDetailModal({ alert, onClose }) {
  const [copied, setCopied] = React.useState(false);
  if (!alert) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const shapList = alert.shap_explanations || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
      <div className="glass-panel-glow w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 shadow-2xl p-6 text-slate-100 relative">
        
        {/* Header */}
        <div className="flex items-start justify-between pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-500/50 text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-100">{alert.threat_name}</h2>
                <span className={`px-2.5 py-0.5 text-xs font-bold rounded-full ${
                  alert.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
                  'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                }`}>
                  {alert.severity}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">Flow ID: {alert.flow_id}</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Confidence Gauge & Key Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <div className="bg-slate-900/90 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Confidence Score</span>
            <div className="flex items-center justify-between">
              <span className="text-xl font-bold text-cyan-400 font-mono">
                {(alert.confidence_score * 100).toFixed(1)}%
              </span>
              <div className="w-16 bg-slate-800 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-cyan-400 h-full rounded-full"
                  style={{ width: `${alert.confidence_score * 100}%` }}
                ></div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/90 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Threat Class</span>
            <span className="text-sm font-semibold text-slate-200 font-mono uppercase">{alert.threat_class}</span>
          </div>

          <div className="bg-slate-900/90 p-3.5 rounded-xl border border-slate-800">
            <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">Timestamp (UTC)</span>
            <span className="text-xs font-mono text-slate-300">{alert.timestamp}</span>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Card */}
        {alert.mitre_attack_id && (
          <div className="bg-indigo-950/40 p-3.5 rounded-xl border border-indigo-500/40 mb-6 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-indigo-900/60 border border-indigo-500/40 text-indigo-300 font-mono font-bold text-xs">
                {alert.mitre_attack_id}
              </div>
              <div>
                <span className="text-[10px] uppercase font-bold tracking-wider text-indigo-400 block">
                  MITRE ATT&CK® Enterprise Matrix Technique
                </span>
                <h4 className="text-xs font-bold text-slate-100 mt-0.5">
                  {alert.mitre_technique_name || "Enterprise Threat Pattern"}
                </h4>
              </div>
            </div>
            <a
              href={`https://attack.mitre.org/techniques/${alert.mitre_attack_id.split('/')[0].trim()}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-1.5 rounded-lg bg-indigo-900/80 hover:bg-indigo-800 text-indigo-200 text-xs font-bold border border-indigo-500/40 transition whitespace-nowrap"
            >
              View MITRE Spec ↗
            </a>
          </div>
        )}

        {/* Section 1: SHAP & Supporting Evidence List */}
        <div className="mb-6">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2 mb-3">
            <BarChart3 className="w-4 h-4 text-emerald-400" />
            SHAP Feature Contributions & Supporting Evidence
          </h3>

          <div className="space-y-2.5">
            {shapList.map((item, idx) => (
              <div key={idx} className="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-emerald-300 font-mono">{item.feature_name}</span>
                  <span className="text-xs font-mono font-semibold text-cyan-400">
                    Impact: +{(item.impact_score * 100).toFixed(1)}%
                  </span>
                </div>
                <p className="text-xs text-slate-300">{item.description}</p>
                <div className="mt-2 w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-emerald-400 h-full rounded-full"
                    style={{ width: `${Math.min(item.impact_score * 100, 100)}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 2: Full Standardized Alert JSON Schema */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <FileText className="w-4 h-4 text-indigo-400" />
              Standardized JSON Alert Schema Output
            </h3>

            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied!" : "Copy JSON"}</span>
            </button>
          </div>

          <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-48 leading-relaxed">
            {JSON.stringify(alert, null, 2)}
          </pre>
        </div>

      </div>
    </div>
  );
}
