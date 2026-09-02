import React from 'react';
import { ShieldAlert, ArrowUpRight, Zap, Radio } from 'lucide-react';

const THREAT_BADGE_STYLES = {
  ddos: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  c2_beaconing: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  dga_dns_tunnel: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  encrypted_malware: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  port_scan: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  exfiltration: 'bg-orange-500/20 text-orange-400 border-orange-500/30'
};

export default function RealtimeAlertFeed({ alerts, onSelectAlert }) {
  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-rose-500 animate-pulse" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
            Real-Time Stream Threat Alert Feed
          </h2>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Showing latest {alerts.length} detections
        </span>
      </div>

      {alerts.length === 0 ? (
        <div className="p-8 text-center bg-slate-900/60 rounded-xl border border-dashed border-slate-800 text-slate-500 text-xs">
          Listening for ingress packet captures... No threat alerts detected in current stream window.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {alerts.slice(0, 6).map((alert, idx) => {
            const style = THREAT_BADGE_STYLES[alert.threat_class] || 'bg-slate-800 text-slate-300';
            return (
              <div
                key={idx}
                onClick={() => onSelectAlert(alert)}
                className="bg-slate-900/90 hover:bg-slate-900 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition cursor-pointer flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${style}`}>
                        {alert.threat_class.toUpperCase()}
                      </span>
                      {alert.mitre_attack_id && (
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-indigo-950/80 text-indigo-300 border border-indigo-500/40">
                          MITRE {alert.mitre_attack_id}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 font-semibold">
                      {(alert.confidence_score * 100).toFixed(0)}% Conf
                    </span>
                  </div>

                  <h3 className="text-xs font-bold text-slate-100 group-hover:text-cyan-400 transition mb-1">
                    {alert.threat_name}
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400 truncate mb-2">
                    {alert.flow_id}
                  </p>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                  <span>{new Date(alert.timestamp || Date.now()).toLocaleTimeString()}</span>
                  <span className="text-cyan-400 font-semibold flex items-center gap-0.5 group-hover:translate-x-0.5 transition">
                    View SHAP Evidence <ArrowUpRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
