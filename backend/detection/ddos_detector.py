from typing import Optional, Dict, Any, List
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence, FlowRecord
from backend.features.feature_extractor import FeatureExtractor

class DDoSDetector:
    def __init__(self, pps_threshold: float = 25_000.0, bps_threshold: float = 750_000_000.0):
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold

    def analyze_window(self, window_flows: List[FlowRecord]) -> Optional[StandardizedAlert]:
        if not window_flows:
            return None
            
        win_stats = FeatureExtractor.extract_window_features(window_flows)
        total_pps = win_stats["total_pps"]
        total_bps = win_stats["total_bps"]
        entropy = win_stats["src_ip_entropy"]

        is_ddos = False
        confidence = 0.0
        threat_type = "Volumetric DDoS"

        if total_pps > self.pps_threshold or total_bps > self.bps_threshold:
            is_ddos = True
            # Compute confidence score based on rate excess and entropy anomaly
            rate_score = min(total_pps / (self.pps_threshold * 2), 1.0)
            
            if entropy < 1.5:
                threat_type = "Concentrated Botnet Pool Flood"
                confidence = min(0.70 + rate_score * 0.30, 0.99)
            elif entropy > 3.5:
                threat_type = "Spoofed-Source Random Flood"
                confidence = min(0.65 + rate_score * 0.35, 0.98)
            else:
                threat_type = "UDP/SYN Amplification Flood"
                confidence = min(0.60 + rate_score * 0.35, 0.95)

        if not is_ddos:
            return None

        # Sample representative flow id
        rep_flow = window_flows[-1]
        
        evidence = {
            "window_pps": round(total_pps, 2),
            "window_bps": round(total_bps, 2),
            "src_ip_entropy": round(entropy, 4),
            "flow_count_in_window": len(window_flows),
            "threshold_pps": self.pps_threshold,
            "attack_classification": threat_type
        }

        shap_items = [
            AlertEvidence(
                feature_name="window_pps",
                value=round(total_pps, 2),
                description=f"Packets per second ({round(total_pps, 1)}) exceeded safety limit ({self.pps_threshold})",
                impact_score=0.45
            ),
            AlertEvidence(
                feature_name="src_ip_entropy",
                value=round(entropy, 4),
                description=f"Source IP entropy {round(entropy, 2)} indicates {threat_type.lower()}",
                impact_score=0.35
            ),
            AlertEvidence(
                feature_name="window_bps",
                value=round(total_bps, 2),
                description=f"Bandwidth utilization reached {round(total_bps/1e6, 2)} Mbps",
                impact_score=0.20
            )
        ]

        return StandardizedAlert(
            flow_id=f"WINDOW_{rep_flow.dst_ip}:{rep_flow.dst_port}",
            threat_class="ddos",
            threat_name=threat_type,
            severity="CRITICAL" if confidence > 0.85 else "HIGH",
            confidence_score=round(confidence, 4),
            supporting_evidence=evidence,
            shap_explanations=shap_items,
            mitre_attack_id="T1498",
            mitre_technique_name="Network Denial of Service"
        )
