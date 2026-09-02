from typing import List, Optional, Dict
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence, FlowRecord
from backend.features.feature_extractor import FeatureExtractor

class PortScanDetector:
    def __init__(self, fanout_port_threshold: int = 15, fanout_host_threshold: int = 10):
        self.fanout_port_threshold = fanout_port_threshold
        self.fanout_host_threshold = fanout_host_threshold

    def analyze_window(self, window_flows: List[FlowRecord]) -> List[StandardizedAlert]:
        alerts = []
        if not window_flows:
            return alerts

        win_stats = FeatureExtractor.extract_window_features(window_flows)
        fan_out_ports = win_stats["fan_out_ports"]
        fan_out_hosts = win_stats["fan_out_hosts"]

        for src_ip, unique_ports in fan_out_ports.items():
            unique_hosts = fan_out_hosts.get(src_ip, 0)
            
            is_port_scan = unique_ports >= self.fanout_port_threshold
            is_host_sweep = unique_hosts >= self.fanout_host_threshold

            if is_port_scan or is_host_sweep:
                scan_type = "Vertical Port Scan" if is_port_scan and not is_host_sweep else (
                    "Horizontal Host Sweep" if is_host_sweep and not is_port_scan else "Hybrid Reconnaissance Sweep"
                )
                
                confidence = min(0.65 + (max(unique_ports, unique_hosts) / 50.0), 0.99)
                severity = "HIGH" if unique_ports > 30 or unique_hosts > 20 else "MEDIUM"

                # Find a sample flow from this source IP
                sample_flow = next((f for f in window_flows if f.src_ip == src_ip), window_flows[0])

                evidence = {
                    "source_ip": src_ip,
                    "unique_dest_ports": unique_ports,
                    "unique_dest_hosts": unique_hosts,
                    "scan_type": scan_type,
                    "threshold_ports": self.fanout_port_threshold,
                    "threshold_hosts": self.fanout_host_threshold
                }

                shap_items = [
                    AlertEvidence(
                        feature_name="unique_dest_ports",
                        value=unique_ports,
                        description=f"Source probed {unique_ports} unique ports in short time window",
                        impact_score=0.55 if is_port_scan else 0.25
                    ),
                    AlertEvidence(
                        feature_name="unique_dest_hosts",
                        value=unique_hosts,
                        description=f"Source targeted {unique_hosts} distinct internal IP addresses",
                        impact_score=0.45 if is_host_sweep else 0.20
                    )
                ]

                alert = StandardizedAlert(
                    flow_id=f"RECON_{src_ip}->MULTI:{sample_flow.dst_port}",
                    threat_class="port_scan",
                    threat_name=scan_type,
                    severity=severity,
                    confidence_score=round(confidence, 4),
                    supporting_evidence=evidence,
                    shap_explanations=shap_items,
                    mitre_attack_id="T1046",
                    mitre_technique_name="Network Service Discovery"
                )
                alerts.append(alert)

        return alerts
