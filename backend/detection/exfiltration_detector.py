from datetime import datetime, timezone
from typing import Optional, List
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence, FlowRecord
from backend.features.feature_extractor import FeatureExtractor, calculate_shannon_entropy

class ExfiltrationDetector:
    def __init__(self, byte_ratio_threshold: float = 4.0, min_bytes_threshold: int = 1_000_000):
        self.byte_ratio_threshold = byte_ratio_threshold
        self.min_bytes_threshold = min_bytes_threshold

    def analyze_batch(self, batch: list, features_list: list, max_alerts: int = 2500) -> list:
        if not batch:
            return []

        # 1. Fast feature evaluation & candidate grouping per (src_ip, dst_ip)
        grouped_candidates = {}
        for flow, features in zip(batch, features_list):
            if flow.src_bytes < self.min_bytes_threshold and flow.src_bytes < 1_000_000:
                continue
            key = f"{flow.src_ip}|{flow.dst_ip}"
            if key not in grouped_candidates:
                grouped_candidates[key] = []
            grouped_candidates[key].append((flow, features))

        alerts = []
        for key, items in grouped_candidates.items():
            if len(alerts) >= max_alerts:
                break
            
            # Find highest confidence hit in group
            candidates = []
            for flow, features in items:
                alert = self.analyze_flow(flow, features)
                if alert:
                    candidates.append((flow, alert))

            if not candidates:
                continue

            first_flow, best_alert = candidates[0]
            max_conf = max(a.confidence_score for _, a in candidates)
            occurrence_count = len(candidates)

            evidence = dict(best_alert.supporting_evidence)
            evidence["occurrence_count"] = occurrence_count
            evidence["merged_alert_count"] = occurrence_count

            agg_alert = StandardizedAlert(
                flow_id=first_flow.flow_id,
                threat_class="exfiltration",
                threat_name=best_alert.threat_name,
                severity="CRITICAL" if max_conf > 0.88 else "HIGH",
                confidence_score=round(max_conf, 4),
                supporting_evidence=evidence,
                shap_explanations=best_alert.shap_explanations,
                mitre_attack_id="T1048",
                mitre_technique_name="Exfiltration Over Alternative Protocol",
                occurrence_count=occurrence_count,
                first_seen=datetime.fromtimestamp(candidates[0][0].timestamp, tz=timezone.utc).isoformat(),
                last_seen=datetime.fromtimestamp(candidates[-1][0].timestamp, tz=timezone.utc).isoformat()
            )
            alerts.append(agg_alert)

        return alerts

    def analyze_flow(self, flow: FlowRecord, features: Optional[dict] = None) -> Optional[StandardizedAlert]:
        if features is None:
            features = FeatureExtractor.extract_flow_features(flow)
        
        byte_ratio = features["byte_ratio"]
        src_bytes = flow.src_bytes
        dst_bytes = flow.dst_bytes
        duration = features["duration"]
        bps = features["bps"]

        is_exfiltration = False
        confidence = 0.0
        threat_type = "Asymmetric Data Exfiltration"

        is_standard_web_port = flow.dst_port in [80, 443, 8080]

        # Secondary Corroborating Risk Factors for Port 443/80 (use pre-computed features["tls_sni_entropy"]):
        sni_entropy = features.get("tls_sni_entropy", 0.0) if flow.tls_sni else 0.0
        has_suspicious_sni = (flow.tls_sni is None) or (sni_entropy > 3.8)
        has_restricted_tls = (flow.tls_cipher_suites_count is not None and flow.tls_cipher_suites_count <= 6) or (flow.tls_ja3 == "unknown")

        # 1. Non-standard port covert egress (Port not in [80, 443, 8080], Egress > 1 MB, Ratio > 4.0) -> High Risk
        if not is_standard_web_port and src_bytes > self.min_bytes_threshold and byte_ratio > self.byte_ratio_threshold:
            is_exfiltration = True
            threat_type = f"Non-Standard Port Covert Exfiltration (Port {flow.dst_port})"
            confidence = min(0.75 + (byte_ratio / 50.0) + (src_bytes / 50_000_000), 0.99)

        # 2. Bulk unidirectional web egress (Port in [80, 443, 8080], Egress > 5 MB, Ratio > 12.0) -> High Risk
        elif is_standard_web_port and src_bytes > 5_000_000 and byte_ratio > 12.0:
            is_exfiltration = True
            threat_type = "High-Volume Unidirectional Web Exfiltration"
            confidence = min(0.70 + (byte_ratio / 50.0) + (src_bytes / 50_000_000), 0.98)

        # 3. Stealthy Covert HTTPS Exfiltration on Web Ports (Ratio 4.0-12.0 + Corroborating SNI/TLS Risk Factor)
        elif is_standard_web_port and src_bytes > self.min_bytes_threshold and byte_ratio > self.byte_ratio_threshold and (has_suspicious_sni or has_restricted_tls):
            is_exfiltration = True
            threat_type = "Stealthy Corroborated HTTPS Covert Exfiltration"
            confidence = min(0.72 + (byte_ratio / 40.0) + (src_bytes / 40_000_000), 0.96)

        if not is_exfiltration:
            return None

        evidence = {
            "source_ip": flow.src_ip,
            "dest_ip": flow.dst_ip,
            "dest_port": flow.dst_port,
            "outbound_bytes": src_bytes,
            "inbound_bytes": dst_bytes,
            "outbound_to_inbound_byte_ratio": round(byte_ratio, 2),
            "bandwidth_bps": round(bps, 2),
            "duration_sec": round(duration, 2)
        }

        shap_items = [
            AlertEvidence(
                feature_name="outbound_to_inbound_byte_ratio",
                value=round(byte_ratio, 2),
                description=f"Outbound-to-inbound byte ratio ({round(byte_ratio, 1)}:1) indicates extreme asymmetric data egress",
                impact_score=0.55
            ),
            AlertEvidence(
                feature_name="outbound_bytes",
                value=src_bytes,
                description=f"Total egress volume reached {round(src_bytes / 1e6, 2)} MB",
                impact_score=0.30
            ),
            AlertEvidence(
                feature_name="dest_port",
                value=flow.dst_port,
                description=f"Target egress destination port {flow.dst_port}",
                impact_score=0.15
            )
        ]

        return StandardizedAlert(
            flow_id=flow.flow_id,
            threat_class="exfiltration",
            threat_name=threat_type,
            severity="CRITICAL" if confidence > 0.88 else "HIGH",
            confidence_score=round(confidence, 4),
            supporting_evidence=evidence,
            shap_explanations=shap_items,
            mitre_attack_id="T1048",
            mitre_technique_name="Exfiltration Over Alternative Protocol"
        )
