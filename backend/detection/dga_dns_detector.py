import os
import time
import joblib
import numpy as np
from typing import Optional, List
from datetime import datetime, timezone
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence, FlowRecord
from backend.features.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "dga_lgbm.joblib")
VOWELS_SET = set("aeiouAEIOU")

class DGA_DNS_Detector:
    def __init__(self):
        self.model = None
        self.total_prep_time = 0.0
        self.total_inference_time = 0.0
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                if hasattr(self.model, "set_params"):
                    self.model.set_params(n_jobs=1)
            except Exception as e:
                print(f"[!] Warning: Could not load DGA model: {e}")

    def analyze_flow(self, flow: FlowRecord, features: Optional[dict] = None) -> Optional[StandardizedAlert]:
        results = self.analyze_batch([flow], [features] if features else None)
        return results[0] if results else None

    def analyze_batch(self, flows: List[FlowRecord], features_list: Optional[List[dict]] = None, max_alerts: int = 2500) -> List[Optional[StandardizedAlert]]:
        if not flows:
            return []

        # Fast rejection if no flow in batch has a DNS query domain
        if not any(f.dns_query_name for f in flows):
            return []

        t_prep_start = time.perf_counter()

        if features_list is None:
            features_list = [FeatureExtractor.extract_flow_features(f) for f in flows]

        alerts: List[Optional[StandardizedAlert]] = [None] * len(flows)

        ml_indices = []
        ml_feature_rows = []
        pre_eval = []

        for idx, (flow, features) in enumerate(zip(flows, features_list)):
            if not flow.dns_query_name:
                pre_eval.append(None)
                continue

            domain = flow.dns_query_name
            entropy = features["dns_entropy"]
            length = features["dns_len"]
            subdomains = features["subdomain_count"]
            query_type = flow.dns_query_type or "A"

            is_dga_or_tunnel = False
            threat_type = "Algorithmically Generated Domain (DGA)"
            confidence = 0.0

            if query_type in ["TXT", "NULL", "CNAME"] and (length > 30 or entropy > 4.2):
                is_dga_or_tunnel = True
                threat_type = "DNS Tunneling Exfiltration Vector"
                confidence = min(0.80 + (length / 100.0), 0.99)
            elif entropy > 3.8 and length > 15:
                is_dga_or_tunnel = True
                threat_type = "High-Entropy DGA Domain"
                confidence = min(0.70 + (entropy - 3.5) * 0.25, 0.95)

            vowel_ratio = 0.0
            digit_ratio = 0.0
            if is_dga_or_tunnel or (self.model and (entropy > 3.0 or length > 18 or query_type != "A")):
                vowels = sum(1 for c in domain if c in VOWELS_SET)
                vowel_ratio = vowels / max(length, 1)
                digits = sum(1 for c in domain if c.isdigit())
                digit_ratio = digits / max(length, 1)

            pre_eval.append({
                "domain": domain, "entropy": entropy, "length": length,
                "subdomains": subdomains, "query_type": query_type,
                "vowel_ratio": vowel_ratio, "digit_ratio": digit_ratio,
                "is_dga_or_tunnel": is_dga_or_tunnel,
                "threat_type": threat_type, "confidence": confidence
            })

            if self.model and not is_dga_or_tunnel and (entropy > 3.0 or length > 18 or query_type != "A"):
                ml_indices.append(idx)
                ml_feature_rows.append([entropy, length, vowel_ratio, digit_ratio, subdomains])

        t_prep_end = time.perf_counter()
        self.total_prep_time += (t_prep_end - t_prep_start)

        t_infer_start = time.perf_counter()
        # Vectorized single-call model evaluation across all micro-batch candidate flows
        if self.model and ml_feature_rows:
            X = np.array(ml_feature_rows)  # Shape (M, 5)
            probs = self.model.predict_proba(X)[:, 1]
            for i, idx in enumerate(ml_indices):
                prob = float(probs[i])
                if prob > 0.60:
                    pre_eval[idx]["is_dga_or_tunnel"] = True
                    pre_eval[idx]["confidence"] = max(pre_eval[idx]["confidence"], prob)

        t_infer_end = time.perf_counter()
        self.total_inference_time += (t_infer_end - t_infer_start)

        grouped_candidates = {}
        for idx, (flow, info) in enumerate(zip(flows, pre_eval)):
            if info is None or not info["is_dga_or_tunnel"]:
                continue
            src_ip = flow.src_ip or "0.0.0.0"
            if src_ip not in grouped_candidates:
                grouped_candidates[src_ip] = []
            grouped_candidates[src_ip].append((flow, info))

        alerts: List[StandardizedAlert] = []
        for src_ip, items in grouped_candidates.items():
            if len(alerts) >= max_alerts:
                break
            first_flow, first_info = items[0]
            max_conf = max(info["confidence"] for _, info in items)
            occurrence_count = len(items)

            evidence = {
                "src_ip": src_ip,
                "dns_query_name": first_info["domain"],
                "dns_entropy": round(first_info["entropy"], 4),
                "domain_length": first_info["length"],
                "query_type": first_info["query_type"],
                "subdomain_depth": first_info["subdomains"],
                "vowel_ratio": round(first_info["vowel_ratio"], 3),
                "digit_ratio": round(first_info["digit_ratio"], 3),
                "threat_classification": first_info["threat_type"],
                "occurrence_count": occurrence_count,
                "merged_alert_count": occurrence_count
            }

            shap_items = [
                AlertEvidence(
                    feature_name="dns_entropy",
                    value=round(first_info["entropy"], 4),
                    description=f"Domain Shannon entropy ({round(first_info['entropy'], 2)}) significantly exceeds natural language distribution (~2.8)",
                    impact_score=0.45
                ),
                AlertEvidence(
                    feature_name="domain_length",
                    value=first_info["length"],
                    description=f"Query string length ({first_info['length']} chars) indicative of encoded data stream or synthetic generator",
                    impact_score=0.35
                ),
                AlertEvidence(
                    feature_name="query_type",
                    value=first_info["query_type"],
                    description=f"Resource record type '{first_info['query_type']}' frequently weaponized for DNS tunnel payloads",
                    impact_score=0.20
                )
            ]

            alert = StandardizedAlert(
                flow_id=first_flow.flow_id,
                threat_class="dga_dns_tunnel",
                threat_name=first_info["threat_type"],
                severity="CRITICAL" if max_conf > 0.85 else "HIGH",
                confidence_score=round(max_conf, 4),
                supporting_evidence=evidence,
                shap_explanations=shap_items,
                mitre_attack_id="T1568.002",
                mitre_technique_name="Domain Generation Algorithms",
                occurrence_count=occurrence_count,
                first_seen=datetime.fromtimestamp(items[0][0].timestamp, tz=timezone.utc).isoformat(),
                last_seen=datetime.fromtimestamp(items[-1][0].timestamp, tz=timezone.utc).isoformat()
            )
            alerts.append(alert)

        return alerts
