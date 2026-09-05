import os
import time
import joblib
import numpy as np
from typing import Optional, List
from datetime import datetime, timezone
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence, FlowRecord
from backend.features.feature_extractor import FeatureExtractor

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "c2_isolation_forest.joblib")

class BeaconingDetector:
    def __init__(self):
        self.model = None
        self.total_prep_time = 0.0
        self.total_inference_time = 0.0
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                if hasattr(self.model, "set_params"):
                    self.model.set_params(n_jobs=1)
                elif hasattr(self.model, "n_jobs"):
                    self.model.n_jobs = 1
            except Exception as e:
                print(f"[!] Warning: Could not load C2 model: {e}")

    def analyze_flow(self, flow: FlowRecord, features: Optional[dict] = None) -> Optional[StandardizedAlert]:
        results = self.analyze_batch([flow], [features] if features else None)
        return results[0] if results else None

    def analyze_batch(self, flows: List[FlowRecord], features_list: Optional[List[dict]] = None, max_alerts: int = 2500) -> List[Optional[StandardizedAlert]]:
        if not flows:
            return []

        # Fast rejection if no flow in batch has >= 4 packets
        if not any(f.src_packets + f.dst_packets >= 4 for f in flows):
            return []

        t_prep_start = time.perf_counter()

        if features_list is None:
            features_list = [FeatureExtractor.extract_flow_features(f) for f in flows]

        # Fast statistical pre-filter: skip expensive evaluation if no flow in batch has packets >= 4 and iat_cv < 0.30
        if not any(f.get("total_packets", 0) >= 4 and f.get("iat_cv", 1.0) < 0.30 for f in features_list):
            return []

        ml_indices = []
        ml_feature_rows = []
        pre_eval = []

        for idx, (flow, features) in enumerate(zip(flows, features_list)):
            iat_mean = features["iat_mean"]
            iat_std = features["iat_std"]
            iat_cv = features["iat_cv"]
            duration = features["duration"]
            packets = features["total_packets"]

            is_beacon = False
            confidence = 0.0

            if packets >= 4 and iat_cv < 0.20 and iat_mean > 0.5:
                is_beacon = True
                confidence = min(0.70 + (0.20 - iat_cv) * 1.5, 0.96)

            pre_eval.append({
                "iat_mean": iat_mean, "iat_std": iat_std, "iat_cv": iat_cv,
                "duration": duration, "packets": packets,
                "is_beacon": is_beacon, "confidence": confidence
            })

            if self.model and not is_beacon and packets >= 5 and iat_cv < 0.10 and iat_mean >= 1.0:
                ml_indices.append(idx)
                ml_feature_rows.append([iat_mean, iat_std, iat_cv, duration, packets])

        t_prep_end = time.perf_counter()
        self.total_prep_time += (t_prep_end - t_prep_start)

        t_infer_start = time.perf_counter()
        # Vectorized single-call model evaluation across all micro-batch candidate flows
        if self.model and ml_feature_rows:
            X = np.array(ml_feature_rows)  # Shape (M, 5)
            preds = self.model.predict(X)
            for i, idx in enumerate(ml_indices):
                if preds[i] == -1:
                    pre_eval[idx]["is_beacon"] = True
                    pre_eval[idx]["confidence"] = max(pre_eval[idx]["confidence"], 0.92)

        t_infer_end = time.perf_counter()
        self.total_inference_time += (t_infer_end - t_infer_start)

        grouped_candidates = {}
        for idx, (flow, info) in enumerate(zip(flows, pre_eval)):
            if not info["is_beacon"]:
                continue
            key = f"{flow.src_ip}|{flow.dst_ip}"
            if key not in grouped_candidates:
                grouped_candidates[key] = []
            grouped_candidates[key].append((flow, info))

        alerts: List[StandardizedAlert] = []
        for key, items in grouped_candidates.items():
            if len(alerts) >= max_alerts:
                break
            first_flow, first_info = items[0]
            max_conf = max(info["confidence"] for _, info in items)
            occurrence_count = len(items)

            evidence = {
                "source_ip": first_flow.src_ip,
                "dest_ip": first_flow.dst_ip,
                "dest_port": first_flow.dst_port,
                "inter_arrival_mean_sec": round(first_info["iat_mean"], 3),
                "inter_arrival_std_sec": round(first_info["iat_std"], 3),
                "coefficient_of_variation": round(first_info["iat_cv"], 4),
                "packet_count": first_info["packets"],
                "flow_duration_sec": round(first_info["duration"], 2),
                "occurrence_count": occurrence_count,
                "merged_alert_count": occurrence_count
            }

            shap_items = [
                AlertEvidence(
                    feature_name="coefficient_of_variation",
                    value=round(first_info["iat_cv"], 4),
                    description=f"Low timing variance (CV={round(first_info['iat_cv'], 4)}) confirms strict periodic beaconing interval (~{round(first_info['iat_mean'], 1)}s)",
                    impact_score=0.55
                ),
                AlertEvidence(
                    feature_name="inter_arrival_mean_sec",
                    value=round(first_info["iat_mean"], 3),
                    description=f"Persistent communication heartbeat observed every {round(first_info['iat_mean'], 1)} seconds",
                    impact_score=0.30
                ),
                AlertEvidence(
                    feature_name="packet_count",
                    value=first_info["packets"],
                    description=f"{first_info['packets']} probe requests recorded to suspected C2 endpoint",
                    impact_score=0.15
                )
            ]

            alert = StandardizedAlert(
                flow_id=first_flow.flow_id,
                threat_class="c2_beaconing",
                threat_name="Botnet C2 Periodic Beaconing",
                severity="CRITICAL" if max_conf > 0.85 else "HIGH",
                confidence_score=round(max_conf, 4),
                supporting_evidence=evidence,
                shap_explanations=shap_items,
                mitre_attack_id="T1071.001",
                mitre_technique_name="Application Layer Protocol: Web Protocols",
                occurrence_count=occurrence_count,
                first_seen=datetime.fromtimestamp(items[0][0].timestamp, tz=timezone.utc).isoformat(),
                last_seen=datetime.fromtimestamp(items[-1][0].timestamp, tz=timezone.utc).isoformat()
            )
            alerts.append(alert)

        return alerts
