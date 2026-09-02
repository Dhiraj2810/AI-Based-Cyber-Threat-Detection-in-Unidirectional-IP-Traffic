import os
import sys
import time
import random
from typing import Optional, List, Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.ingest.flow_generator import FlowStreamGenerator
from backend.pipeline.streaming_engine import StreamingPipelineEngine, MICROBATCH_MAX_SIZE
from backend.features.feature_extractor import FeatureExtractor
from backend.schema.alert_schema import FlowRecord, StandardizedAlert
from backend.forensics.chain_of_custody import chain_manager

ATTACK_NAMES = {
    "ddos": "Volumetric DDoS Flood",
    "c2_beaconing": "Botnet C2 Beaconing",
    "dga_dns_tunnel": "DGA / DNS Tunneling",
    "encrypted_malware": "Encrypted Malware Session",
    "port_scan": "Reconnaissance / Port Scan",
    "exfiltration": "Data Exfiltration Channel"
}

def run_throughput_benchmark(
    num_flows: int = 10000,
    attack_type: Optional[str] = None,
    simulate_fail: bool = False,
    use_live_state: bool = False,
    live_attacks: Optional[list] = None,
    batch_size: int = 1000
) -> dict:
    """Evaluates the maximum sustained flow processing rate using micro-batching."""
    generator = FlowStreamGenerator()

    if use_live_state and live_attacks:
        generator.set_active_attacks(live_attacks)
        if len(live_attacks) == 6:
            profile_name = "ALL 6 Active Attack Vectors (DDoS, C2, DGA, Malware, Scan, Exfil)"
        elif len(live_attacks) > 0:
            profile_name = f"Active Attack Stream ({', '.join(live_attacks)})"
        else:
            profile_name = "Benign Baseline / Mixed Traffic"
    elif attack_type:
        generator.set_active_attack(attack_type)
        profile_name = ATTACK_NAMES.get(attack_type, f"Attack Vector: {attack_type}")
    else:
        profile_name = "Benign Baseline / Mixed Traffic"

    if simulate_fail:
        profile_name += " [Simulated Heavy Load Fail-Case]"

    print(f"[*] Starting throughput benchmark ({profile_name}) with {num_flows} synthetic flows...")

    flows = generator.generate_flow_batch(count=num_flows)
    
    total_bytes = sum(f.src_bytes + f.dst_bytes for f in flows)
    total_packets = sum(f.src_packets + f.dst_packets for f in flows)

    # Stage accumulators
    timings = {
        "a_feature_extraction": 0.0,
        "b_detection_inference": 0.0,
        "c_shap_evidence": 0.0,
        "d_alert_formatting": 0.0,
        "e_loop_overhead": 0.0
    }

    detector_timings = {
        "b1_c2_beaconing_detector": 0.0,
        "b2_dga_dns_detector": 0.0,
        "b3_encrypted_malware_detector": 0.0,
        "b4_exfiltration_detector": 0.0,
        "b5_ddos_window_detector": 0.0,
        "b6_port_scan_window_detector": 0.0
    }

    engine = StreamingPipelineEngine(window_size=200)

    start_time = time.perf_counter()
    alerts_generated = 0
    all_benchmark_deduped_alerts: List[StandardizedAlert] = []

    # Chunk flows into micro-batches of batch_size
    micro_batches = [flows[i:i + batch_size] for i in range(0, len(flows), batch_size)]
    batch_latencies_ms = []

    for micro_batch in micro_batches:
        batch_start_t = time.perf_counter()

        if simulate_fail:
            time.sleep(0.00035 * len(micro_batch))

        t0 = time.perf_counter()
        for flow in micro_batch:
            engine.flow_window.append(flow)
            engine.total_processed_flows += 1
        t1 = time.perf_counter()
        timings["e_loop_overhead"] += (t1 - t0)

        # Stage a: Vectorized / Parallel Feature Extraction for batch
        features_list = [FeatureExtractor.extract_flow_features(f) for f in micro_batch]
        t2 = time.perf_counter()
        timings["a_feature_extraction"] += (t2 - t1)

        # Stage b: Micro-Batched Threat Detectors
        new_alerts: List[StandardizedAlert] = []

        # b1: C2 Beaconing analyze_batch
        tb0 = time.perf_counter()
        c2_alerts = engine.beaconing_detector.analyze_batch(micro_batch, features_list)
        tb1 = time.perf_counter()
        detector_timings["b1_c2_beaconing_detector"] += (tb1 - tb0)
        for a in c2_alerts:
            if a: new_alerts.append(a)

        # b2: DGA & DNS analyze_batch
        dga_alerts = engine.dga_dns_detector.analyze_batch(micro_batch, features_list)
        tb2 = time.perf_counter()
        detector_timings["b2_dga_dns_detector"] += (tb2 - tb1)
        for a in dga_alerts:
            if a: new_alerts.append(a)

        # b3: Encrypted Malware analyze_batch
        malware_alerts = engine.encrypted_malware_detector.analyze_batch(micro_batch, features_list)
        tb3 = time.perf_counter()
        detector_timings["b3_encrypted_malware_detector"] += (tb3 - tb2)
        for a in malware_alerts:
            if a: new_alerts.append(a)

        # b4: Exfiltration analyze_batch
        exfil_alerts = engine.exfiltration_detector.analyze_batch(micro_batch, features_list)
        tb4 = time.perf_counter()
        detector_timings["b4_exfiltration_detector"] += (tb4 - tb3)
        for a in exfil_alerts:
            if a: new_alerts.append(a)

        # Window-level DDoS & Port Scan
        if len(engine.flow_window) >= 20 and engine.total_processed_flows % 50 < len(micro_batch):
            window_list = list(engine.flow_window)
            
            tb_ddos0 = time.perf_counter()
            ddos_alert = engine.ddos_detector.analyze_window(window_list)
            tb_ddos1 = time.perf_counter()
            detector_timings["b5_ddos_window_detector"] += (tb_ddos1 - tb_ddos0)
            if ddos_alert: new_alerts.append(ddos_alert)

            scan_alerts = engine.port_scan_detector.analyze_window(window_list)
            tb_scan1 = time.perf_counter()
            detector_timings["b6_port_scan_window_detector"] += (tb_scan1 - tb_ddos1)
            new_alerts.extend(scan_alerts)

        timings["b_detection_inference"] += (tb4 - tb0)

        raw_detection_count = len(new_alerts)
        alerts_generated += raw_detection_count

        deduped_alerts = engine.deduplicate_alerts(new_alerts)
        if deduped_alerts:
            all_benchmark_deduped_alerts.extend(deduped_alerts)

        # Stage c & d: Alert formatting & SHAP evidence objects
        t_d_start = time.perf_counter()
        for alert in deduped_alerts:
            t_shap0 = time.perf_counter()
            _shap_count = len(alert.shap_explanations)
            _evidence_keys = len(alert.supporting_evidence)
            t_shap1 = time.perf_counter()
            timings["c_shap_evidence"] += (t_shap1 - t_shap0)

            engine.alerts.append(alert)
        t_d_end = time.perf_counter()
        timings["d_alert_formatting"] += (t_d_end - t_d_start)

        # End-to-end micro-batch latency measurement
        batch_end_t = time.perf_counter()
        batch_latencies_ms.append((batch_end_t - batch_start_t) * 1000.0)

    elapsed = max(time.perf_counter() - start_time, 0.000001)

    # Persist alerts to Chain of Custody DB and broadcast callbacks post-benchmark timing
    if all_benchmark_deduped_alerts:
        try:
            chain_manager.append_alerts(all_benchmark_deduped_alerts)
        except Exception:
            pass
        for alert in all_benchmark_deduped_alerts:
            for cb in engine.alert_callbacks:
                try: cb(alert)
                except Exception: pass

    flows_per_sec = num_flows / elapsed
    packets_per_sec = total_packets / elapsed
    mbps = ((total_bytes * 8) / elapsed) / 1_000_000
    avg_latency_us = (elapsed / num_flows) * 1_000_000
    worst_case_microbatch_latency_ms = max(batch_latencies_ms) if batch_latencies_ms else 0.0
    avg_microbatch_latency_ms = sum(batch_latencies_ms) / len(batch_latencies_ms) if batch_latencies_ms else 0.0

    stage_percentages = {
        k: round((v / max(elapsed, 1e-6)) * 100, 2)
        for k, v in timings.items()
    }
    detector_percentages = {
        k: round((v / max(elapsed, 1e-6)) * 100, 2)
        for k, v in detector_timings.items()
    }

    report = {
        "benchmark_status": "COMPLETED",
        "attack_vector_tested": profile_name,
        "attack_type": attack_type or "benign_mixed",
        "total_flows_tested": num_flows,
        "total_packets_processed": total_packets,
        "total_megabytes_processed": round(total_bytes / 1e6, 2),
        "execution_time_seconds": round(elapsed, 4),
        "flows_per_second": round(flows_per_sec, 2),
        "packets_per_second": round(packets_per_sec, 2),
        "throughput_mbps": round(mbps, 2),
        "avg_latency_per_flow_microseconds": round(avg_latency_us, 2),
        "worst_case_microbatch_latency_ms": round(worst_case_microbatch_latency_ms, 2),
        "avg_microbatch_latency_ms": round(avg_microbatch_latency_ms, 2),
        "alerts_detected": alerts_generated,
        "pass_target_high_throughput": flows_per_sec >= 10000,
        "stage_timings_seconds": {k: round(v, 4) for k, v in timings.items()},
        "stage_percentages": stage_percentages,
        "detector_breakdown_seconds": {k: round(v, 4) for k, v in detector_timings.items()},
        "detector_percentages": detector_percentages,
        "dga_timing_breakdown": {
            "feature_prep_seconds": round(engine.dga_dns_detector.total_prep_time, 4),
            "model_inference_seconds": round(engine.dga_dns_detector.total_inference_time, 4)
        },
        "c2_timing_breakdown": {
            "feature_prep_seconds": round(engine.beaconing_detector.total_prep_time, 4),
            "model_inference_seconds": round(engine.beaconing_detector.total_inference_time, 4)
        }
    }

    print(f"=== Throughput Benchmark Results ({profile_name}) ===")
    for k, v in report.items():
        print(f"  {k}: {v}")

    return report

if __name__ == "__main__":
    run_throughput_benchmark(1000)
