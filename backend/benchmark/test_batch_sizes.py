import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    all_attacks = ['c2_beaconing', 'encrypted_malware', 'port_scan', 'dga_dns_tunnel', 'exfiltration', 'ddos']
    batch_sizes = [50, 100, 150, 200, 300]

    print("=" * 95)
    print(" STEP 2: MICRO-BATCH SIZE TUNING EXPERIMENT (1,000 Flows, All 6 Active Attack Vectors)")
    print("=" * 95)
    print(f"{'Batch Size':<12} | {'Flows/Sec':<14} | {'Exec Time (s)':<14} | {'Avg Latency (ms)':<18} | {'Worst-Case Latency (ms)'}")
    print("-" * 95)

    results = []
    for bs in batch_sizes:
        report = run_throughput_benchmark(
            num_flows=1000,
            use_live_state=True,
            live_attacks=all_attacks,
            batch_size=bs
        )
        fps = report["flows_per_second"]
        exec_t = report["execution_time_seconds"]
        avg_lat = report["avg_microbatch_latency_ms"]
        worst_lat = report["worst_case_microbatch_latency_ms"]

        results.append({
            "batch_size": bs,
            "flows_per_second": fps,
            "execution_time_seconds": exec_t,
            "avg_microbatch_latency_ms": avg_lat,
            "worst_case_microbatch_latency_ms": worst_lat
        })

        print(f"{bs:<12} | {fps:<14.2f} | {exec_t:<14.4f} | {avg_lat:<18.2f} | {worst_lat:.2f}")

    print("=" * 95)

if __name__ == "__main__":
    main()
