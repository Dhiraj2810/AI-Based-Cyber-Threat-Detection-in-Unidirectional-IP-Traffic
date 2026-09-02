import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    all_attacks = ['encrypted_malware', 'exfiltration', 'ddos', 'c2_beaconing', 'dga_dns_tunnel', 'port_scan']
    print("RUNNING DIAGNOSTIC BREAKDOWN ACROSS 5 RUNS...")

    for i in range(1, 6):
        report = run_throughput_benchmark(
            num_flows=10000,
            use_live_state=True,
            live_attacks=all_attacks,
            batch_size=500
        )
        print(f"\n--- RUN {i} ---")
        print(f"Flows/Sec: {report['flows_per_second']:.2f}")
        print(f"Exec Time: {report['execution_time_seconds']:.4f}s")
        print("Stage Timings:", report['stage_timings_seconds'])
        print("Detector Breakdown:", report['detector_breakdown_seconds'])

if __name__ == "__main__":
    main()
