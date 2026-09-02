import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    attacks = ['ddos', 'c2_beaconing']
    print("=" * 80)
    print(" TESTING 10,000 FLOWS BENCHMARK WITH DDoS + C2 BEACONING")
    print("=" * 80)

    report = run_throughput_benchmark(
        num_flows=10000,
        use_live_state=True,
        live_attacks=attacks,
        batch_size=500
    )
    print(f"Flows/Sec: {report['flows_per_second']:.2f}")
    print(f"Exec Time: {report['execution_time_seconds']:.4f}s")
    print("Stage timings:", report['stage_timings_seconds'])
    print("Detector breakdown:", report['detector_breakdown_seconds'])

if __name__ == "__main__":
    main()
