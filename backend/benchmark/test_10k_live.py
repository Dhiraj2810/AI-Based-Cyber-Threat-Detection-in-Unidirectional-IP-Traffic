import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    all_attacks = ['ddos', 'c2_beaconing', 'dga_dns_tunnel', 'encrypted_malware', 'port_scan', 'exfiltration']
    print("=" * 80)
    print(" TESTING 10,000 FLOWS BENCHMARK WITH ALL 6 ATTACKS ACTIVE (use_live_state=true)")
    print("=" * 80)

    for r in range(1, 6):
        report = run_throughput_benchmark(
            num_flows=10000,
            use_live_state=True,
            live_attacks=all_attacks,
            batch_size=500
        )
        print(f"Run {r}: {report['flows_per_second']:.2f} flows/sec | Exec Time: {report['execution_time_seconds']:.4f}s | Pass Target: {report['pass_target_high_throughput']}")

    print("=" * 80)

if __name__ == "__main__":
    main()
