import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    all_attacks = ['c2_beaconing', 'encrypted_malware', 'port_scan', 'dga_dns_tunnel', 'exfiltration', 'ddos']
    print("=" * 80)
    print(" STAGE-BY-STAGE PROFILING RUN FOR LIVE ACTIVE ATTACK BENCHMARK")
    print("=" * 80)
    print(f"Active Attacks ({len(all_attacks)} vectors): {all_attacks}")
    print(f"Tested Flows: 1000")
    print("=" * 80)

    report = run_throughput_benchmark(
        num_flows=1000,
        use_live_state=True,
        live_attacks=all_attacks
    )

    print("\n" + "=" * 80)
    print(" PROFILING REPORT JSON BREAKDOWN:")
    print("=" * 80)
    print(json.dumps(report, indent=2))
    print("=" * 80)

if __name__ == "__main__":
    main()
