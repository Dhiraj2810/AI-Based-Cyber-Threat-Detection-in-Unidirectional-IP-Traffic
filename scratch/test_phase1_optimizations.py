import os
import sys
sys.path.insert(0, "d:/PS SIH26145")

import time
import statistics
from backend.benchmark.throughput_benchmark import run_throughput_benchmark

def main():
    print("=" * 80)
    print("TESTING PHASE 1 OPTIMIZATIONS ACROSS ALL ATTACK SCENARIOS")
    print("=" * 80)

    scenarios = [
        ("a. Baseline (0 attacks)", None, None, False),
        ("b1. 1 Attack: DDoS", "ddos", None, False),
        ("b2. 1 Attack: Beaconing", "c2_beaconing", None, False),
        ("b3. 1 Attack: Encrypted Malware", "encrypted_malware", None, False),
        ("c. 3 Attacks (DDoS, Beaconing, DGA)", None, ["ddos", "c2_beaconing", "dga_dns_tunnel"], True),
        ("d. 5 Attacks (All except Exfil)", None, ["ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan"], True),
        ("e. All 6 Attacks Active", None, ["ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "port_scan", "exfiltration"], True)
    ]

    for label, single_attack, multi_attacks, use_live in scenarios:
        print(f"\nEvaluating: {label}")
        fps_list = []
        exec_times = []
        for i in range(10):
            report = run_throughput_benchmark(
                num_flows=10000,
                attack_type=single_attack,
                use_live_state=use_live,
                live_attacks=multi_attacks,
                batch_size=1000
            )
            fps = report.get("flows_per_second", 0.0)
            exec_t = report.get("execution_time_seconds", 0.0)
            fps_list.append(fps)
            exec_times.append(exec_t)

        min_fps = min(fps_list)
        max_fps = max(fps_list)
        avg_fps = statistics.mean(fps_list)
        std_fps = statistics.stdev(fps_list)
        pass_count = sum(1 for f in fps_list if f >= 10000)
        pass_pct = (pass_count / 10) * 100.0

        print(f"  Min FPS: {min_fps:.2f} | Max FPS: {max_fps:.2f} | Avg FPS: {avg_fps:.2f} | Std Dev: {std_fps:.2f}")
        print(f"  Target 10,000 FPS Pass Rate: {pass_pct:.0f}% ({pass_count}/10 runs)")

if __name__ == "__main__":
    main()
