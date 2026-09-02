import os
import sys
import time
import requests
import numpy as np

def main():
    base_url = "http://127.0.0.1:8000"
    
    # Activate ALL 6 vectors
    r = requests.post(f"{base_url}/api/traffic/all")
    print("[1] Activated all 6 vectors:", r.json())
    
    print("\n[2] EXECUTING 10x CACHE-HOSTILE BENCHMARK RUNS (num_flows=10000, ALL 6 VECTORS ACTIVE)...")
    print("=" * 88)
    print(f"{'Run':<6} | {'Flows/Sec':<14} | {'Exec Time (s)':<14} | {'Total MB':<12} | {'Throughput Mbps':<16} | {'Pass Target'}")
    print("-" * 88)

    fps_list = []
    exec_list = []
    mb_list = []
    mbps_list = []

    for i in range(1, 11):
        res = requests.post(f"{base_url}/api/benchmark?num_flows=10000&use_live_state=true").json()
        fps = res["flows_per_second"]
        exec_t = res["execution_time_seconds"]
        tot_mb = res["total_megabytes_processed"]
        mbps = res["throughput_mbps"]
        passed = res["pass_target_high_throughput"]

        fps_list.append(fps)
        exec_list.append(exec_t)
        mb_list.append(tot_mb)
        mbps_list.append(mbps)

        print(f"Run {i:<3} | {fps:<14.2f} | {exec_t:<14.4f} | {tot_mb:<12.2f} | {mbps:<16.2f} | {passed}")

    print("=" * 88)
    print(" SUMMARY STATISTICS ACROSS 10 CACHE-HOSTILE RUNS:")
    print("=" * 88)
    print(f"Minimum Flows/Sec:       {np.min(fps_list):.2f}")
    print(f"Maximum Flows/Sec:       {np.max(fps_list):.2f}")
    print(f"Average Flows/Sec:       {np.mean(fps_list):.2f}")
    print(f"Std Dev Flows/Sec:       {np.std(fps_list):.2f}")
    print(f"Average Throughput Mbps: {np.mean(mbps_list):.2f} Mbps")
    print(f"Average Exec Time:       {np.mean(exec_list):.4f} s")
    print(f"Pass Rate:               {sum(1 for f in fps_list if f >= 10000)} / 10 ({sum(1 for f in fps_list if f >= 10000)*10}%)")
    print("=" * 88)

if __name__ == "__main__":
    main()
