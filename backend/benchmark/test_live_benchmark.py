import json
import time
import urllib.request
import statistics

BASE_URL = "http://127.0.0.1:8000"

def main():
    print("=" * 95)
    print(" REQUIREMENT 4: VERIFICATION SEQUENCE FOR REAL LIVE ACTIVE ATTACK BENCHMARK (use_live_state=true)")
    print("=" * 95)

    # 4a. Call POST /api/traffic/all
    print("[1] Executing POST /api/traffic/all to activate all 6 threat vectors...")
    req_all = urllib.request.Request(f"{BASE_URL}/api/traffic/all", method="POST")
    res_all = json.loads(urllib.request.urlopen(req_all).read().decode())
    print(f"    Response: {res_all}")

    # 4b. Call GET /api/status to confirm all 6 are active
    print("[2] Executing GET /api/status to confirm active attacks set...")
    res_status = json.loads(urllib.request.urlopen(f"{BASE_URL}/api/status").read().decode())
    print(f"    Active Attacks ({len(res_status.get('active_attacks', []))} vectors): {res_status.get('active_attacks')}")

    # 4c. Call POST /api/benchmark?num_flows=1000&use_live_state=true TEN times in a loop
    target_url = f"{BASE_URL}/api/benchmark?num_flows=1000&use_live_state=true"
    print(f"[3] Executing 10 POST requests to: {target_url}")
    print("-" * 95)
    print(f"{'Run':<6} | {'Flows/Sec':<12} | {'Exec Time (s)':<14} | {'Alerts':<8} | {'Total MB':<10} | {'Profile Name'}")
    print("-" * 95)

    live_fps = []
    live_times = []
    live_passes = []

    for i in range(1, 11):
        req = urllib.request.Request(target_url, method="POST")
        res_data = json.loads(urllib.request.urlopen(req).read().decode())

        fps = res_data.get("flows_per_second", 0.0)
        exec_t = res_data.get("execution_time_seconds", 0.0)
        passed = res_data.get("pass_target_high_throughput", False)
        profile = res_data.get("attack_vector_tested", "")
        alerts = res_data.get("alerts_detected", 0)
        total_mb = res_data.get("total_megabytes_processed", 0.0)

        live_fps.append(fps)
        live_times.append(exec_t)
        live_passes.append(passed)

        print(f"Run {i:<2}  | {fps:<12.2f} | {exec_t:<14.4f} | {alerts:<8} | {total_mb:<10.2f} | {profile}")
        time.sleep(0.5)

    # 4d. Summary stats
    print("=" * 95)
    print(" SUMMARY STATISTICS ACROSS 10 LIVE ACTIVE-ATTACK BENCHMARK RUNS:")
    print("=" * 95)
    print(f"Minimum Flows/Sec:       {min(live_fps):.2f}")
    print(f"Maximum Flows/Sec:       {max(live_fps):.2f}")
    print(f"Average Flows/Sec:       {statistics.mean(live_fps):.2f}")
    print(f"Std Deviation Flows/Sec: {statistics.stdev(live_fps):.2f}")
    print("=" * 95)

    # Requirement 5: Run ORIGINAL benign-only benchmark (use_live_state=false or omitted) 3 times
    print("\n" + "=" * 95)
    print(" REQUIREMENT 5: BENIGN-ONLY BASELINE BENCHMARK (use_live_state=false) - 3 RUNS")
    print("=" * 95)
    benign_url = f"{BASE_URL}/api/benchmark?num_flows=10000&use_live_state=false"
    print(f"Target URL: {benign_url}")
    print("-" * 95)
    print(f"{'Run':<6} | {'Flows/Sec':<14} | {'Exec Time (s)':<14} | {'Pass Target':<15} | {'Profile Name'}")
    print("-" * 95)

    for i in range(1, 4):
        req = urllib.request.Request(benign_url, method="POST")
        res_data = json.loads(urllib.request.urlopen(req).read().decode())
        fps = res_data.get("flows_per_second", 0.0)
        exec_t = res_data.get("execution_time_seconds", 0.0)
        passed = res_data.get("pass_target_high_throughput", False)
        profile = res_data.get("attack_vector_tested", "")

        print(f"Run {i:<2}  | {fps:<14.2f} | {exec_t:<14.4f} | {str(passed):<15} | {profile}")
        time.sleep(0.5)

    print("=" * 95)

if __name__ == "__main__":
    main()
