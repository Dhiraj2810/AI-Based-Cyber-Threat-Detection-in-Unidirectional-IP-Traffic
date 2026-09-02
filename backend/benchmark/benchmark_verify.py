import json
import time
import urllib.request
import statistics

BASE_URL = "http://127.0.0.1:8000"
ENDPOINT_PATH = "/api/benchmark"
PARAMS = "?num_flows=10000"
FULL_URL = f"{BASE_URL}{ENDPOINT_PATH}{PARAMS}"

def main():
    print("=" * 75)
    print(" UNAMBIGUOUS DEFINITIVE THROUGHPUT BENCHMARK VERIFICATION SCRIPT")
    print("=" * 75)
    print(f"Target URL:              {FULL_URL}")
    print(f"Bypassing UI:            YES (Direct HTTP POST request)")
    print(f"Explicit Parameter Check: simulate_fail is NOT PRESENT (simulate_fail=False)")
    print(f"Loop Iterations:         10 runs")
    print("=" * 75)

    # 1. Verify all 6 attack vectors are active on the server
    try:
        status_resp = urllib.request.urlopen(f"{BASE_URL}/api/status").read().decode()
        status_data = json.loads(status_resp)
        active_attacks = status_data.get("active_attacks", [])
        print(f"Current Server Active Attacks ({len(active_attacks)} vectors): {active_attacks}")
    except Exception as e:
        print(f"[!] Could not query /api/status: {e}")

    print("-" * 75)
    print(f"{'Run':<6} | {'Flows/Sec':<14} | {'Exec Time (s)':<14} | {'Pass Target (>=10k FPS)':<24}")
    print("-" * 75)

    fps_list = []
    time_list = []
    pass_list = []

    for i in range(1, 11):
        req = urllib.request.Request(FULL_URL, method="POST")
        start_t = time.perf_counter()
        response_bytes = urllib.request.urlopen(req).read()
        res_data = json.loads(response_bytes.decode())
        
        fps = res_data.get("flows_per_second", 0.0)
        exec_t = res_data.get("execution_time_seconds", 0.0)
        passed = res_data.get("pass_target_high_throughput", False)

        fps_list.append(fps)
        time_list.append(exec_t)
        pass_list.append(passed)

        print(f"Run {i:<2}  | {fps:<14.2f} | {exec_t:<14.4f} | {str(passed):<24}")
        time.sleep(1.5)

    print("=" * 75)
    print(" SUMMARY STATISTICS ACROSS 10 INDIVIDUAL RUNS:")
    print("=" * 75)
    print(f"Minimum Flows/Sec:       {min(fps_list):.2f}")
    print(f"Maximum Flows/Sec:       {max(fps_list):.2f}")
    print(f"Average Flows/Sec:       {statistics.mean(fps_list):.2f}")
    print(f"Std Deviation Flows/Sec: {statistics.stdev(fps_list):.2f}")
    print(f"Pass Rate:               {sum(pass_list)} / 10 runs ({sum(pass_list)*10}% passed 10k target)")
    print("=" * 75)

if __name__ == "__main__":
    main()
