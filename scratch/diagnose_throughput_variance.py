import os
import sys
import time
import json
import sqlite3
import psutil
import requests
import datetime
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
PROJECT_ROOT = Path("d:/PS SIH26145")

def get_system_resource_state():
    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    process_count = len(psutil.pids())
    python_processes = [p.info for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']) if 'python' in p.info['name'].lower()]
    
    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_available_mb": round(memory.available / (1024 * 1024), 2),
        "total_processes": process_count,
        "python_process_count": len(python_processes),
        "python_processes": python_processes
    }

def get_db_stats():
    live_db_path = PROJECT_ROOT / "data" / "chain_of_custody.db"
    archive_db_path = PROJECT_ROOT / "data" / "chain_of_custody_archive.db"

    live_count = 0
    archive_count = 0

    if live_db_path.exists():
        try:
            conn = sqlite3.connect(live_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM chain_of_custody")
            live_count = cursor.fetchone()[0]
            conn.close()
        except Exception as e:
            live_count = f"Error: {e}"

    if archive_db_path.exists():
        try:
            conn = sqlite3.connect(archive_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM chain_of_custody_archive")
            archive_count = cursor.fetchone()[0]
            conn.close()
        except Exception as e:
            archive_count = f"Error: {e}"

    return {
        "live_db_entries": live_count,
        "archive_db_entries": archive_count,
        "total_entries": live_count + archive_count if isinstance(live_count, int) and isinstance(archive_count, int) else "N/A"
    }

def run_benchmark_call(num_flows=10000, use_live_state=False):
    url = f"{BASE_URL}/api/benchmark?num_flows={num_flows}&use_live_state={str(use_live_state).lower()}"
    start_time = time.time()
    resp = requests.post(url, timeout=30)
    elapsed = time.time() - start_time
    if resp.status_code == 200:
        data = resp.json()
        return {
            "status": "SUCCESS",
            "flows_per_second": data.get("flows_per_second", 0.0),
            "execution_time_seconds": data.get("execution_time_seconds", 0.0),
            "total_http_elapsed": round(elapsed, 4),
            "alerts_detected": data.get("alerts_detected", 0)
        }
    else:
        return {"status": "FAILED", "code": resp.status_code, "text": resp.text}

def check_file_timestamps():
    backend_dir = PROJECT_ROOT / "backend"
    files_info = []
    for root, _, files in os.walk(backend_dir):
        for f in files:
            if f.endswith(".py"):
                p = Path(root) / f
                mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                files_info.append((str(p.relative_to(PROJECT_ROOT)), mtime))
    return sorted(files_info, key=lambda x: x[1], reverse=True)

def main():
    print("=" * 80)
    print("THROUGHPUT VARIANCE DIAGNOSTIC SUITE")
    print("=" * 80)

    # Candidate 4: Check file modification timestamps
    print("\n--- 4. FILE STALENESS & TIMESTAMPS CHECK ---")
    timestamps = check_file_timestamps()
    print("Latest 5 modified backend files:")
    for f_path, m_time in timestamps[:5]:
        print(f"  - {f_path}: {m_time}")

    # Candidate 3: System Resource State
    print("\n--- 3. SYSTEM RESOURCE STATE BEFORE BENCHMARK ---")
    res_before = get_system_resource_state()
    print(f"  CPU Utilization: {res_before['cpu_percent']}%")
    print(f"  RAM Usage:       {res_before['memory_percent']}% (Available: {res_before['memory_available_mb']} MB)")
    print(f"  Active Processes: {res_before['total_processes']} (Python instances: {res_before['python_process_count']})")

    # Candidate 1: Database size correlation
    print("\n--- 1. CHAIN-OF-CUSTODY DATABASE SIZE CORRELATION ---")
    db_before = get_db_stats()
    print(f"  Pre-test DB State: Live Entries={db_before['live_db_entries']} | Archive Entries={db_before['archive_db_entries']} | Total={db_before['total_entries']}")

    print("  Running Baseline Benchmark (Run 1 - Existing DB State)...")
    bench_1 = run_benchmark_call(num_flows=10000, use_live_state=False)
    print(f"    -> Result: {bench_1.get('flows_per_second', 0.0):.2f} flows/sec (Internal Exec: {bench_1.get('execution_time_seconds', 0.0):.4f}s, HTTP Total: {bench_1.get('total_http_elapsed', 0.0):.4f}s)")

    print("  Running Baseline Benchmark (Run 2 - Repeat under same DB State)...")
    bench_2 = run_benchmark_call(num_flows=10000, use_live_state=False)
    print(f"    -> Result: {bench_2.get('flows_per_second', 0.0):.2f} flows/sec (Internal Exec: {bench_2.get('execution_time_seconds', 0.0):.4f}s, HTTP Total: {bench_2.get('total_http_elapsed', 0.0):.4f}s)")

    # Candidate 2: Background Stream Interference Test
    print("\n--- 2. BACKGROUND STREAM INTERFERENCE TEST ---")
    print("  Running Baseline Benchmark while background stream is active...")
    bench_bg_active = run_benchmark_call(num_flows=10000, use_live_state=False)
    print(f"    -> Result: {bench_bg_active.get('flows_per_second', 0.0):.2f} flows/sec")

    # Candidate 5: Time-Series Drift / Multiple Consecutive Runs
    print("\n--- 5. CONSECUTIVE RUN DRIFT TEST (5 RUNS) ---")
    runs = []
    for i in range(1, 6):
        res = run_benchmark_call(num_flows=10000, use_live_state=False)
        db_s = get_db_stats()
        sys_s = get_system_resource_state()
        fps = res.get('flows_per_second', 0.0)
        runs.append((i, fps, res.get('execution_time_seconds', 0.0), db_s['live_db_entries'], sys_s['cpu_percent']))
        print(f"  Run {i}: {fps:.2f} flows/sec | Exec Time: {res.get('execution_time_seconds', 0.0):.4f}s | Live DB: {db_s['live_db_entries']} | CPU: {sys_s['cpu_percent']}%")
        time.sleep(1.0)

    # Save artifact
    summary_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "resource_before": res_before,
        "db_before": db_before,
        "bench_1": bench_1,
        "bench_2": bench_2,
        "bench_bg_active": bench_bg_active,
        "consecutive_runs": runs,
        "file_timestamps": timestamps[:10]
    }

    out_file = PROJECT_ROOT / "scratch" / "throughput_variance_results.json"
    with open(out_file, "w") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\nDiagnostic completed! Raw results saved to {out_file}")

if __name__ == "__main__":
    main()
