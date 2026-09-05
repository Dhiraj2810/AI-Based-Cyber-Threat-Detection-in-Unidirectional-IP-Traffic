import os
import sys
import time
import json
import sqlite3
import requests
import psutil
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
PROJECT_ROOT = Path("d:/PS SIH26145")
LIVE_DB_PATH = PROJECT_ROOT / "data" / "chain_of_custody.db"

def populate_live_db(target_count: int):
    conn = sqlite3.connect(LIVE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chain_of_custody (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            alert_content TEXT NOT NULL,
            alert_content_hash TEXT NOT NULL,
            previous_entry_hash TEXT NOT NULL,
            this_entry_hash TEXT NOT NULL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM chain_of_custody")
    current_count = cursor.fetchone()[0]

    needed = target_count - current_count
    if needed > 0:
        print(f"Populating DB with {needed} synthetic rows (target={target_count})...")
        sample_content = json.dumps({"test": "row", "data": "x" * 200})
        rows = [
            (time.strftime('%Y-%m-%d %H:%M:%S'), f"alert-{current_count + i}", sample_content, "hash_content", "prev_hash", "this_hash")
            for i in range(needed)
        ]
        cursor.executemany("INSERT INTO chain_of_custody (timestamp, alert_id, alert_content, alert_content_hash, previous_entry_hash, this_entry_hash) VALUES (?, ?, ?, ?, ?, ?)", rows)
        conn.commit()
    conn.close()

def get_live_db_count():
    if not LIVE_DB_PATH.exists():
        return 0
    conn = sqlite3.connect(LIVE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM chain_of_custody")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def clear_live_db():
    if LIVE_DB_PATH.exists():
        conn = sqlite3.connect(LIVE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM chain_of_custody")
        conn.commit()
        conn.close()

def run_baseline_benchmark(num_flows=10000):
    url = f"{BASE_URL}/api/benchmark?num_flows={num_flows}&use_live_state=false"
    t0 = time.time()
    resp = requests.post(url, timeout=30)
    t1 = time.time()
    if resp.status_code == 200:
        data = resp.json()
        return data.get("flows_per_second", 0.0), data.get("execution_time_seconds", 0.0), round(t1 - t0, 4)
    else:
        return 0.0, 0.0, 0.0

def main():
    print("=" * 80)
    print("GAP 1 & GAP 2 EMPIRICAL INVESTIGATION SUITE")
    print("=" * 80)

    # Test Gap 1: DB Population at 0, 10,000, 50,000 entries
    db_test_levels = [0, 10000, 50000]
    gap1_results = {}

    for level in db_test_levels:
        if level == 0:
            clear_live_db()
        else:
            populate_live_db(level)
        
        actual_count = get_live_db_count()
        print(f"\n--- Testing Live DB Entry Level: {actual_count} rows ---")
        
        # Run 3 benchmark calls at this DB level
        fps_list = []
        exec_times = []
        http_times = []
        for r in range(3):
            fps, exec_t, http_t = run_baseline_benchmark(10000)
            fps_list.append(fps)
            exec_times.append(exec_t)
            http_times.append(http_t)
            print(f"  Run {r+1}: {fps:.2f} flows/sec | Exec: {exec_t:.4f}s | HTTP: {http_t:.4f}s")
            time.sleep(0.5)
        
        avg_fps = sum(fps_list) / len(fps_list)
        gap1_results[level] = {
            "actual_rows": actual_count,
            "avg_fps": round(avg_fps, 2),
            "fps_runs": fps_list,
            "exec_times": exec_times
        }

    # Clean up DB after test
    clear_live_db()

    print("\n" + "=" * 80)
    print("GAP 1 SUMMARY - THROUGHPUT VS LIVE DB ROW COUNT:")
    print("=" * 80)
    for level, res in gap1_results.items():
        print(f"  Live DB Rows: {res['actual_rows']:<6} | Avg Baseline Throughput: {res['avg_fps']:<10.2f} flows/sec")

    # Save results artifact
    out_file = PROJECT_ROOT / "scratch" / "gap_investigation_results.json"
    with open(out_file, "w") as f:
        json.dump(gap1_results, f, indent=2)

    print(f"\nSaved raw results to {out_file}")

if __name__ == "__main__":
    main()
