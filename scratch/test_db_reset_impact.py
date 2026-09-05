import sqlite3
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"
PROJECT_ROOT = Path("d:/PS SIH26145")

def get_db_stats():
    live_db_path = PROJECT_ROOT / "data" / "chain_of_custody.db"
    archive_db_path = PROJECT_ROOT / "data" / "chain_of_custody_archive.db"

    live_count = 0
    archive_count = 0

    if live_db_path.exists():
        conn = sqlite3.connect(live_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM chain_of_custody")
        live_count = cursor.fetchone()[0]
        conn.close()

    if archive_db_path.exists():
        conn = sqlite3.connect(archive_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM chain_of_custody_archive")
        archive_count = cursor.fetchone()[0]
        conn.close()

    return live_count, archive_count

def run_benchmark():
    url = f"{BASE_URL}/api/benchmark?num_flows=10000&use_live_state=false"
    resp = requests.post(url, timeout=30)
    data = resp.json()
    return data.get("flows_per_second", 0.0), data.get("execution_time_seconds", 0.0)

print("=" * 70)
print("CANDIDATE 1: DATABASE RESET VS HEAVY DATABASE THROUGHPUT COMPARISON")
print("=" * 70)

live_pre, archive_pre = get_db_stats()
fps_pre, time_pre = run_benchmark()
print(f"[WITH HEAVY DB - Live: {live_pre} entries | Archive: {archive_pre} entries]")
print(f"  -> Throughput: {fps_pre:.2f} flows/sec | Execution Time: {time_pre:.4f}s")

# Reset live DB table
live_db_path = PROJECT_ROOT / "data" / "chain_of_custody.db"
conn = sqlite3.connect(live_db_path)
cursor = conn.cursor()
cursor.execute("DELETE FROM chain_of_custody")
conn.commit()
conn.close()

live_post, archive_post = get_db_stats()
fps_post, time_post = run_benchmark()
print(f"\n[AFTER LIVE DB RESET - Live: {live_post} entries | Archive: {archive_post} entries]")
print(f"  -> Throughput: {fps_post:.2f} flows/sec | Execution Time: {time_post:.4f}s")

print("=" * 70)
