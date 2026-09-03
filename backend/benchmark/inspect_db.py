import sqlite3
import json
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

live_db = "data/chain_of_custody.db"
archive_db = "data/chain_of_custody_archive.db"

live_count = 0
max_seq = 0
archive_count = 0

if os.path.exists(live_db):
    conn = sqlite3.connect(live_db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM chain_of_custody;")
    live_count = cursor.fetchone()[0]
    cursor.execute("SELECT MAX(sequence_number) FROM chain_of_custody;")
    max_seq = cursor.fetchone()[0] or 0
    conn.close()

if os.path.exists(archive_db):
    try:
        conn = sqlite3.connect(archive_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]
        if tables:
            cursor.execute(f"SELECT COUNT(*) FROM {tables[0]};")
            archive_count = cursor.fetchone()[0]
        conn.close()
    except Exception:
        pass

print("="*80)
print("  CHAINS OF CUSTODY SYSTEM AUDIT LEDGER REPORT")
print("="*80)
print(f"  • Live Database Records (data/chain_of_custody.db):    {live_count:,} records")
print(f"  • Archive Database Records (chain_of_custody_archive): {archive_count:,} records")
print(f"  • Total Combined Forensic Audit Blocks:                 {live_count + archive_count:,} records")
print(f"  • Highest Sequence Number Reached:                     #{max_seq:,}")
print("="*80)

conn = sqlite3.connect(live_db)
cursor = conn.cursor()
cursor.execute("SELECT sequence_number, timestamp, alert_id, alert_content, alert_content_hash, previous_entry_hash, this_entry_hash FROM chain_of_custody ORDER BY sequence_number DESC LIMIT 3;")
rows = cursor.fetchall()

print("\n=== LATEST 3 ALERTS IN LIVE CHAIN OF CUSTODY LEDGER ===")
for row in rows:
    seq_num, ts, alert_id, content, content_hash, prev_hash, block_hash = row
    print(f"\n[RECORD BLOCK #{seq_num}] | Timestamp: {ts}")
    print(f"   Alert ID:            {alert_id}")
    print(f"   Alert Content Hash:  {content_hash}")
    print(f"   Previous Block Hash: {prev_hash}")
    print(f"   Current Block Hash:  {block_hash}")
    try:
        alert_data = json.loads(content)
        print(f"   Threat Class:        {alert_data.get('threat_class')}")
        print(f"   Threat Name:         {alert_data.get('threat_name')}")
        print(f"   Severity:            {alert_data.get('severity')}")
        print(f"   Confidence Score:    {alert_data.get('confidence_score', 0):.2%}")
        print(f"   Flow ID:             {alert_data.get('flow_id')}")
        print(f"   Supporting Evidence: {json.dumps(alert_data.get('supporting_evidence', {}), indent=2)}")
    except Exception as e:
        print(f"   Raw Content: {content[:100]}...")
    print("-" * 80)

conn.close()
