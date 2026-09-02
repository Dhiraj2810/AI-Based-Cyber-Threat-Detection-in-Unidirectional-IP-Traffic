import os
import sys
import time
import tempfile
from datetime import datetime, timezone

# Ensure project root is in import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.forensics.chain_of_custody import ChainOfCustodyManager
from backend.schema.alert_schema import StandardizedAlert, AlertEvidence

def run_archive_verification_suite():
    print("=" * 85)
    print(" EMPIRICAL VERIFICATION: CHAIN-OF-CUSTODY ARCHIVE & SEGMENTATION SYSTEM")
    print("=" * 85)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        live_db = os.path.join(tmp_dir, "test_live_chain.db")
        archive_db = os.path.join(tmp_dir, "test_archive_chain.db")

        manager = ChainOfCustodyManager(
            db_path=live_db,
            archive_db_path=archive_db,
            max_live_entries=1000,
            auto_archive=False  # We will test manual & auto triggers explicitly
        )
        manager.reset_chain()

        print("[+] Creating 2,500 synthetic alert records...")
        batch = []
        now = datetime.now(timezone.utc).isoformat()
        for i in range(1, 2501):
            alert = StandardizedAlert(
                flow_id=f"192.168.1.{i % 250}:1234->10.0.0.1:80[TCP]",
                threat_class="ddos" if i % 2 == 0 else "dga_dns_tunnel",
                threat_name="DDoS SYN Flood" if i % 2 == 0 else "DGA Query Flood",
                severity="HIGH",
                confidence_score=0.95,
                supporting_evidence={"seq_test": i},
                shap_explanations=[],
                timestamp=now
            )
            batch.append(alert)

        # Batch insert in chunks of 500
        for b_idx in range(0, len(batch), 500):
            manager.append_alerts(batch[b_idx:b_idx + 500])

        stats_pre = manager.get_chain_stats()
        print(f"  - Pre-Archive Stats: Live={stats_pre['live_entries']} | Archived={stats_pre['archived_entries']} | Total={stats_pre['total_entries']}")
        assert stats_pre['live_entries'] == 2500
        assert stats_pre['archived_entries'] == 0

        # Verify initial un-segmented chain
        res_pre = manager.verify_chain(include_archive=True)
        assert res_pre['is_valid'] is True
        print(f"  - Pre-Archive Chain Verification: Valid ({res_pre['total_entries']} entries)")

        print("\n[+] Triggering Segmentation Archive (keep_live_count=500)...")
        t_arch0 = time.perf_counter()
        arch_res = manager.archive_old_entries(keep_live_count=500)
        t_arch1 = time.perf_counter()
        arch_duration_ms = (t_arch1 - t_arch0) * 1000.0

        print(f"  - Archiving Result: {arch_res['message']} (Duration: {arch_duration_ms:.2f} ms)")
        assert arch_res['status'] == "SUCCESS"
        assert arch_res['archived_count'] == 2000
        assert arch_res['remaining_live_count'] == 500

        stats_post = manager.get_chain_stats()
        print(f"  - Post-Archive Stats: Live={stats_post['live_entries']} | Archived={stats_post['archived_entries']} | Total={stats_post['total_entries']}")
        assert stats_post['live_entries'] == 500
        assert stats_post['archived_entries'] == 2000
        assert stats_post['total_entries'] == 2500

        # Benchmark 1: Live Chain Only Verification Speed
        print("\n[+] Benchmarking Live-Chain Only Verification Speed (500 live entries)...")
        t_live0 = time.perf_counter()
        live_verify = manager.verify_chain(include_archive=False)
        t_live1 = time.perf_counter()
        live_verify_ms = (t_live1 - t_live0) * 1000.0
        print(f"  - Live Chain Verification: Valid={live_verify['is_valid']} | Time={live_verify_ms:.3f} ms ({live_verify['live_entries']} entries)")
        assert live_verify['is_valid'] is True
        assert live_verify['live_entries'] == 500

        # Benchmark 2: Unified Cross-Database Forensic Verification (2,500 entries)
        print("\n[+] Benchmarking Unified Cross-Database Forensic Verification (2,500 entries)...")
        t_full0 = time.perf_counter()
        full_verify = manager.verify_chain(include_archive=True)
        t_full1 = time.perf_counter()
        full_verify_ms = (t_full1 - t_full0) * 1000.0
        print(f"  - Full Unified Verification: Valid={full_verify['is_valid']} | Time={full_verify_ms:.2f} ms ({full_verify['archived_entries']} archived + {full_verify['live_entries']} live = {full_verify['total_entries']} total)")
        assert full_verify['is_valid'] is True
        assert full_verify['total_entries'] == 2500

        # Append more alerts to test cross-boundary continuity append
        print("\n[+] Appending 500 new alerts (Seq #2501 - #3000) to live chain...")
        new_batch = []
        for i in range(2501, 3001):
            alert = StandardizedAlert(
                flow_id=f"192.168.1.{i % 250}:1234->10.0.0.1:80[TCP]",
                threat_class="c2_beaconing",
                threat_name="Botnet C2 Beacon",
                severity="CRITICAL",
                confidence_score=0.98,
                supporting_evidence={"seq_test": i},
                shap_explanations=[],
                timestamp=now
            )
            new_batch.append(alert)
        manager.append_alerts(new_batch)

        post_append_verify = manager.verify_chain(include_archive=True)
        print(f"  - Post-Append Unified Verification: Valid={post_append_verify['is_valid']} | Total Entries={post_append_verify['total_entries']}")
        assert post_append_verify['is_valid'] is True
        assert post_append_verify['total_entries'] == 3000

        # Benchmark 3: Tamper Detection in Archived Segment
        print("\n[!] Injecting Evidence Tampering into Entry #500 (Archived DB Segment)...")
        tamper_res = manager.tamper_entry_for_test(sequence_number=500)
        print(f"  - Tamper Endpoint Output: {tamper_res}")
        assert tamper_res['status'] == "SUCCESS"
        assert tamper_res['tampered_sequence_number'] == 500
        assert tamper_res['target_table'] == "chain_of_custody_archive"

        t_tamper0 = time.perf_counter()
        post_tamper_verify = manager.verify_chain(include_archive=True)
        t_tamper1 = time.perf_counter()
        tamper_audit_ms = (t_tamper1 - t_tamper0) * 1000.0

        print(f"  - Post-Tamper Audit Output: Valid={post_tamper_verify['is_valid']} | Broken Seq={post_tamper_verify['broken_sequence_number']} | Time={tamper_audit_ms:.2f} ms")
        print(f"  - Details: {post_tamper_verify['details']}")
        assert post_tamper_verify['is_valid'] is False
        assert post_tamper_verify['broken_sequence_number'] == 500

        print("\n=" * 85)
        print(" EMPIRICAL VERIFICATION COMPLETE: ARCHIVE & SEGMENTATION SYSTEM IS 100% VERIFIED!")
        print("=" * 85)

if __name__ == "__main__":
    run_archive_verification_suite()
