import os
import sys
import tempfile
from backend.schema.alert_schema import StandardizedAlert
from backend.forensics.chain_of_custody import ChainOfCustodyManager, GENESIS_HASH

def run_chain_of_custody_test():
    print("=" * 80)
    print(" CRYPTOGRAPHIC CHAIN-OF-CUSTODY AUDIT LOG VERIFICATION TEST")
    print("=" * 80)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        manager = ChainOfCustodyManager(db_path=db_path)
        print(f"[+] Initialized fresh forensic SQLite database: {db_path}")

        # 1. Create sample alerts across different threat classes
        alert1 = StandardizedAlert(
            flow_id="192.168.1.50:443->10.0.0.1:80[TCP]",
            threat_class="ddos",
            threat_name="Spoofed-Source Random Flood",
            severity="CRITICAL",
            confidence_score=0.98,
            supporting_evidence={"window_pps": 5000},
            mitre_attack_id="T1498",
            mitre_technique_name="Network Denial of Service"
        )

        alert2 = StandardizedAlert(
            flow_id="192.168.1.56:43636->104.16.132.229:443[TLS]",
            threat_class="c2_beaconing",
            threat_name="Botnet C2 Periodic Beaconing",
            severity="CRITICAL",
            confidence_score=0.9425,
            supporting_evidence={"coefficient_of_variation": 0.038},
            mitre_attack_id="T1071.001",
            mitre_technique_name="Application Layer Protocol: Web Protocols"
        )

        alert3 = StandardizedAlert(
            flow_id="192.168.1.80:53->8.8.8.8:53[DNS]",
            threat_class="dga_dns_tunnel",
            threat_name="High-Entropy DGA Domain",
            severity="HIGH",
            confidence_score=0.91,
            supporting_evidence={"domain_entropy": 4.65},
            mitre_attack_id="T1568.002",
            mitre_technique_name="Domain Generation Algorithms"
        )

        print("[+] Appending 3 alerts to chain of custody...")
        e1 = manager.append_alert(alert1)
        e2 = manager.append_alert(alert2)
        e3 = manager.append_alert(alert3)

        print(f"  - Entry #1: Hash = {e1['this_entry_hash'][:16]}... (Prev = {e1['previous_entry_hash'][:16]}...)")
        print(f"  - Entry #2: Hash = {e2['this_entry_hash'][:16]}... (Prev = {e2['previous_entry_hash'][:16]}...)")
        print(f"  - Entry #3: Hash = {e3['this_entry_hash'][:16]}... (Prev = {e3['previous_entry_hash'][:16]}...)")

        # Confirm Genesis linkage
        assert e1["previous_entry_hash"] == GENESIS_HASH, "Genesis block previous_entry_hash must be 64 zeros"
        assert e2["previous_entry_hash"] == e1["this_entry_hash"], "Entry #2 previous_entry_hash must match Entry #1 this_entry_hash"
        assert e3["previous_entry_hash"] == e2["this_entry_hash"], "Entry #3 previous_entry_hash must match Entry #2 this_entry_hash"

        print("\n[+] Testing Initial Chain Verification (Pre-Tampering)...")
        report = manager.verify_chain()
        print(f"  - Valid: {report['is_valid']}")
        print(f"  - Total Entries: {report['total_entries']}")
        print(f"  - Details: {report['details']}")
        assert report["is_valid"] is True, "Pre-tamper chain verification MUST return is_valid=True"

        # 2. Inject deliberate evidence tampering
        print("\n[!] Injecting Simulated Insider Evidence Tampering on Entry #2...")
        tamper_res = manager.tamper_entry_for_test(sequence_number=2)
        print(f"  - Tamper Status: {tamper_res['status']}")
        print(f"  - Tampered Entry: #{tamper_res['tampered_sequence_number']}")

        # 3. Re-verify chain and confirm tamper detection
        print("\n[+] Testing Chain Verification Post-Tampering...")
        tamper_report = manager.verify_chain()
        print(f"  - Valid: {tamper_report['is_valid']}")
        print(f"  - Total Entries: {tamper_report['total_entries']}")
        print(f"  - Broken Sequence Number: #{tamper_report['broken_sequence_number']}")
        print(f"  - Details: {tamper_report['details']}")

        assert tamper_report["is_valid"] is False, "Post-tamper chain verification MUST return is_valid=False"
        assert tamper_report["broken_sequence_number"] == 2, f"Tamper detector MUST identify exact broken sequence_number #2 (got #{tamper_report['broken_sequence_number']})"

        print("\n" + "=" * 80)
        print(" SUCCESS: Cryptographic Chain-of-Custody Verification PASSED All Checks!")
        print("=" * 80)
        return True

    finally:
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except Exception:
            pass

if __name__ == "__main__":
    run_chain_of_custody_test()
