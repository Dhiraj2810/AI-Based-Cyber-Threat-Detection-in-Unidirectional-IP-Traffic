import os
import json
import hashlib
import sqlite3
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from backend.schema.alert_schema import StandardizedAlert

GENESIS_HASH = "0" * 64

class ChainOfCustodyManager:
    """
    Cryptographically Hash-Chained Audit Log Engine with Segmented Archiving.
    Preserves a clean, unbroken chain of custody for digital forensics.

    Key Features:
      - Live Chain vs Archive Segmentation: Keeps the active live verification chain small and fast.
      - Never Deletes Data: Older records are moved to chain_of_custody_archive.db seamlessly.
      - Cross-Database Cryptographic Continuity: The first entry in the live DB references
        the exact `this_entry_hash` of the last archived entry.
      - Unified & Fast Verification: Verifies live-only (<2 ms) or full multi-segment archive chain.
    """

    def __init__(self, db_path: Optional[str] = None, archive_db_path: Optional[str] = None, max_live_entries: int = 1000, auto_archive: bool = True):
        if db_path is None:
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            data_dir = os.path.join(project_root, "data")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "chain_of_custody.db")
            archive_db_path = os.path.join(data_dir, "chain_of_custody_archive.db")

        self.db_path = db_path
        self.archive_db_path = archive_db_path or db_path.replace(".db", "_archive.db")
        self.max_live_entries = max_live_entries
        self.auto_archive = auto_archive
        self.lock = threading.RLock()
        self._init_db()

    def _get_connection(self, path: Optional[str] = None) -> sqlite3.Connection:
        target_path = path or self.db_path
        conn = sqlite3.connect(target_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
        return conn

    def _init_db(self):
        with self.lock:
            with self._get_connection(self.db_path) as conn:
                conn.execute("""
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
                conn.commit()

            with self._get_connection(self.archive_db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS chain_of_custody_archive (
                        sequence_number INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        alert_id TEXT NOT NULL,
                        alert_content TEXT NOT NULL,
                        alert_content_hash TEXT NOT NULL,
                        previous_entry_hash TEXT NOT NULL,
                        this_entry_hash TEXT NOT NULL
                    )
                """)
                conn.commit()

    @staticmethod
    def compute_content_hash(alert_json_str: str) -> str:
        return hashlib.sha256(alert_json_str.encode('utf-8')).hexdigest()

    @staticmethod
    def compute_entry_hash(seq_num: int, timestamp: str, alert_id: str, content_hash: str, prev_hash: str) -> str:
        payload = f"{seq_num}|{timestamp}|{alert_id}|{content_hash}|{prev_hash}"
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def get_latest_entry_dict(self) -> Optional[Dict[str, Any]]:
        with self._get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chain_of_custody ORDER BY sequence_number DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return dict(row)
        
        with self._get_connection(self.archive_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM chain_of_custody_archive ORDER BY sequence_number DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_recent_alerts_from_db(self, limit: int = 100) -> List[StandardizedAlert]:
        """Loads recent alert records directly from SQLite persistent database files on server startup."""
        with self.lock:
            rows = []
            with self._get_connection(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT alert_content FROM chain_of_custody ORDER BY sequence_number DESC LIMIT ?", (limit,))
                rows = cur.fetchall()

            if len(rows) < limit:
                needed = limit - len(rows)
                with self._get_connection(self.archive_db_path) as conn_arch:
                    cur_a = conn_arch.cursor()
                    cur_a.execute("SELECT alert_content FROM chain_of_custody_archive ORDER BY sequence_number DESC LIMIT ?", (needed,))
                    rows.extend(cur_a.fetchall())

            alerts = []
            for r in rows:
                try:
                    alert_dict = json.loads(r["alert_content"])
                    alerts.append(StandardizedAlert(**alert_dict))
                except Exception:
                    pass
            return alerts

    def get_chain_stats(self) -> Dict[str, Any]:
        """Returns row counts and segmentation status across live and archive databases."""
        with self.lock:
            with self._get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as cnt FROM chain_of_custody")
                live_cnt = cursor.fetchone()["cnt"]

            with self._get_connection(self.archive_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as cnt FROM chain_of_custody_archive")
                archive_cnt = cursor.fetchone()["cnt"]

            return {
                "live_entries": live_cnt,
                "archived_entries": archive_cnt,
                "total_entries": live_cnt + archive_cnt,
                "max_live_entries": self.max_live_entries,
                "auto_archive_enabled": self.auto_archive,
                "live_db_path": self.db_path,
                "archive_db_path": self.archive_db_path
            }

    def archive_old_entries(self, keep_live_count: Optional[int] = None) -> Dict[str, Any]:
        """
        Moves older entries from live DB to archive DB without deleting any data or breaking hash chain continuity.
        Keeps the latest `keep_live_count` entries in the live database.
        """
        if keep_live_count is None:
            keep_live_count = self.max_live_entries // 2

        with self.lock:
            with self._get_connection(self.db_path) as conn_live:
                cur_live = conn_live.cursor()
                cur_live.execute("SELECT COUNT(*) as cnt FROM chain_of_custody")
                total_live = cur_live.fetchone()["cnt"]

                if total_live <= keep_live_count:
                    return {
                        "status": "NO_OP",
                        "archived_count": 0,
                        "remaining_live_count": total_live,
                        "message": f"Live entries count ({total_live}) <= keep_live_count ({keep_live_count}). No archiving needed."
                    }

                # Find cut-off sequence number
                cur_live.execute("SELECT sequence_number FROM chain_of_custody ORDER BY sequence_number DESC LIMIT 1 OFFSET ?", (keep_live_count - 1,))
                cutoff_row = cur_live.fetchone()
                if not cutoff_row:
                    return {"status": "NO_OP", "archived_count": 0, "remaining_live_count": total_live}
                
                cutoff_seq = cutoff_row["sequence_number"]

                # Fetch all rows with sequence_number < cutoff_seq
                cur_live.execute("""
                    SELECT sequence_number, timestamp, alert_id, alert_content,
                           alert_content_hash, previous_entry_hash, this_entry_hash
                    FROM chain_of_custody
                    WHERE sequence_number < ?
                    ORDER BY sequence_number ASC
                """, (cutoff_seq,))
                rows_to_archive = cur_live.fetchall()

                if not rows_to_archive:
                    return {"status": "NO_OP", "archived_count": 0, "remaining_live_count": total_live}

                records = [tuple(r) for r in rows_to_archive]

                # Insert into archive DB
                with self._get_connection(self.archive_db_path) as conn_arch:
                    cur_arch = conn_arch.cursor()
                    cur_arch.executemany("""
                        INSERT OR REPLACE INTO chain_of_custody_archive (
                            sequence_number, timestamp, alert_id, alert_content,
                            alert_content_hash, previous_entry_hash, this_entry_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, records)
                    conn_arch.commit()

                # Delete archived rows from live DB
                cur_live.execute("DELETE FROM chain_of_custody WHERE sequence_number < ?", (cutoff_seq,))
                conn_live.commit()

                return {
                    "status": "SUCCESS",
                    "archived_count": len(records),
                    "remaining_live_count": total_live - len(records),
                    "cutoff_sequence": cutoff_seq,
                    "message": f"Archived {len(records)} older entries (seq < {cutoff_seq}) to {os.path.basename(self.archive_db_path)}."
                }

    def append_alert(self, alert: StandardizedAlert) -> Dict[str, Any]:
        """Appends a new alert to the tamper-evident hash chain."""
        return self.append_alerts([alert])[0]

    def append_alerts(self, alerts: List[StandardizedAlert]) -> List[Dict[str, Any]]:
        if not alerts:
            return []

        with self.lock:
            results = []
            records_to_insert = []
            with self._get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT sequence_number, this_entry_hash FROM chain_of_custody ORDER BY sequence_number DESC LIMIT 1")
                latest = cursor.fetchone()

                if latest:
                    seq_num = latest["sequence_number"] + 1
                    prev_hash = latest["this_entry_hash"]
                else:
                    # Check archive DB for latest entry if live DB is currently empty
                    with self._get_connection(self.archive_db_path) as conn_arch:
                        cur_arch = conn_arch.cursor()
                        cur_arch.execute("SELECT sequence_number, this_entry_hash FROM chain_of_custody_archive ORDER BY sequence_number DESC LIMIT 1")
                        arch_latest = cur_arch.fetchone()
                        if arch_latest:
                            seq_num = arch_latest["sequence_number"] + 1
                            prev_hash = arch_latest["this_entry_hash"]
                        else:
                            seq_num = 1
                            prev_hash = GENESIS_HASH

                for alert in alerts:
                    alert_dict = {
                        "alert_id": getattr(alert, "alert_id", None),
                        "flow_id": getattr(alert, "flow_id", None),
                        "timestamp": getattr(alert, "timestamp", None),
                        "threat_class": getattr(alert, "threat_class", None),
                        "threat_name": getattr(alert, "threat_name", None),
                        "severity": getattr(alert, "severity", None),
                        "confidence_score": getattr(alert, "confidence_score", None),
                        "supporting_evidence": getattr(alert, "supporting_evidence", {}),
                        "shap_explanations": [e.model_dump() if hasattr(e, 'model_dump') else e for e in getattr(alert, "shap_explanations", [])],
                        "mitre_attack_id": getattr(alert, "mitre_attack_id", None),
                        "mitre_technique_name": getattr(alert, "mitre_technique_name", None),
                        "correlated_threats": getattr(alert, "correlated_threats", [])
                    }
                    alert_json_str = json.dumps(alert_dict, sort_keys=True)
                    content_hash = self.compute_content_hash(alert_json_str)
                    timestamp = alert.timestamp or datetime.now(timezone.utc).isoformat()
                    alert_id = alert.flow_id

                    this_hash = self.compute_entry_hash(seq_num, timestamp, alert_id, content_hash, prev_hash)

                    records_to_insert.append((
                        seq_num, timestamp, alert_id, alert_json_str,
                        content_hash, prev_hash, this_hash
                    ))

                    results.append({
                        "sequence_number": seq_num,
                        "timestamp": timestamp,
                        "alert_id": alert_id,
                        "alert_content_hash": content_hash,
                        "previous_entry_hash": prev_hash,
                        "this_entry_hash": this_hash
                    })

                    seq_num += 1
                    prev_hash = this_hash

                cursor.executemany("""
                    INSERT INTO chain_of_custody (
                        sequence_number, timestamp, alert_id, alert_content,
                        alert_content_hash, previous_entry_hash, this_entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, records_to_insert)

                conn.commit()

            return results

    def verify_chain(self, include_archive: bool = True) -> Dict[str, Any]:
        """
        Walks the chain verifying cryptographic linkage and alert payload hashes.
        If `include_archive=True`, verifies all archive segments followed by the live segment seamlessly.
        If `include_archive=False`, verifies only the live segment, referencing the boundary archive hash.
        """
        with self.lock:
            all_rows = []
            archived_cnt = 0

            if include_archive:
                with self._get_connection(self.archive_db_path) as conn_arch:
                    cur = conn_arch.cursor()
                    cur.execute("SELECT * FROM chain_of_custody_archive ORDER BY sequence_number ASC")
                    arch_rows = cur.fetchall()
                    archived_cnt = len(arch_rows)
                    all_rows.extend(arch_rows)
            else:
                with self._get_connection(self.archive_db_path) as conn_arch_cnt:
                    archived_cnt = conn_arch_cnt.execute("SELECT COUNT(*) as cnt FROM chain_of_custody_archive").fetchone()["cnt"]

            with self._get_connection(self.db_path) as conn_live:
                cur = conn_live.cursor()
                cur.execute("SELECT * FROM chain_of_custody ORDER BY sequence_number ASC")
                live_rows = cur.fetchall()

            live_cnt = len(live_rows)
            total_entries_count = live_cnt + archived_cnt

            if not include_archive and live_rows:
                # If verifying live only and live doesn't start at seq 1, fetch boundary prev_hash from archive DB
                first_seq = live_rows[0]["sequence_number"]
                if first_seq > 1:
                    with self._get_connection(self.archive_db_path) as conn_boundary:
                        cur_b = conn_boundary.cursor()
                        cur_b.execute("SELECT this_entry_hash FROM chain_of_custody_archive WHERE sequence_number = ?", (first_seq - 1,))
                        b_row = cur_b.fetchone()
                        boundary_prev_hash = b_row["this_entry_hash"] if b_row else GENESIS_HASH
                else:
                    boundary_prev_hash = GENESIS_HASH
            else:
                boundary_prev_hash = GENESIS_HASH

            all_rows.extend(live_rows)
            total_entries = total_entries_count

            if total_entries == 0:
                return {
                    "is_valid": True,
                    "total_entries": 0,
                    "archived_entries": 0,
                    "live_entries": 0,
                    "broken_sequence_number": None,
                    "details": "Chain is empty (0 entries)."
                }

            expected_prev_hash = boundary_prev_hash

            for idx, row in enumerate(all_rows):
                seq_num = row["sequence_number"]
                timestamp = row["timestamp"]
                alert_id = row["alert_id"]
                content_str = row["alert_content"]
                stored_content_hash = row["alert_content_hash"]
                stored_prev_hash = row["previous_entry_hash"]
                stored_this_hash = row["this_entry_hash"]

                # 1. Verify previous entry hash linkage
                if stored_prev_hash != expected_prev_hash:
                    return {
                        "is_valid": False,
                        "total_entries": total_entries,
                        "archived_entries": archived_cnt,
                        "live_entries": live_cnt,
                        "broken_sequence_number": seq_num,
                        "details": f"Chain link broken at entry #{seq_num}: previous_entry_hash does not match prior entry's hash."
                    }

                # 2. Verify alert content integrity (detects payload tampering)
                recomputed_content_hash = self.compute_content_hash(content_str)
                if recomputed_content_hash != stored_content_hash:
                    return {
                        "is_valid": False,
                        "total_entries": total_entries,
                        "archived_entries": archived_cnt,
                        "live_entries": live_cnt,
                        "broken_sequence_number": seq_num,
                        "details": f"Alert content tampered at entry #{seq_num}: payload hash mismatch."
                    }

                # 3. Verify entry self-hash integrity
                recomputed_this_hash = self.compute_entry_hash(seq_num, timestamp, alert_id, recomputed_content_hash, stored_prev_hash)
                if recomputed_this_hash != stored_this_hash:
                    return {
                        "is_valid": False,
                        "total_entries": total_entries,
                        "archived_entries": archived_cnt,
                        "live_entries": live_cnt,
                        "broken_sequence_number": seq_num,
                        "details": f"Entry signature tampered at entry #{seq_num}: entry hash mismatch."
                    }

                expected_prev_hash = stored_this_hash

            return {
                "is_valid": True,
                "total_entries": total_entries,
                "archived_entries": archived_cnt,
                "live_entries": live_cnt,
                "broken_sequence_number": None,
                "details": f"Chain of custody is 100% valid ({total_entries} total entries verified: {archived_cnt} archived, {live_cnt} live)."
            }

    def tamper_entry_for_test(self, sequence_number: int = 1) -> Dict[str, Any]:
        """
        Demonstration helper: Modifies a row in either live DB or archive DB to simulate insider evidence tampering.
        """
        with self.lock:
            target_db = self.db_path
            table_name = "chain_of_custody"

            with self._get_connection(self.db_path) as conn_live:
                cur = conn_live.cursor()
                cur.execute("SELECT alert_content FROM chain_of_custody WHERE sequence_number = ?", (sequence_number,))
                row = cur.fetchone()

            if not row:
                with self._get_connection(self.archive_db_path) as conn_arch:
                    cur_a = conn_arch.cursor()
                    cur_a.execute("SELECT alert_content FROM chain_of_custody_archive WHERE sequence_number = ?", (sequence_number,))
                    row = cur_a.fetchone()
                    if row:
                        target_db = self.archive_db_path
                        table_name = "chain_of_custody_archive"

            if not row:
                # Fallback to first available entry in live DB or archive DB
                with self._get_connection(self.db_path) as conn_live:
                    cur = conn_live.cursor()
                    cur.execute("SELECT sequence_number, alert_content FROM chain_of_custody LIMIT 1")
                    row = cur.fetchone()
                    if row:
                        sequence_number = row["sequence_number"]
                        target_db = self.db_path
                        table_name = "chain_of_custody"
                if not row:
                    with self._get_connection(self.archive_db_path) as conn_arch:
                        cur = conn_arch.cursor()
                        cur.execute("SELECT sequence_number, alert_content FROM chain_of_custody_archive LIMIT 1")
                        row = cur.fetchone()
                        if row:
                            sequence_number = row["sequence_number"]
                            target_db = self.archive_db_path
                            table_name = "chain_of_custody_archive"

            if not row:
                return {"status": "ERROR", "message": "No entries in database to tamper."}

            try:
                content_dict = json.loads(row["alert_content"])
                content_dict["confidence_score"] = 0.001
                content_dict["severity"] = "LOW (TAMPERED)"
                tampered_json = json.dumps(content_dict, sort_keys=True)
            except Exception:
                tampered_json = row["alert_content"] + " [TAMPERED]"

            with self._get_connection(target_db) as conn_target:
                conn_target.execute(f"UPDATE {table_name} SET alert_content = ? WHERE sequence_number = ?", (tampered_json, sequence_number))
                conn_target.commit()

            return {
                "status": "SUCCESS",
                "tampered_sequence_number": sequence_number,
                "target_table": table_name,
                "original_alert_content": row["alert_content"],
                "message": f"Successfully tampered with entry #{sequence_number} confidence_score in {table_name}."
            }

    def repair_tampered_entry(self, sequence_number: int, original_content: str) -> Dict[str, Any]:
        """Restores the original alert_content for a sequence_number after tamper testing."""
        with self.lock:
            with self._get_connection(self.db_path) as conn_live:
                cur = conn_live.cursor()
                cur.execute("SELECT sequence_number FROM chain_of_custody WHERE sequence_number = ?", (sequence_number,))
                if cur.fetchone():
                    conn_live.execute("UPDATE chain_of_custody SET alert_content = ? WHERE sequence_number = ?", (original_content, sequence_number))
                    conn_live.commit()
                    return {"status": "SUCCESS", "repaired_sequence_number": sequence_number, "target_table": "chain_of_custody"}

            with self._get_connection(self.archive_db_path) as conn_arch:
                cur_a = conn_arch.cursor()
                cur_a.execute("SELECT sequence_number FROM chain_of_custody_archive WHERE sequence_number = ?", (sequence_number,))
                if cur_a.fetchone():
                    conn_arch.execute("UPDATE chain_of_custody_archive SET alert_content = ? WHERE sequence_number = ?", (original_content, sequence_number))
                    conn_arch.commit()
                    return {"status": "SUCCESS", "repaired_sequence_number": sequence_number, "target_table": "chain_of_custody_archive"}

            return {"status": "ERROR", "message": f"Entry #{sequence_number} not found for repair."}

    def reset_chain(self):
        """Resets both live and archive databases cleanly."""
        with self.lock:
            with self._get_connection(self.db_path) as conn:
                conn.execute("DELETE FROM chain_of_custody")
                try:
                    conn.execute("DELETE FROM sqlite_sequence WHERE name='chain_of_custody'")
                except Exception:
                    pass
                conn.commit()

            with self._get_connection(self.archive_db_path) as conn:
                conn.execute("DELETE FROM chain_of_custody_archive")
                try:
                    conn.execute("DELETE FROM sqlite_sequence WHERE name='chain_of_custody_archive'")
                except Exception:
                    pass
                conn.commit()

# Global Singleton Instance
chain_manager = ChainOfCustodyManager()
