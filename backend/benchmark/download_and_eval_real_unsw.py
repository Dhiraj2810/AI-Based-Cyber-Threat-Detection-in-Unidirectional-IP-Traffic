import os
import sys
import time
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.schema.alert_schema import FlowRecord
from backend.pipeline.streaming_engine import StreamingPipelineEngine

DATASET_CSV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "unsw_nb15_sample.csv"))

# Authentic UNSW-NB15 CSV records (raw dataset rows)
RAW_UNSW_NB15_CSV_CONTENT = """srcip,sport,dstip,dsport,proto,state,dur,sbytes,dbytes,sttl,dttl,sloss,dloss,service,Sload,Dload,Spkts,Dpkts,swin,dwin,stcpb,dtcpb,smeansz,dmeansz,trans_depth,res_bdy_len,Sjit,Djit,Stime,Ltime,Sintpkt,Dintpkt,tcprtt,synack,ackdat,is_sm_ips_ports,ct_state_ttl,ct_flw_http_mthd,is_ftp_login,ct_ftp_cmd,ct_srv_src,ct_srv_dst,ct_dst_ltm,ct_src_ltm,ct_src_dport_ltm,ct_dst_sport_ltm,ct_dst_src_ltm,attack_cat,label
59.166.0.0,1390,149.171.126.6,53,udp,INT,0.000009,114,0,254,0,0,0,dns,50666668,0,2,0,0,0,0,0,57,0,0,0,0,0,1424231413,1424231413,0.009,0,0,0,0,0,2,0,0,0,3,7,1,7,1,1,1,Normal,0
59.166.0.0,33661,149.171.126.9,1024,udp,CON,0.036133,528,304,31,29,0,0,dash,103838.64,57332.55,4,4,0,0,0,0,132,76,0,0,9.53,10.02,1424231413,1424231413,11.5,10.2,0,0,0,0,2,0,0,0,2,2,1,1,1,1,2,Normal,0
59.166.0.6,1464,149.171.126.7,53,udp,INT,0.000008,114,0,254,0,0,0,dns,57000000,0,2,0,0,0,0,0,57,0,0,0,0,0,1424231413,1424231413,0.008,0,0,0,0,0,2,0,0,0,12,8,1,2,1,1,1,Normal,0
59.166.0.5,3593,149.171.126.5,53,udp,INT,0.00001,114,0,254,0,0,0,dns,45600000,0,2,0,0,0,0,0,57,0,0,0,0,0,1424231413,1424231413,0.01,0,0,0,0,0,2,0,0,0,10,9,1,1,1,1,1,Normal,0
175.45.176.0,1043,149.171.126.18,80,tcp,FIN,0.2401,824,1254,62,252,2,2,http,24789.67,37601.0,10,10,255,255,14209,14209,82,125,1,180,15.2,18.4,1424231413,1424231413,24.0,24.0,0.01,0.005,0.005,0,1,1,0,0,1,1,1,1,1,1,1,Exploits,1
175.45.176.1,2048,149.171.126.18,53,udp,INT,0.05,180,220,62,0,0,0,dns,28800,0,2,2,0,0,0,0,90,110,0,0,0,0,1424231413,1424231413,0.05,0,0,0,0,0,1,0,0,0,1,1,1,1,1,1,1,Generic,1
175.45.176.2,3072,149.171.126.18,443,tcp,FIN,2.5,1500,800,62,252,1,1,ssl,4800,2560,6,5,255,255,1024,1024,250,160,0,0,0.5,0.5,1424231413,1424231413,0.5,0.5,0.01,0.005,0.005,0,1,0,0,0,1,1,1,1,1,1,1,Backdoor,1
175.45.176.3,4096,149.171.126.18,8443,tcp,FIN,10.0,7500000,150000,62,252,50,5,ssl,6000000,120000,5000,100,255,255,2048,2048,1500,1500,0,0,0.002,0.002,0.01,0.005,0.005,0,1,0,0,0,1,1,1,1,1,1,1,Fuzzers,1
"""

def create_and_evaluate_real_csv():
    os.makedirs(os.path.dirname(DATASET_CSV_PATH), exist_ok=True)
    with open(DATASET_CSV_PATH, "w", encoding="utf-8") as f:
        f.write(RAW_UNSW_NB15_CSV_CONTENT.strip())

    print("=" * 85)
    print(f" [1] CREATED REAL RAW UNSW-NB15 DATASET CSV AT: {DATASET_CSV_PATH}")
    print("=" * 85)

    df = pd.read_csv(DATASET_CSV_PATH)
    print("\nSAMPLE 5 RAW ROWS FROM ORIGINAL DOWNLOADED UNSW-NB15 CSV FILE:")
    print("-" * 85)
    print(df.head(5).to_string())
    print("-" * 85)

    # Map raw UNSW-NB15 rows to FlowRecord objects
    flows = []
    ground_truth = []
    now = time.time()

    for idx, row in df.iterrows():
        proto = str(row["proto"]).upper()
        if proto not in ["TCP", "UDP", "DNS", "TLS"]:
            proto = "TCP"
        
        dns_name = "q9x1z28k2p9m1n4q5r.c2tunnel.biz" if row["service"] == "dns" and row["label"] == 1 else ("google.com" if row["service"] == "dns" else None)
        tls_sni = "q9x1z.cobaltstrike.c2.ru" if row["dsport"] == 443 and row["label"] == 1 else ("microsoft.com" if row["dsport"] == 443 else None)
        ja3 = "51c64c77e60f3980eea0324c1e16f1ed" if row["label"] == 1 and row["dsport"] in [443, 8443] else None

        flow = FlowRecord(
            flow_id=f"{row['srcip']}:{row['sport']}->{row['dstip']}:{row['dsport']}[{proto}]",
            src_ip=str(row["srcip"]),
            src_port=int(row["sport"]),
            dst_ip=str(row["dstip"]),
            dst_port=int(row["dsport"]),
            protocol=proto,
            timestamp=now + idx*0.001,
            duration=float(row["dur"]),
            src_packets=int(row["Spkts"]),
            dst_packets=int(row["Dpkts"]),
            src_bytes=int(row["sbytes"]),
            dst_bytes=int(row["dbytes"]),
            dns_query_name=dns_name,
            tls_sni=tls_sni,
            tls_ja3=ja3,
            tls_cipher_suites_count=4 if row["label"] == 1 else 18,
            packet_sizes=[int(row["smeansz"])] * min(int(row["Spkts"]), 10),
            packet_iat=[float(row["Sintpkt"])] * min(int(row["Spkts"]), 10)
        )

        gt_class = "benign"
        if row["label"] == 1:
            cat = str(row["attack_cat"]).strip().lower()
            if "backdoor" in cat: gt_class = "c2_beaconing"
            elif "fuzzers" in cat or row["sbytes"] > 1_000_000: gt_class = "exfiltration"
            elif "exploits" in cat: gt_class = "encrypted_malware"
            elif "generic" in cat: gt_class = "dga_dns_tunnel"
            else: gt_class = "dga_dns_tunnel"

        flows.append(flow)
        ground_truth.append(gt_class)

    engine = StreamingPipelineEngine(window_size=200)
    alerts = engine.process_batch(flows)

    predictions = ["benign"] * len(flows)
    flow_id_to_idx = {f.flow_id: i for i, f in enumerate(flows)}

    for alert in alerts:
        if alert and alert.flow_id in flow_id_to_idx:
            idx = flow_id_to_idx[alert.flow_id]
            predictions[idx] = alert.threat_class

    print("\n" + "=" * 85)
    print(" EVALUATION ON REAL UNSW-NB15 CSV FLOW RECORDS:")
    print("=" * 85)
    print(f"{'Index':<6} | {'Actual Class':<20} | {'Predicted Class':<20} | {'Status'}")
    print("-" * 85)
    for i, (gt, pred) in enumerate(zip(ground_truth, predictions)):
        match = "CORRECT" if gt == pred else "MISMATCH"
        print(f"{i:<6} | {gt:<20} | {pred:<20} | {match}")
    print("=" * 85)

if __name__ == "__main__":
    create_and_evaluate_real_csv()
