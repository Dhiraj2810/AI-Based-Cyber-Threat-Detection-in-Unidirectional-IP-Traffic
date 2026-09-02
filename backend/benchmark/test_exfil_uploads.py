import os
import sys
import time
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.schema.alert_schema import FlowRecord
from backend.detection.exfiltration_detector import ExfiltrationDetector

def main():
    print("=" * 80)
    print(" GAP 2 TEST: STRESS-TESTING LEGITIMATE BENIGN HIGH-RATIO UPLOADS (PORT 443)")
    print("=" * 80)

    now = time.time()
    legit_uploads = []

    # Generate 500 legitimate benign upload flows (Google Drive, Dropbox, Zoom video)
    # Byte ratio 4.0 - 8.0, egress 1.5 MB - 4.5 MB on Port 443 (TLS)
    for i in range(500):
        src_bytes = random.randint(1_500_000, 4_500_000)
        ratio = random.uniform(4.2, 7.8)
        dst_bytes = int(src_bytes / ratio)
        flow = FlowRecord(
            flow_id=f"192.168.1.50:{30000+i}->142.250.190.46:443[TLS]",
            src_ip="192.168.1.50",
            src_port=30000 + i,
            dst_ip="142.250.190.46", # Google / Cloud storage IP
            dst_port=443,
            protocol="TLS",
            timestamp=now + i*0.001,
            duration=4.5,
            src_packets=3000,
            dst_packets=100,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            tls_sni="drive.google.com", # Legitimate browser SNI
            tls_ja3="771,4865-4866-4867,0-23-65281-10-11,29-23-24,0", # Standard Chrome JA3
            tls_cipher_suites_count=18, # Standard browser cipher suite count
            packet_sizes=[1460] * 10,
            packet_iat=[0.002] * 10
        )
        legit_uploads.append(flow)

    detector = ExfiltrationDetector()
    alerts = [detector.analyze_flow(f) for f in legit_uploads]
    false_positives = [a for a in alerts if a is not None]

    print(f"[+] Tested 500 Legitimate High-Ratio Benign Upload Flows (Port 443, Ratio 4.0-8.0)")
    print(f"[-] False Positives Triggered: {len(false_positives)} / 500 (FPR: {len(false_positives)/500*100:.2f}%)")
    print("=" * 80)

if __name__ == "__main__":
    main()
