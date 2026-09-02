import os
import sys
import time
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.schema.alert_schema import FlowRecord
from backend.detection.exfiltration_detector import ExfiltrationDetector

def main():
    print("=" * 85)
    print(" CLARIFICATION 2 TEST: STEALTHY HTTPS EXFILTRATION (PORT 443, RATIO 4.0 - 12.0)")
    print("=" * 85)

    now = time.time()
    stealthy_exfil_flows = []

    # Generate 250 stealthy HTTPS exfiltration flows on Port 443 with INDEPENDENT VARIATION
    # Test Case A (125 flows): Low SNI entropy (3.3 < 3.8) BUT restricted ciphers (5 <= 6)
    # Test Case B (125 flows): Standard ciphers (16) BUT suspicious unknown JA3 stager hash
    for i in range(250):
        src_bytes = random.randint(1_500_000, 4_500_000)
        ratio = random.uniform(4.5, 11.5)
        dst_bytes = int(src_bytes / ratio)
        
        is_case_a = i % 2 == 0
        sni = "custom-c2-drop.info" if is_case_a else "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=18)) + ".net"
        ciphers = 5 if is_case_a else 16
        ja3 = "standard_browser_ja3" if is_case_a else "unknown_custom_python_ja3"

        flow = FlowRecord(
            flow_id=f"192.168.1.100:{30000+i}->194.26.29.11:443[TLS]",
            src_ip="192.168.1.100",
            src_port=30000 + i,
            dst_ip="194.26.29.11",
            dst_port=443,
            protocol="TLS",
            timestamp=now + i*0.001,
            duration=15.0,
            src_packets=3000,
            dst_packets=100,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            tls_sni=sni,
            tls_ja3=ja3,
            tls_cipher_suites_count=ciphers,
            packet_sizes=[1460] * 10,
            packet_iat=[0.005] * 10
        )
        stealthy_exfil_flows.append(flow)

    detector = ExfiltrationDetector()
    alerts = [detector.analyze_flow(f) for f in stealthy_exfil_flows]
    detected = [a for a in alerts if a is not None]
    recall = (len(detected) / 250) * 100.0

    print(f"[+] Tested 250 Stealthy HTTPS Exfiltration Flows (Port 443, Ratio 4.0-12.0)")
    print(f"[-] Detections Triggered: {len(detected)} / 250")
    print(f"[-] Stealthy HTTPS Exfiltration Recall: {recall:.2f}%")
    print("=" * 85)

if __name__ == "__main__":
    main()
