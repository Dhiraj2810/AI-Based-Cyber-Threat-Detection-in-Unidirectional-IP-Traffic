import random
import time
import string
from typing import Generator, List, Optional
from backend.schema.alert_schema import FlowRecord

BENIGN_SERVERS = [
    ("142.250.190.46", 443, "TLS", "google.com"),
    ("13.107.42.14", 443, "TLS", "microsoft.com"),
    ("1.1.1.1", 53, "DNS", "one.one.one.one"),
    ("8.8.8.8", 53, "DNS", "dns.google"),
    ("104.16.132.229", 443, "TLS", "cloudflare.com")
]

MALICIOUS_JA3_SAMPLES = [
    ("51c64c77e60f3980eea0324c1e16f1ed", "t13d151600_8da5c8b52b03_000000000000", "CobaltStrike C2"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "t12d080400_b247f0e911a2_123456789abc", "TrickBot"),
    ("de350869b8c85670d379613d80768079", "t13d030200_a1b2c3d4e5f6_000000000000", "AsyncRAT")
]

# Pre-allocated pools for high-speed synthetic flow generation
PRE_GENERATED_DGA_DOMAINS = [f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=28))}.c2tunnel.biz" for _ in range(500)]
PRE_GENERATED_SNI_STRINGS = [''.join(random.choices(string.ascii_lowercase + string.digits, k=25)) for _ in range(500)]
PRECOMPUTED_SIZES = [[random.randint(64, 1400) for _ in range(k)] for k in range(3, 35)]
PRECOMPUTED_IATS = [[round(random.uniform(0.01, 0.1), 4) for _ in range(k)] for k in range(3, 35)]

class FlowStreamGenerator:
    """Generates real-time synthetic flow streams for benign and attack scenarios."""

    def __init__(self, internal_subnet: str = "192.168.1."):
        self.internal_subnet = internal_subnet
        self.active_attacks: set = set()
        self.attack_start_time: float = 0.0

    @property
    def active_attack(self) -> Optional[str]:
        """Legacy helper returning first active attack or None."""
        if not self.active_attacks:
            return None
        return next(iter(self.active_attacks))

    def set_active_attack(self, attack_type: Optional[str]):
        """Sets active attack to the specified single attack vector."""
        if attack_type is None:
            self.active_attacks.clear()
        else:
            self.active_attacks = {attack_type}
        self.attack_start_time = time.time()

    def toggle_attack(self, attack_type: str) -> List[str]:
        """Toggles an attack vector ON or OFF in the active attacks set."""
        if attack_type in self.active_attacks:
            self.active_attacks.remove(attack_type)
        else:
            self.active_attacks.add(attack_type)
        self.attack_start_time = time.time()
        return list(self.active_attacks)

    def set_active_attacks(self, attacks: List[str]) -> List[str]:
        """Sets the exact list of active attack vectors."""
        self.active_attacks = set(attacks)
        self.attack_start_time = time.time()
        return list(self.active_attacks)

    def generate_flow_batch(self, count: int = 20) -> List[FlowRecord]:
        flows = []
        now = time.time()

        active_list = list(self.active_attacks)

        for i in range(count):
            if active_list and random.random() < 0.70:
                selected_attack = random.choice(active_list)
                flow = self._generate_attack_flow(selected_attack, now, i)
            else:
                flow = self._generate_benign_flow(now)
            flows.append(flow)

        return flows

    def _generate_benign_flow(self, now: float) -> FlowRecord:
        client_host = random.randint(10, 250)
        client_ip = f"{self.internal_subnet}{client_host}"
        srv_ip, srv_port, proto, domain = BENIGN_SERVERS[client_host % len(BENIGN_SERVERS)]
        client_port = 32000 + (client_host * 137) % 33000

        duration = 0.05 + (client_host % 100) * 0.02
        src_pkts = 3 + (client_host % 25)
        dst_pkts = 3 + (client_host % 35)
        src_bytes = src_pkts * 250
        dst_bytes = dst_pkts * 800

        iats = PRECOMPUTED_IATS[src_pkts - 3]
        sizes = PRECOMPUTED_SIZES[src_pkts - 3]

        dns_name = domain if proto == "DNS" else None
        tls_sni = domain if proto == "TLS" else None

        return FlowRecord(
            flow_id=f"{client_ip}:{client_port}->{srv_ip}:{srv_port}[{proto}]",
            src_ip=client_ip,
            src_port=client_port,
            dst_ip=srv_ip,
            dst_port=srv_port,
            protocol=proto,
            timestamp=now,
            duration=duration,
            src_packets=src_pkts,
            dst_packets=dst_pkts,
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            tcp_flags=["SYN", "ACK", "PSH"],
            dns_query_name=dns_name,
            dns_query_type="A" if dns_name else None,
            tls_sni=tls_sni,
            tls_ja3="771,4865-4866-4867,0-23-65281-10-11,29-23-24,0" if proto == "TLS" else None,
            tls_cipher_suites_count=18 if proto == "TLS" else None,
            packet_sizes=sizes,
            packet_iat=iats
        )

    def _generate_attack_flow(self, attack: str, now: float, index: int) -> FlowRecord:
        if attack == "ddos":
            # Volumetric SYN flood
            src_ip = f"192.168.1.{random.randint(1, 255)}" if random.random() > 0.5 else f"{random.randint(1,220)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            target_ip = "10.0.0.100"
            return FlowRecord(
                flow_id=f"{src_ip}:{random.randint(1024,65535)}->{target_ip}:80[TCP_SYN]",
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=target_ip,
                dst_port=80,
                protocol="TCP",
                timestamp=now,
                duration=0.001,
                src_packets=random.randint(200, 1000),
                dst_packets=0,
                src_bytes=random.randint(12000, 60000),
                dst_bytes=0,
                tcp_flags=["SYN"],
                packet_sizes=[64] * 10,
                packet_iat=[0.0001] * 10
            )

        elif attack == "port_scan":
            # Fan-out scan from a single attacker source IP
            attacker_ip = "192.168.1.99"
            target_port = 1 + (index * 7) % 1000
            target_host = f"10.0.0.{(index % 25) + 1}"
            return FlowRecord(
                flow_id=f"{attacker_ip}:{45000+index}->{target_host}:{target_port}[TCP_SYN]",
                src_ip=attacker_ip,
                src_port=45000 + index,
                dst_ip=target_host,
                dst_port=target_port,
                protocol="TCP",
                timestamp=now,
                duration=0.005,
                src_packets=1,
                dst_packets=0,
                src_bytes=64,
                dst_bytes=0,
                tcp_flags=["SYN"],
                packet_sizes=[64],
                packet_iat=[0.005]
            )

        elif attack == "c2_beaconing":
            # Periodic low-variance beaconing to C2 IP
            infected_host = "192.168.1.45"
            c2_ip = "185.220.101.5"
            iat = 3.0  # Steady 3-second heartbeat
            return FlowRecord(
                flow_id=f"{infected_host}:{52140+index}->{c2_ip}:443[TCP]",
                src_ip=infected_host,
                src_port=52140 + index,
                dst_ip=c2_ip,
                dst_port=443,
                protocol="TCP",
                timestamp=now,
                duration=15.0,
                src_packets=10,
                dst_packets=10,
                src_bytes=1200,
                dst_bytes=1400,
                tcp_flags=["SYN", "ACK", "PSH"],
                packet_sizes=[120] * 10,
                packet_iat=[iat, iat + 0.01, iat - 0.01, iat, iat + 0.005]
            )

        elif attack == "dga_dns_tunnel":
            # DGA / DNS Tunneling high entropy query
            infected_host = "192.168.1.88"
            dga_domain = random.choice(PRE_GENERATED_DGA_DOMAINS)
            return FlowRecord(
                flow_id=f"{infected_host}:{33000+index}->8.8.8.8:53[DNS]",
                src_ip=infected_host,
                src_port=33000 + index,
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="DNS",
                timestamp=now,
                duration=0.05,
                src_packets=1,
                dst_packets=1,
                src_bytes=180,
                dst_bytes=220,
                dns_query_name=dga_domain,
                dns_query_type="TXT" if random.random() > 0.5 else "A",
                packet_sizes=[180],
                packet_iat=[0.05]
            )

        elif attack == "encrypted_malware":
            # Encrypted session with malicious JA3 / JA4 fingerprint
            infected_host = "192.168.1.112"
            c2_ip = "194.26.29.11"
            ja3, ja4, name = random.choice(MALICIOUS_JA3_SAMPLES)
            rand_sni = random.choice(PRE_GENERATED_SNI_STRINGS)
            return FlowRecord(
                flow_id=f"{infected_host}:{49180+index}->{c2_ip}:443[TLS]",
                src_ip=infected_host,
                src_port=49180 + index,
                dst_ip=c2_ip,
                dst_port=443,
                protocol="TLS",
                timestamp=now,
                duration=2.5,
                src_packets=6,
                dst_packets=5,
                src_bytes=1500,
                dst_bytes=800,
                tls_ja3=ja3,
                tls_ja4=ja4,
                tls_sni=f"{rand_sni}.{name.lower().replace(' ', '')}.ru",
                tls_cipher_suites_count=3,
                packet_sizes=[200, 200, 200, 200, 200, 500],
                packet_iat=[0.5, 0.5, 0.5, 0.5, 0.5]
            )

        elif attack == "exfiltration":
            # Asymmetric massive byte outbound transfer
            compromised_host = "192.168.1.200"
            exfil_drop = "45.142.214.8"
            return FlowRecord(
                flow_id=f"{compromised_host}:{41900+index}->{exfil_drop}:8443[TCP]",
                src_ip=compromised_host,
                src_port=41900 + index,
                dst_ip=exfil_drop,
                dst_port=8443,
                protocol="TCP",
                timestamp=now,
                duration=10.0,
                src_packets=5000,
                dst_packets=100,
                src_bytes=7_500_000,  # 7.5 MB egress
                dst_bytes=150_000,     # 150 KB ingress (50:1 ratio!)
                packet_sizes=[1460] * 10,
                packet_iat=[0.002] * 10
            )

        return self._generate_benign_flow(now)
