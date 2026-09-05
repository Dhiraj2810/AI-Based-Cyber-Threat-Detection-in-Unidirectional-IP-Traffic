import math
import numpy as np
from typing import List, Dict, Any, Tuple
from collections import Counter
from functools import lru_cache
from backend.schema.alert_schema import FlowRecord

@lru_cache(maxsize=16384)
def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (e.g. DNS query name or SNI)."""
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for ch in set(data):
        p = data.count(ch) / length
        entropy -= p * math.log2(p)
    return entropy

def calculate_ip_entropy(ip_list: List[str]) -> float:
    """Calculate Shannon entropy of a list of IP addresses in a time window."""
    if not ip_list:
        return 0.0
    length = len(ip_list)
    counts = Counter(ip_list)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def extract_ngram_freq(domain: str, n: int = 2) -> Dict[str, float]:
    """Extract character n-grams from a domain name and compute frequency."""
    domain_clean = domain.lower().replace('.', '')
    if len(domain_clean) < n:
        return {}
    ngrams = [domain_clean[i:i+n] for i in range(len(domain_clean) - n + 1)]
    total = len(ngrams)
    counts = Counter(ngrams)
    return {k: v / total for k, v in counts.items()}

class FeatureExtractor:
    """Computes flow-level and windowed statistical and ML features."""

    @staticmethod
    def extract_flow_features(flow: FlowRecord) -> Dict[str, Any]:
        duration = max(flow.duration, 0.001)
        total_packets = flow.src_packets + flow.dst_packets
        total_bytes = flow.src_bytes + flow.dst_bytes
        
        pps = total_packets / duration
        bps = (total_bytes * 8) / duration
        byte_ratio = flow.src_bytes / max(flow.dst_bytes, 1)

        # Fast Timing features using pure math
        iats = flow.packet_iat[:20] if flow.packet_iat else [duration / max(total_packets, 1)]
        n_iat = len(iats)
        iat_mean = sum(iats) / n_iat
        if n_iat > 1 and iats[0] != iats[-1]:
            iat_sq_sum = sum(x * x for x in iats)
            iat_var = max(iat_sq_sum / n_iat - iat_mean * iat_mean, 0.0)
            iat_std = math.sqrt(iat_var)
        else:
            iat_std = 0.0
        iat_cv = iat_std / max(iat_mean, 1e-6)

        # Fast Packet size sequence features using pure math
        sizes = flow.packet_sizes[:20] if flow.packet_sizes else [flow.src_bytes]
        n_sizes = len(sizes)
        size_mean = sum(sizes) / n_sizes
        if n_sizes > 1 and sizes[0] != sizes[-1]:
            size_sq_sum = sum(x * x for x in sizes)
            size_var = max(size_sq_sum / n_sizes - size_mean * size_mean, 0.0)
            size_std = math.sqrt(size_var)
        else:
            size_std = 0.0

        # DNS features
        dns_entropy = calculate_shannon_entropy(flow.dns_query_name) if flow.dns_query_name else 0.0
        dns_len = len(flow.dns_query_name) if flow.dns_query_name else 0
        subdomain_count = flow.dns_query_name.count('.') if flow.dns_query_name else 0

        # TLS features
        tls_sni_entropy = calculate_shannon_entropy(flow.tls_sni) if flow.tls_sni else 0.0

        return {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": duration,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "pps": pps,
            "bps": bps,
            "byte_ratio": byte_ratio,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_cv": iat_cv,
            "size_mean": size_mean,
            "size_std": size_std,
            "dns_name": flow.dns_query_name,
            "dns_entropy": dns_entropy,
            "dns_len": dns_len,
            "subdomain_count": subdomain_count,
            "dns_query_type": flow.dns_query_type,
            "tls_ja3": flow.tls_ja3,
            "tls_ja4": flow.tls_ja4,
            "tls_sni": flow.tls_sni,
            "tls_sni_entropy": tls_sni_entropy,
            "tls_ciphers_count": flow.tls_cipher_suites_count or 0,
            "packet_sizes_seq": sizes[:10],
            "packet_iat_seq": iats[:10]
        }

    @staticmethod
    def extract_window_features(window_flows: List[FlowRecord]) -> Dict[str, Any]:
        """Compute aggregate window statistics for DDoS and Fan-out port scanning."""
        if not window_flows:
            return {
                "window_size": 0,
                "src_ip_entropy": 0.0,
                "total_pps": 0.0,
                "total_bps": 0.0,
                "fan_out_ports": {},
                "fan_out_hosts": {}
            }

        src_ips = [f.src_ip for f in window_flows]
        src_ip_entropy = calculate_ip_entropy(src_ips)
        
        duration = max(window_flows[-1].timestamp - window_flows[0].timestamp, 1.0)
        total_packets = sum(f.src_packets + f.dst_packets for f in window_flows)
        total_bytes = sum(f.src_bytes + f.dst_bytes for f in window_flows)

        # Fan-out tracking per source IP
        fan_out_ports: Dict[str, set] = {}
        fan_out_hosts: Dict[str, set] = {}

        for f in window_flows:
            src = f.src_ip
            if src not in fan_out_ports:
                fan_out_ports[src] = set()
                fan_out_hosts[src] = set()
            fan_out_ports[src].add(f.dst_port)
            fan_out_hosts[src].add(f.dst_ip)

        fan_out_port_counts = {k: len(v) for k, v in fan_out_ports.items()}
        fan_out_host_counts = {k: len(v) for k, v in fan_out_hosts.items()}

        return {
            "window_size": len(window_flows),
            "src_ip_entropy": src_ip_entropy,
            "total_pps": total_packets / duration,
            "total_bps": (total_bytes * 8) / duration,
            "fan_out_ports": fan_out_port_counts,
            "fan_out_hosts": fan_out_host_counts
        }
