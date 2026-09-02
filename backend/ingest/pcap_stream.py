import socket
import struct
import dpkt
from typing import Generator, Optional, List
from backend.schema.alert_schema import FlowRecord

def inet_to_str(inet) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return str(inet)

class PCAPStreamReader:
    """Passively reads PCAP captures and emits FlowRecord objects."""

    @staticmethod
    def read_pcap_file(file_path: str) -> Generator[FlowRecord, None, None]:
        with open(file_path, 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src_ip = inet_to_str(ip.src)
                    dst_ip = inet_to_str(ip.dst)
                    proto_name = "IP"
                    src_port = 0
                    dst_port = 0

                    dns_name = None
                    dns_type = None

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        proto_name = "TCP"
                        if dst_port == 443 or src_port == 443:
                            proto_name = "TLS"

                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport
                        proto_name = "UDP"
                        if dst_port == 53 or src_port == 53:
                            proto_name = "DNS"
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                if dns.qd:
                                    dns_name = dns.qd[0].name
                                    dns_type = "A" if dns.qd[0].type == 1 else "TXT"
                            except Exception:
                                pass

                    flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}[{proto_name}]"

                    yield FlowRecord(
                        flow_id=flow_id,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto_name,
                        timestamp=float(ts),
                        duration=0.01,
                        src_packets=1,
                        dst_packets=0,
                        src_bytes=len(buf),
                        dst_bytes=0,
                        dns_query_name=dns_name,
                        dns_query_type=dns_type,
                        packet_sizes=[len(buf)],
                        packet_iat=[0.01]
                    )

                except Exception as e:
                    continue
