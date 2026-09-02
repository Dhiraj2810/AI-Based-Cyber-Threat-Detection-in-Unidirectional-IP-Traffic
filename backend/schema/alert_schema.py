from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict

class AlertEvidence(BaseModel):
    model_config = ConfigDict(revalidate_instances='never')
    feature_name: str
    value: Any
    description: str
    impact_score: Optional[float] = None

class StandardizedAlert(BaseModel):
    model_config = ConfigDict(revalidate_instances='never')
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: str
    threat_class: str  # ddos | c2_beaconing | dga_dns_tunnel | encrypted_malware | port_scan | exfiltration | encrypted_c2_beaconing
    threat_name: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    confidence_score: float = Field(ge=0.0, le=1.0)
    supporting_evidence: Dict[str, Any]
    shap_explanations: Optional[List[AlertEvidence]] = None
    correlated_threats: Optional[List[str]] = None
    mitre_attack_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    occurrence_count: int = 1
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

class FlowRecord(BaseModel):
    model_config = ConfigDict(revalidate_instances='never')
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP | UDP | ICMP | DNS | TLS
    timestamp: float
    duration: float = 0.0
    src_packets: int = 1
    dst_packets: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    tcp_flags: List[str] = []
    
    # Metadata for specialized threat analysis (no payload decryption!)
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_ja4: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_cipher_suites_count: Optional[int] = None
    packet_sizes: List[int] = []
    packet_iat: List[float] = []  # Inter-arrival times
