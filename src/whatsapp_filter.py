"""
whatsapp_filter.py: Classifies flows as WhatsApp based on domains, IP ranges, and behavior.
"""

import ipaddress
from typing import Dict, List, Set, Any, Tuple, Optional
import os

# Global set to track confirmed server IPs (must be populated from high-confidence evidence)
CONFIRMED_WHATSAPP_SERVERS: Set[str] = set()

# Lists for 4a
STRONG_DOMAINS = {
    "whatsapp.net", "whatsapp.com", "mmg.whatsapp.net", 
    "media.whatsapp.net", "g.whatsapp.net", "v.whatsapp.net", 
    "graph.whatsapp.com"
}
WEAK_DOMAINS = {
    "fbcdn.net", "cdninstagram.com", "facebook.com"
}

def seed_confirmed_servers(server_ip: str):
    CONFIRMED_WHATSAPP_SERVERS.add(server_ip)

def check_inference_matching(server_ip: Optional[str]) -> Tuple[str, List[str]]:
    """
    4c. Same-server-IP inference.
    Returns (confidence, signals) if the server_ip is in the confirmed set.
    """
    if server_ip and server_ip in CONFIRMED_WHATSAPP_SERVERS:
        return "medium", ["inferred_server"]
    return "none", []

def load_meta_ip_ranges(filepath: str) -> List[ipaddress.IPv4Network]:
    ranges = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ranges.append(ipaddress.ip_network(line))
                    except ValueError:
                        pass
    return ranges

META_IP_RANGES = load_meta_ip_ranges("resources/meta_ip_ranges.txt")

def check_domain_matching(sni: Optional[str], dns_query: Optional[str]) -> Tuple[str, List[str]]:
    """
    4a. Domain matching. Checks SNI and DNS against STRONG/WEAK lists.
    Returns (confidence, signals).
    """
    signals = []
    
    # Check for strong match
    if (sni and any(sni.endswith(d) for d in STRONG_DOMAINS)) or \
       (dns_query and any(dns_query.endswith(d) for d in STRONG_DOMAINS)):
        return "high", ["domain_strong"]
    
    # Check for weak match
    if (sni and any(sni.endswith(d) for d in WEAK_DOMAINS)) or \
       (dns_query and any(dns_query.endswith(d) for d in WEAK_DOMAINS)):
        return "low", ["domain_weak"]
        
    return "none", []

def check_cidr_matching(server_ip: Optional[str]) -> Tuple[str, List[str]]:
    """
    4b. CIDR matching. Checks server_ip against configured ranges.
    Returns (confidence, signals).
    """
    if not server_ip:
        return "none", []
        
    try:
        ip = ipaddress.ip_address(server_ip)
        for net in META_IP_RANGES:
            if ip in net:
                return "high", ["cidr_strong"]
    except ValueError:
        pass
        
    return "none", []

def guess_media_type(packet_count: int, upload_bytes: int, download_bytes: int, protocol_type: str, is_quic: bool) -> str:
    """
    4d. Behavioral sub-classification.
    Guesses media type based on placeholder thresholds.
    """
    # This is placeholder logic, Task 6 will tune these.
    if is_quic:
        return "video_call"
    
    total_bytes = upload_bytes + download_bytes
    if total_bytes < 10000:
        return "message"
    elif total_bytes < 100000:
        return "photo"
    elif total_bytes < 1000000:
        return "audio"
    else:
        return "video"
