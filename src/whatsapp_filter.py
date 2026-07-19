"""
whatsapp_filter.py: Classifies flows as WhatsApp based on domains, IP ranges, and behavior.

Enhancements:
  - SNI sub-activity tagging (chat_control, photo_audio, video)
  - Port-based validation (5222/5223/5228/4244/5242 = high confidence chat)
  - VoIP bitrate detection via 5-second sliding window (>12 kbps = voice_call)
  - Burst-based media guessing (burst_intensity ratio vs. raw byte thresholds)
  - STUN packet signature (is_stun_binding flag from packet_parser)
"""

import re
import ipaddress
from typing import Dict, List, Set, Any, Tuple, Optional
import os

# Global set to track confirmed server IPs (must be populated from high-confidence evidence)
CONFIRMED_WHATSAPP_SERVERS: Set[str] = set()

# Domain lists (reused by geolocation.py for rDNS verification)
STRONG_DOMAINS = {
    "whatsapp.net", "whatsapp.com", "mmg.whatsapp.net",
    "media.whatsapp.net", "g.whatsapp.net", "v.whatsapp.net",
    "graph.whatsapp.com"
}
WEAK_DOMAINS = {
    "fbcdn.net", "cdninstagram.com", "facebook.com"
}

# SNI sub-activity patterns — ordered by specificity (most specific first)
_SNI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^mmv\d+.*\.whatsapp\.net$'),    'video'),
    (re.compile(r'^mm[is]\d+.*\.whatsapp\.net$'), 'photo_audio'),
    (re.compile(r'^[cde]\d+\.whatsapp\.net$'),    'chat_control'),
    (re.compile(r'^media.*\.whatsapp\.net$'),      'media_generic'),
    (re.compile(r'^graph\.whatsapp\.com$'),        'graph_api'),
    (re.compile(r'^.*\.whatsapp\.net$'),           'whatsapp_generic'),
    (re.compile(r'^.*\.whatsapp\.com$'),           'whatsapp_generic'),
]

# WhatsApp-specific ports
WHATSAPP_CHAT_PORTS:  set = {5222, 5223, 5228, 4244, 5242}
WHATSAPP_STUN_PORTS:  set = {3478}
WHATSAPP_MEDIA_PORTS: set = {443}

# VoIP bitrate thresholds
_VOIP_THRESHOLD_KBPS   = 12.0   # sustained above → voice_call
_SIGNALING_MAX_KBPS    = 8.0    # mean below → call_signaling
_WINDOW_SECONDS        = 5.0
_WINDOW_SLIDE_STEP     = 1.0

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

def check_domain_matching(
    sni: Optional[str], dns_query: Optional[str]
) -> Tuple[str, List[str], Optional[str]]:
    """
    Domain matching with SNI sub-activity tagging.
    Returns (confidence, signals, sub_activity).
    sub_activity is one of: chat_control, photo_audio, video, media_generic,
    graph_api, whatsapp_generic, or None.
    """
    domain = sni or dns_query
    sub_activity: Optional[str] = None

    # Detect sub-activity from SNI pattern
    if sni:
        for pattern, tag in _SNI_PATTERNS:
            if pattern.match(sni):
                sub_activity = tag
                break

    # Confidence from domain lists
    if (sni and any(sni.endswith(d) for d in STRONG_DOMAINS)) or \
       (dns_query and any(dns_query.endswith(d) for d in STRONG_DOMAINS)):
        return "high", ["domain_strong"], sub_activity

    if (sni and any(sni.endswith(d) for d in WEAK_DOMAINS)) or \
       (dns_query and any(dns_query.endswith(d) for d in WEAK_DOMAINS)):
        return "low", ["domain_weak"], sub_activity

    return "none", [], sub_activity

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


def check_port_matching(
    src_port: Optional[int], dst_port: Optional[int]
) -> Tuple[str, List[str], Optional[str]]:
    """
    Port-based confidence signal.
    Returns (confidence, signals, port_activity).
    """
    ports = {p for p in (src_port, dst_port) if p is not None}
    if ports & WHATSAPP_CHAT_PORTS:
        return "high", ["port_chat"], "chat_signaling"
    if ports & WHATSAPP_STUN_PORTS:
        return "medium", ["port_stun"], "call_signaling"
    if ports & WHATSAPP_MEDIA_PORTS:
        return "low", ["port_https"], "media_or_https"
    return "none", [], None

# ---------------------------------------------------------------------------
# VoIP bitrate detection
# ---------------------------------------------------------------------------

def detect_voip_by_bitrate(packets: List[Dict[str, Any]]) -> Optional[str]:
    """
    Analyze UDP packets over 5-second sliding windows.
    Returns 'voice_call' if sustained bitrate > 12 kbps,
    'call_signaling' if mean < 8 kbps, else None.
    """
    if not packets:
        return None
    timestamps = [p['timestamp'] for p in packets if p.get('timestamp') is not None]
    if not timestamps:
        return None
    start, end = min(timestamps), max(timestamps)
    if end - start < _WINDOW_SECONDS:
        return None

    window_bitrates = []
    t = start
    while t + _WINDOW_SECONDS <= end:
        window_bytes = sum(
            p['length'] for p in packets
            if p.get('timestamp') is not None and t <= p['timestamp'] < t + _WINDOW_SECONDS
        )
        window_bitrates.append((window_bytes * 8) / (_WINDOW_SECONDS * 1000))
        t += _WINDOW_SLIDE_STEP

    if not window_bitrates:
        return None

    mean_br = sum(window_bitrates) / len(window_bitrates)
    sustained = sum(1 for b in window_bitrates if b > _VOIP_THRESHOLD_KBPS)
    if sustained / len(window_bitrates) > 0.5:
        return 'voice_call'
    if mean_br < _SIGNALING_MAX_KBPS:
        return 'call_signaling'
    return None


# ---------------------------------------------------------------------------
# Burst extraction
# ---------------------------------------------------------------------------

def extract_bursts(
    packets: List[Dict[str, Any]], threshold: float = 1.0
) -> List[List[Dict[str, Any]]]:
    """Split packets into burst groups where inter-packet gap <= threshold."""
    if not packets:
        return []
    sorted_pkts = sorted(packets, key=lambda p: p.get('timestamp', 0))
    bursts: List[List[Dict[str, Any]]] = [[sorted_pkts[0]]]
    for pkt in sorted_pkts[1:]:
        gap = pkt.get('timestamp', 0) - bursts[-1][-1].get('timestamp', 0)
        if gap <= threshold:
            bursts[-1].append(pkt)
        else:
            bursts.append([pkt])
    return bursts


# ---------------------------------------------------------------------------
# Media type guesser (burst-based)
# ---------------------------------------------------------------------------

def guess_media_type(
    packets: List[Dict[str, Any]],
    protocol_type: str,
    flow_duration: float,
    sub_activity_hint: Optional[str] = None,
) -> str:
    """
    Burst-aware media type classification.
    Priority: sub_activity_hint from SNI > VoIP bitrate > burst intensity > total bytes.
    """
    total_bytes = sum(p.get('length', 0) for p in packets)

    # 1. Prioritize SNI-derived hint
    if sub_activity_hint == 'video':
        return 'video'
    if sub_activity_hint == 'photo_audio':
        return 'audio' if total_bytes > 500_000 else 'photo'
    if sub_activity_hint == 'chat_control':
        return 'message'

    # 2. VoIP bitrate analysis for UDP flows
    if protocol_type == 'UDP':
        voip = detect_voip_by_bitrate(packets)
        if voip:
            return voip

    # 3. Burst intensity ratio
    if packets and flow_duration > 0:
        bursts = extract_bursts(packets)
        if bursts:
            max_burst_bytes = max(sum(p.get('length', 0) for p in b) for b in bursts)
            burst_intensity = max_burst_bytes / flow_duration
            if burst_intensity > 50_000 and flow_duration < 30:
                if total_bytes > 1_000_000:
                    return 'video'
                if total_bytes > 100_000:
                    return 'audio'
                return 'photo'
            if flow_duration > 300 and burst_intensity < 2_000:
                return 'message'

    # 4. Fallback: raw byte thresholds
    if total_bytes < 10_000:
        return 'message'
    if total_bytes < 100_000:
        return 'photo'
    if total_bytes < 1_000_000:
        return 'audio'
    return 'video'
