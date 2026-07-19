"""
party_grouper.py: Hierarchical 5-level party aggregation.

Level 1: Transport flow partitioning (handled by flow_builder.py)
Level 2: Entity-level aggregation — group by (remote_ip, remote_port, protocol),
         ignoring ephemeral source port. Prevents one server from appearing as
         dozens of parties due to port recycling.
Level 3: Protocol session linking — TLS session ID (falls back to entity key)
Level 4: Behavioral termination — OS-aware inactivity timeout (in flow_builder.py)
Level 5: Temporal burst partitioning — 1-second gap threshold
"""

import os
import sys
from collections import defaultdict
from typing import Dict, Any, List, Tuple, Optional

# Need to import check_cidr_matching to classify Relays vs P2P
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.whatsapp_filter import check_cidr_matching

WELL_KNOWN_PORTS = {
    443, 80, 53, 5222, 5223, 5228, 4244, 5242,  # WhatsApp
    3478,                                          # STUN
    8080, 8443, 993, 465, 587, 25,               # Other common
}


def get_entity_key(packet: Dict[str, Any]) -> Tuple:
    """
    Level 2: Entity-level aggregation key.
    Groups by (remote_ip, remote_port, protocol), ignoring ephemeral source port.
    'Remote' = whichever side is on a well-known port; if neither, use lower IP.
    """
    src_ip   = packet.get("src_ip", "")
    dst_ip   = packet.get("dst_ip", "")
    src_port = packet.get("src_port") or 0
    dst_port = packet.get("dst_port") or 0
    protocol = packet.get("protocol", "UNKNOWN")

    if dst_port in WELL_KNOWN_PORTS:
        return (dst_ip, dst_port, protocol)
    elif src_port in WELL_KNOWN_PORTS:
        return (src_ip, src_port, protocol)
    else:
        # Neither side is well-known; pick the "server" by lower IP string
        if src_ip <= dst_ip:
            return (dst_ip, dst_port, protocol)
        else:
            return (src_ip, src_port, protocol)


def classify_party_type(
    remote_port: Optional[int],
    protocol: str,
    media_guess: Optional[str]
) -> str:
    """Classify the entity as client_to_server, peer_to_peer, or unknown."""
    server_ports = {443, 80, 5222, 5223, 5228, 4244, 5242}
    p2p_ports    = {3478}

    if remote_port in server_ports or media_guess in ('message', 'photo', 'audio', 'video'):
        return 'client_to_server'
    if remote_port in p2p_ports or media_guess in ('voice_call', 'video_call', 'call_signaling'):
        return 'peer_to_peer'
    return 'unknown'


def group_into_entities(
    packets: List[Dict[str, Any]],
    upload_id: str,
    os_hint: str = 'unknown',
) -> List[Dict[str, Any]]:
    """
    Level 2 + 5: Group packets into entity-level parties with burst analysis.
    Returns a list of party dicts ready for db_analysis.insert_parties().
    """
    # Level 2: entity grouping
    entity_packets: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        key = get_entity_key(pkt)
        entity_packets[key].append(pkt)

    parties = []
    for (remote_ip, remote_port, protocol), pkts in entity_packets.items():
        pkts_sorted = sorted(pkts, key=lambda p: p.get('timestamp', 0))

        timestamps  = [p['timestamp'] for p in pkts_sorted if p.get('timestamp') is not None]
        first_seen  = min(timestamps) if timestamps else 0.0
        last_seen   = max(timestamps) if timestamps else 0.0
        duration_s  = last_seen - first_seen

        total_bytes  = sum(p.get('length', 0) for p in pkts_sorted)
        packet_count = len(pkts_sorted)

        # Local IPs observed talking to this entity
        local_ips = set()
        for p in pkts_sorted:
            src, dst = p.get('src_ip'), p.get('dst_ip')
            if src and src != remote_ip:
                local_ips.add(src)
            if dst and dst != remote_ip:
                local_ips.add(dst)

        # Derive dominant media / sub_activity
        media_guesses = [p.get('whatsapp_media_guess') for p in pkts_sorted if p.get('whatsapp_media_guess')]
        sub_activities = [p.get('sub_activity') for p in pkts_sorted if p.get('sub_activity')]

        from collections import Counter
        media_guess  = Counter(media_guesses).most_common(1)[0][0] if media_guesses else None
        sub_activity = Counter(sub_activities).most_common(1)[0][0] if sub_activities else None

        # Confidence: highest observed
        confidences = [p.get('whatsapp_confidence', 'none') for p in pkts_sorted]
        confidence  = 'high' if 'high' in confidences else ('medium' if 'medium' in confidences else 'none')

        party_type = classify_party_type(remote_port, protocol, media_guess)

        # 1. Look for STUN mapped address (public local IP)
        public_local_ip = None
        for p in pkts_sorted:
            if p.get('stun_mapped_address'):
                public_local_ip = p['stun_mapped_address'].split(':')[0]
                break

        # 2. Determine Relay vs P2P for calls
        is_p2p = False
        if party_type == 'peer_to_peer' or media_guess in ('voice_call', 'video_call'):
            # Check if remote_ip is a Meta relay server
            conf_cidr, _ = check_cidr_matching(remote_ip)
            if conf_cidr == 'none':
                is_p2p = True

        party_id = f"{upload_id}_{remote_ip}_{remote_port}_{protocol}"

        parties.append({
            'party_id':     party_id,
            'upload_id':    upload_id,
            'remote_ip':    remote_ip,
            'remote_port':  remote_port,
            'protocol':     protocol,
            'local_ips':    ','.join(sorted(local_ips)),
            'public_local_ip': public_local_ip,
            'packet_count': packet_count,
            'total_bytes':  total_bytes,
            'first_seen':   first_seen,
            'last_seen':    last_seen,
            'duration_s':   duration_s,
            'party_type':   party_type,
            'sub_activity': sub_activity,
            'confidence':   confidence,
            'os_hint':      os_hint,
            'is_p2p':       is_p2p,
        })

    return sorted(parties, key=lambda p: p['packet_count'], reverse=True)
