"""
party_grouper.py: Groups whatsapp_packets into parties.
"""

import sqlite3
import os
import sys
from collections import defaultdict
from typing import Dict, Any

# Assuming DB_PATH is the same as in db.py
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'whatsapp.db'))

def get_normalized_5tuple(packet: Dict[str, Any]):
    """
    Reuses the 5-tuple normalization logic.
    """
    src_ip = packet["src_ip"]
    dst_ip = packet["dst_ip"]
    src_port = packet["src_port"]
    dst_port = packet["dst_port"]
    protocol = packet["protocol"]
    
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    else:
        return (dst_ip, dst_port, src_ip, src_port, protocol)

def group_packets_into_parties(pcap_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Read the 100 rows (or fewer)
    cursor.execute("SELECT * FROM whatsapp_packets WHERE pcap_id = ?", (pcap_id,))
    rows = cursor.fetchall()
    
    if not rows:
        print(f"No packets found for pcap_id: {pcap_id}")
        conn.close()
        return

    # 2. Group by normalized 5-tuple
    parties = defaultdict(list)
    for row in rows:
        packet = dict(row)
        # Re-derive 5-tuple for grouping
        key = get_normalized_5tuple(packet)
        parties[key].append(packet)
        
    # 3. Compute stats and insert
    cursor.execute("DELETE FROM parties WHERE pcap_id = ?", (pcap_id,))
    
    total_packets_inserted = 0
    
    for key, packets in parties.items():
        packet_count = len(packets)
        total_bytes = sum(p['length'] for p in packets)
        timestamps = [p['timestamp'] for p in packets]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # Classification of party_type
        # key is (src_ip, src_port, dst_ip, dst_port, protocol)
        src_port, dst_port = key[1], sys.maxsize if key[3] is None else key[3] # handle potential None ports
        media_guess = packets[0].get('whatsapp_media_guess')

        server_ports = {443, 5222}
        peer_ports = {3478}

        is_server_port = (src_port in server_ports) or (dst_port in server_ports)
        is_peer_port = (src_port in peer_ports) or (dst_port in peer_ports)

        if is_server_port or media_guess in ('message', 'photo', 'audio', 'video'):
            party_type = 'client_to_server'
        elif is_peer_port and media_guess in ('voice_call', 'video_call'):
            party_type = 'peer_to_peer'
        else:
            party_type = 'unknown'

        # Using a unique party_id based on the key and pcap_id to avoid cross-pcap uniqueness failures
        party_id = f"{pcap_id}_{key[0]}_{key[1]}_{key[2]}_{key[3]}_{key[4]}"

        cursor.execute("""
            INSERT OR REPLACE INTO parties (
                party_id, pcap_id, src_ip, dst_ip, src_port, dst_port, 
                protocol, packet_count, total_bytes, first_seen, last_seen, party_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (party_id, pcap_id, key[0], key[2], key[1], key[3], key[4], 
              packet_count, total_bytes, first_seen, last_seen, party_type))

        
        total_packets_inserted += packet_count
        
    conn.commit()
    
    # Verification
    cursor.execute("SELECT SUM(packet_count) FROM parties WHERE pcap_id = ?", (pcap_id,))
    sum_packet_count = cursor.fetchone()[0]
    
    print(f"Pcap ID: {pcap_id}")
    print(f"Total packets in whatsapp_packets: {len(rows)}")
    print(f"Sum of packet_count in parties: {sum_packet_count}")
    print(f"Number of distinct parties: {len(parties)}")
    for key, packets in parties.items():
        print(f"  Party {key}: {len(packets)} packets")
        
    assert sum_packet_count == len(rows), "Packet count mismatch!"
    
    conn.close()
