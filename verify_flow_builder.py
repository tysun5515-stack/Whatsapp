import sys
import os

# Add src to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from pcap_reader import read_packets
from packet_parser import parse_packet
from flow_builder import rebuild_flows

def test_real_capture_flow_reconstruction():
    pcap_path = "resources/Messages_record.pcap"
    if not os.path.exists(pcap_path):
        print(f"Skipping flow builder verification: {pcap_path} not found.")
        return
        
    print(f"Starting flow builder verification on: {pcap_path}")
    
    # 1. Parse packets
    packet_records = []
    packet_no = 0
    total_raw_packets = 0
    total_ip_packets = 0
    total_ip_bytes = 0
    
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        total_raw_packets += 1
        record = parse_packet(packet_no, ts, link, data)
        packet_records.append(record)
        
        if record["src_ip"] is not None and record["dst_ip"] is not None:
            total_ip_packets += 1
            total_ip_bytes += record["length"]
            
    print(f"Total raw packets in file: {total_raw_packets}")
    print(f"Total IP-bearing packets: {total_ip_packets}")
    print(f"Total IP packet bytes: {total_ip_bytes}")
    
    # 2. Reconstruct flows
    flows = rebuild_flows(packet_records, pcap_id="Messages_record.pcap", inactivity_timeout=1.0)
    
    flow_count = len(flows)
    print(f"Reconstructed flow count: {flow_count}")
    
    # Assert (a): flow count is small and sane (not 1 per packet, not 1 for the whole file)
    assert 1 < flow_count < total_ip_packets, f"Flow count {flow_count} is not sane (expected between 1 and {total_ip_packets})"
    print("Assertion (a) passed: flow count is small and sane.")
    
    # Assert (b): sum(upload_bytes + download_bytes) across all flows equals total bytes of IP-bearing packets
    sum_flow_bytes = sum(flow["upload_bytes"] + flow["download_bytes"] for flow in flows)
    print(f"Sum of bytes across all flows: {sum_flow_bytes}")
    
    assert sum_flow_bytes == total_ip_bytes, f"Byte mismatch! Flows sum: {sum_flow_bytes}, IP packets sum: {total_ip_bytes}"
    print("Assertion (b) passed: sum of flow bytes equals total IP packet bytes.")
    
    # Assert (c): every IP packet's direction field got filled in (none left null)
    ip_packet_records = [p for p in packet_records if p["src_ip"] is not None and p["dst_ip"] is not None]
    
    for idx, p in enumerate(ip_packet_records):
        assert p["direction"] in ("upload", "download"), f"Packet {idx} has invalid/null direction: {p['direction']}"
        
    print("Assertion (c) passed: all IP packets have a valid direction field (upload/download).")
    
    # Display some flow details for spot checking
    print("\n--- Summary of first 5 flows ---")
    for f in flows[:5]:
        print(f"Flow {f['flow_id']}: {f['client_ip']}:{f['client_port']} -> {f['server_ip']}:{f['server_port']} "
              f"[{f['protocol_type']}] - Duration: {f['duration']:.4f}s, Packets: {f['packet_count']} (U:{f['upload_packet_count']}, D:{f['download_packet_count']}), "
              f"Bytes: {f['upload_bytes'] + f['download_bytes']} (U:{f['upload_bytes']}, D:{f['download_bytes']}), "
              f"Bursts: {f['burst_count']}, IAT Mean: {f['inter_arrival_mean']:.6f}s")
        
if __name__ == "__main__":
    try:
        test_real_capture_flow_reconstruction()
        print("\nFlow Builder Verification Completed successfully!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Verification Failed: {e}")
        sys.exit(1)
