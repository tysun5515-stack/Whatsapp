import struct
import sys
import os

# Add src to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from packet_parser import parse_packet
from pcap_reader import read_packets

def create_synthetic_tls_frame(sni_name: str) -> bytes:
    # 1. Ethernet Header (14 bytes)
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        b"\x66\x77\x88\x99\xaa\xbb"  # src MAC
        b"\x08\x00"                  # EtherType (IPv4)
    )
    
    # SNI payload construction
    name_bytes = sni_name.encode('utf-8')
    name_len = len(name_bytes)
    
    # Server Name Entry:
    # Name Type: 1 byte (0x00 for host_name)
    # Name Length: 2 bytes
    # Name: name_len bytes
    entry = b"\x00" + struct.pack('!H', name_len) + name_bytes
    
    # Server Name List:
    # List Length: 2 bytes
    # Entry
    list_len = len(entry)
    server_name_list = struct.pack('!H', list_len) + entry
    
    # Extension:
    # Extension Type: 2 bytes (0x0000)
    # Extension Length: 2 bytes
    # Extension Data
    ext_len = len(server_name_list)
    extension = struct.pack('!HH', 0, ext_len) + server_name_list
    
    # Extensions Block:
    # Extensions Length: 2 bytes
    # Extension
    exts_block_len = len(extension)
    extensions_block = struct.pack('!H', exts_block_len) + extension
    
    # ClientHello body:
    # Version: 2 bytes (0x0303)
    # Random: 32 bytes
    # Session ID Length: 1 byte (0x00)
    # Cipher Suites: 2 bytes length + 2 bytes suite
    # Compression: 1 byte length + 1 byte method (0x00)
    # Extensions
    client_hello_body = (
        b"\x03\x03" +
        (b"\xaa" * 32) +
        b"\x00" +
        b"\x00\x02\x12\x34" +
        b"\x01\x00" +
        extensions_block
    )
    
    # Handshake Header:
    # Handshake Type: 1 byte (0x01 ClientHello)
    # Length: 3 bytes
    hand_len = len(client_hello_body)
    handshake_header = b"\x01" + struct.pack('!I', hand_len)[1:]
    
    handshake_payload = handshake_header + client_hello_body
    
    # TLS Record Header:
    # Content Type: 1 byte (0x16 Handshake)
    # Version: 2 bytes (0x0303)
    # Length: 2 bytes
    tls_rec_len = len(handshake_payload)
    tls_header = b"\x16\x03\x03" + struct.pack('!H', tls_rec_len)
    
    tls_payload = tls_header + handshake_payload
    
    # 2. IPv4 Header (20 bytes)
    ip_proto = 6  # TCP
    ip_total_len = 20 + 20 + len(tls_payload)
    ip_header = struct.pack(
        '!BBHHHBBHII',
        0x45,         # Version/IHL (IPv4, 20 bytes)
        0x00,         # DSCP/ECN
        ip_total_len, # Total Length
        0x1234,       # Identification
        0x4000,       # Flags (DF)
        0x40,         # TTL
        ip_proto,     # Protocol
        0x0000,       # Header Checksum (placeholder)
        0xc0a80105,   # Source IP (192.168.1.5)
        0xc0a8010a    # Dest IP (192.168.1.10)
    )
    
    # 3. TCP Header (20 bytes)
    tcp_header = struct.pack(
        '!HHIIBBHHH',
        12345,        # Source Port
        443,          # Destination Port
        1,            # Seq Num
        0,            # Ack Num
        0x50,         # Data Offset (5 * 4 = 20 bytes), Flags 0
        0x18,         # Flags (PSH, ACK)
        0xfaf0,       # Window
        0x0000,       # Checksum (placeholder)
        0x0000        # Urgent Pointer
    )
    
    return eth_header + ip_header + tcp_header + tls_payload

def create_synthetic_dns_frame(query_name: str) -> bytes:
    # 1. Ethernet Header (14 bytes)
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        b"\x66\x77\x88\x99\xaa\xbb"  # src MAC
        b"\x08\x00"                  # EtherType (IPv4)
    )
    
    # QNAME construction
    qname = b""
    for part in query_name.split('.'):
        part_bytes = part.encode('utf-8')
        qname += struct.pack('B', len(part_bytes)) + part_bytes
    qname += b"\x00"
    
    # DNS Question body
    # QNAME + QTYPE (2 bytes, 0x0001 A) + QCLASS (2 bytes, 0x0001 IN)
    dns_question = qname + b"\x00\x01\x00\x01"
    
    # DNS Header:
    # ID: 2 bytes
    # Flags: 2 bytes (0x0100 standard query)
    # QDCOUNT: 2 bytes (1)
    # ANCOUNT, NSCOUNT, ARCOUNT: 2 bytes each (0)
    dns_header = (
        b"\x12\x34" +
        b"\x01\x00" +
        b"\x00\x01" +
        b"\x00\x00" +
        b"\x00\x00" +
        b"\x00\x00"
    )
    
    dns_payload = dns_header + dns_question
    
    # 2. IPv4 Header (20 bytes)
    ip_proto = 17  # UDP
    ip_total_len = 20 + 8 + len(dns_payload)
    ip_header = struct.pack(
        '!BBHHHBBHII',
        0x45,         # Version/IHL (IPv4, 20 bytes)
        0x00,         # DSCP/ECN
        ip_total_len, # Total Length
        0x5678,       # Identification
        0x0000,       # Flags/Frag
        0x40,         # TTL
        ip_proto,     # Protocol
        0x0000,       # Checksum
        0xc0a80105,   # Source IP (192.168.1.5)
        0x08080808    # Dest IP (8.8.8.8)
    )
    
    # 3. UDP Header (8 bytes)
    udp_len = 8 + len(dns_payload)
    udp_header = struct.pack(
        '!HHHH',
        54321,        # Source Port
        53,           # Destination Port
        udp_len,      # Length
        0x0000        # Checksum
    )
    
    return eth_header + ip_header + udp_header + dns_payload

def test_synthetic_frames():
    print("Testing synthetic TLS ClientHello frame...")
    expected_sni = "mmg.whatsapp.net"
    tls_frame = create_synthetic_tls_frame(expected_sni)
    record = parse_packet(1, 1626256800.0, 1, tls_frame)
    
    assert record["is_tls"] is True, "Expected is_tls to be True"
    assert record["sni"] == expected_sni, f"Expected SNI to be {expected_sni}, got {record['sni']}"
    assert record["src_ip"] == "192.168.1.5", f"Expected src_ip to be 192.168.1.5, got {record['src_ip']}"
    assert record["dst_ip"] == "192.168.1.10", f"Expected dst_ip to be 192.168.1.10, got {record['dst_ip']}"
    assert record["src_port"] == 12345, f"Expected src_port to be 12345, got {record['src_port']}"
    assert record["dst_port"] == 443, f"Expected dst_port to be 443, got {record['dst_port']}"
    assert record["protocol"] == "TCP", f"Expected protocol to be TCP, got {record['protocol']}"
    assert "PSH" in record["tcp_udp_flags"] and "ACK" in record["tcp_udp_flags"], "Expected TCP flags to have PSH,ACK"
    
    print("Synthetic TLS ClientHello frame test passed!")
    
    print("Testing synthetic DNS query frame...")
    expected_dns = "dns.whatsapp.net"
    dns_frame = create_synthetic_dns_frame(expected_dns)
    record2 = parse_packet(2, 1626256801.0, 1, dns_frame)
    
    assert record2["dns_query"] == expected_dns, f"Expected DNS query to be {expected_dns}, got {record2['dns_query']}"
    assert record2["src_ip"] == "192.168.1.5", f"Expected src_ip to be 192.168.1.5, got {record2['src_ip']}"
    assert record2["dst_ip"] == "8.8.8.8", f"Expected dst_ip to be 8.8.8.8, got {record2['dst_ip']}"
    assert record2["src_port"] == 54321, f"Expected src_port to be 54321, got {record2['src_port']}"
    assert record2["dst_port"] == 53, f"Expected dst_port to be 53, got {record2['dst_port']}"
    assert record2["protocol"] == "UDP", f"Expected protocol to be UDP, got {record2['protocol']}"
    assert record2["tcp_udp_flags"] is None, "Expected UDP packet to have no flags"
    
    print("Synthetic DNS query frame test passed!")

def test_real_capture_parsing():
    resources_dir = "resources"
    if not os.path.exists(resources_dir):
        print(f"Skipping real capture test: {resources_dir} directory not found.")
        return
        
    pcap_files = [f for f in os.listdir(resources_dir) if f.endswith(".pcap")]
    if not pcap_files:
        print(f"No pcap files found in {resources_dir}.")
        return
        
    snis_found = []
    dns_queries_found = []
    
    for pcap_file in pcap_files:
        pcap_path = os.path.join(resources_dir, pcap_file)
        print(f"Parsing real pcap capture: {pcap_path}")
        
        packet_no = 0
        file_snis = 0
        file_dns = 0
        for ts, link, data in read_packets(pcap_path):
            packet_no += 1
            record = parse_packet(packet_no, ts, link, data)
            if record["sni"]:
                snis_found.append((pcap_file, packet_no, record["sni"]))
                file_snis += 1
            if record["dns_query"]:
                dns_queries_found.append((pcap_file, packet_no, record["dns_query"]))
                file_dns += 1
                
        print(f"  Processed {packet_no} packets: found {file_snis} SNIs, {file_dns} DNS queries.")
        
    print(f"\nTotal SNIs found across all files: {len(snis_found)}")
    print(f"Total DNS queries found across all files: {len(dns_queries_found)}")
    
    print("\n--- Spot-check 5 SNI values ---")
    for fname, pkt_num, sni in snis_found[:5]:
        print(f"File {fname}, Packet No {pkt_num}: SNI = {sni}")
        
    print("\n--- Spot-check 5 DNS query values ---")
    for fname, pkt_num, query in dns_queries_found[:5]:
        print(f"File {fname}, Packet No {pkt_num}: DNS Query = {query}")
        
    assert len(snis_found) > 0, "No SNIs found across any real capture!"
    assert len(dns_queries_found) > 0, "No DNS queries found across any real capture!"

if __name__ == "__main__":
    try:
        test_synthetic_frames()
        test_real_capture_parsing()
        print("\nAll Packet Parser Verifications Passed successfully!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Verification Failed: {e}")
        sys.exit(1)
