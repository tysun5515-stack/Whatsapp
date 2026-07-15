import unittest
import struct
import sys
import os

# Add src to the path
sys.path.append(os.path.dirname(__file__))

from packet_parser import parse_packet

class TestPacketParser(unittest.TestCase):
    def create_synthetic_tls_frame(self, sni_name: str) -> bytes:
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

    def create_synthetic_dns_frame(self, query_name: str) -> bytes:
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

    def test_synthetic_tls_extraction(self):
        expected_sni = "mmg.whatsapp.net"
        frame = self.create_synthetic_tls_frame(expected_sni)
        record = parse_packet(1, 123.45, 1, frame)
        
        self.assertEqual(record["packet_no"], 1)
        self.assertEqual(record["timestamp"], 123.45)
        self.assertTrue(record["is_tls"])
        self.assertFalse(record["is_quic"])
        self.assertEqual(record["sni"], expected_sni)
        self.assertEqual(record["src_ip"], "192.168.1.5")
        self.assertEqual(record["dst_ip"], "192.168.1.10")
        self.assertEqual(record["src_port"], 12345)
        self.assertEqual(record["dst_port"], 443)
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["tcp_udp_flags"], "ACK,PSH")
        self.assertIn("ACK", record["tcp_udp_flags"])
        self.assertIn("PSH", record["tcp_udp_flags"])
        self.assertNotIn("SYN", record["tcp_udp_flags"])

    def test_synthetic_dns_extraction(self):
        expected_dns = "dns.whatsapp.net"
        frame = self.create_synthetic_dns_frame(expected_dns)
        record = parse_packet(2, 678.90, 1, frame)
        
        self.assertEqual(record["packet_no"], 2)
        self.assertEqual(record["timestamp"], 678.90)
        self.assertEqual(record["dns_query"], expected_dns)
        self.assertEqual(record["src_ip"], "192.168.1.5")
        self.assertEqual(record["dst_ip"], "8.8.8.8")
        self.assertEqual(record["src_port"], 54321)
        self.assertEqual(record["dst_port"], 53)
        self.assertEqual(record["protocol"], "UDP")
        self.assertIsNone(record["tcp_udp_flags"])

if __name__ == '__main__':
    unittest.main()
