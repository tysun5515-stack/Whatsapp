import struct
import socket
from src.packet_parser import parse_packet

# Construct a STUN Binding Response with XOR-MAPPED-ADDRESS
# IP: 198.51.100.1, Port: 54321
magic_cookie = 0x2112A442
real_ip = struct.unpack('!I', socket.inet_aton('198.51.100.1'))[0]
real_port = 54321

x_ip = real_ip ^ magic_cookie
x_port = real_port ^ (magic_cookie >> 16)

attr_len = 8
attr_type = 0x0020
family = 0x01
reserved = 0x00

stun_header = struct.pack('!HHI', 0x0101, attr_len + 4, magic_cookie)
tx_id = b'\x00' * 12 # 12 bytes
attr = struct.pack('!HHBBH', attr_type, attr_len, reserved, family, x_port) + struct.pack('!I', x_ip)

udp_payload = stun_header + tx_id + attr

# Construct dummy raw frame (Ethernet + IPv4 + UDP)
ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + 8 + len(udp_payload), 0, 0, 64, 17, 0, socket.inet_aton('1.1.1.1'), socket.inet_aton('2.2.2.2'))
udp_hdr = struct.pack('!HHHH', 3478, 54321, 8 + len(udp_payload), 0)
eth_hdr = b'\x00'*14
# need correct IP header length and ethertype is 0x0800 which is implicitly checked by packet_parser using link_type=1 -> 14 bytes ethernet. But ethernet header needs ethertype 0x0800 at bytes 12-14
eth_hdr = b'\x00'*12 + b'\x08\x00'

raw_frame = eth_hdr + ip_hdr + udp_hdr + udp_payload

record = parse_packet(1, 0.0, 1, raw_frame)
print("Extracted STUN:", record.get("stun_mapped_address"))
assert record.get("stun_mapped_address") == "198.51.100.1:54321", f"Got {record.get('stun_mapped_address')}"
print("Success!")
