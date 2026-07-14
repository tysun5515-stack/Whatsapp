import struct
import io
import os
import csv
from src.pcap_reader import read_packets

def test_mock_pcap():
    print("Running Mock Pcap Test...")
    # Construct a minimal valid classic-pcap byte string
    # Magic (4), Major (2), Minor (2), Zone (4), Sig (4), Snap (4), Network (4)
    magic = 0xa1b2c3d4 # Standard magic
    # Pack as little-endian to simulate a little-endian file
    header = struct.pack('<IHHIIII', magic, 2, 4, 0, 0, 65535, 1)
    
    # Packet Record
    # ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    ts_sec = 1626256800
    ts_usec = 500000
    incl_len = 4
    orig_len = 4
    record_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
    payload = b'ABCD'
    
    mock_data = header + record_header + payload
    
    mock_file_path = 'mock.pcap'
    with open(mock_file_path, 'wb') as f:
        f.write(mock_data)
        
    try:
        packets = list(read_packets(mock_file_path))
        assert len(packets) == 1, f"Expected 1 packet, got {len(packets)}"
        ts, link, data = packets[0]
        assert ts == 1626256800.5, f"Expected timestamp 1626256800.5, got {ts}"
        assert link == 1, f"Expected link type 1, got {link}"
        assert data == b'ABCD', f"Expected data b'ABCD', got {data}"
        print("Mock Pcap Test Passed!")
    finally:
        if os.path.exists(mock_file_path):
            os.remove(mock_file_path)

def test_real_pcap():
    print("Running Real Pcap Validation...")
    pcap_path = "resources/Messages_record.pcap"
    csv_path = "resources/Messages_record.csv"
    
    if not os.path.exists(pcap_path) or not os.path.exists(csv_path):
        print(f"Skipping real pcap test: files not found ({pcap_path} or {csv_path})")
        return

    # Count packets from reader
    pcap_count = 0
    for _ in read_packets(pcap_path):
        pcap_count += 1
        
    # Count rows from CSV (excluding header)
    csv_count = 0
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)
        for _ in reader:
            csv_count += 1
            
    print(f"Pcap Reader Count: {pcap_count}")
    print(f"CSV Row Count: {csv_count}")
    
    assert pcap_count == csv_count, f"Count mismatch! Pcap: {pcap_count}, CSV: {csv_count}"
    print("Real Pcap Validation Passed!")

if __name__ == "__main__":
    try:
        test_mock_pcap()
        test_real_pcap()
    except Exception as e:
        print(f"Verification Failed: {e}")
        exit(1)
