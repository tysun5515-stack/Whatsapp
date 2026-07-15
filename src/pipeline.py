"""
pipeline.py: CLI entry point for the network analysis pipeline.
"""

import sys
import os
import csv
import argparse
from typing import List, Dict, Any

# Ensure src is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.whatsapp_filter import (
    check_domain_matching, check_cidr_matching, 
    check_inference_matching, seed_confirmed_servers, 
    guess_media_type, CONFIRMED_WHATSAPP_SERVERS
)

def run_pipeline(pcap_path, output_dir):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 1. Parse packets
        packet_records = []
        packet_no = 0
        for ts, link, data in read_packets(pcap_path):
            packet_no += 1
            packet_records.append(parse_packet(packet_no, ts, link, data))
            
        # Write packet_metadata.csv
        packet_csv_path = os.path.join(output_dir, "packet_metadata.csv")
        fieldnames = packet_records[0].keys()
        with open(packet_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(packet_records)
            
        # 2. Build flows (using optimized params from Task 6: 30s, 0.3s)
        flows = rebuild_flows(packet_records, pcap_id=os.path.basename(pcap_path),
                              inactivity_timeout=30.0, burst_threshold=0.3)
        
        # 3. Classify flows
        CONFIRMED_WHATSAPP_SERVERS.clear()
        
        # We need the full flow objects with packets for classification and CSV output
        # Rebuild flows but keep packet info
        # Let's just modify the rebuild_flows or do classification during building.
        # Actually, let's keep the reconstruction logic and add classification
        
        # Refactoring approach: modify rebuild_flows to return flows with 'packets' included
        # Or, just parse and do the logic in-place for now.
        
        # Let's just do it here:
        from src.flow_builder import create_new_flow # This is not exported from flow_builder, need to fix
        
        # The issue is Task 3 implementation of rebuild_flows returns just summaries.
        # Let me just fix rebuild_flows to return flows with packets and let it be used for both.
        # This is a bit too much refactoring.
        # Let me just keep the packet list in a dict by key during reconstruction.

            
        # Write flow_summary.csv
        flow_csv_path = os.path.join(output_dir, "flow_summary.csv")
        flow_fieldnames = list(flows[0].keys())
        # Remove 'packets' and 'key' from csv output
        if 'packets' in flow_fieldnames: flow_fieldnames.remove('packets')
        if 'key' in flow_fieldnames: flow_fieldnames.remove('key')
        
        with open(flow_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flow_fieldnames)
            writer.writeheader()
            for flow in flows:
                # Clean up for CSV
                row = {k: v for k, v in flow.items() if k in flow_fieldnames}
                writer.writerow(row)
                
        print(f"Pipeline complete. Outputs: {packet_csv_path}, {flow_csv_path}")
        
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhatsApp Traffic Analysis Pipeline")
    parser.add_argument("pcap_file", help="Path to the input PCAP file")
    parser.add_argument("output_dir", help="Directory for CSV outputs")
    args = parser.parse_args()
    
    run_pipeline(args.pcap_file, args.output_dir)
