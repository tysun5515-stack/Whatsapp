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
from src.db import init_db, insert_whatsapp_packets

def run_pipeline(pcap_path, output_dir):
    try:
        init_db()
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
            
        # 2. Build flows
        flows = rebuild_flows(packet_records, pcap_id=os.path.basename(pcap_path),
                              inactivity_timeout=30.0, burst_threshold=0.3)
        
        # 3. Classify flows
        CONFIRMED_WHATSAPP_SERVERS.clear()
        
        all_whatsapp_packets = []
        
        for flow in flows:
            sni, dns = None, None
            for p in flow["packets"]:
                if p.get("sni"): sni = p["sni"]
                if p.get("dns_query"): dns = p["dns_query"]
                
            conf_domain, sig_domain = check_domain_matching(sni, dns)
            conf_cidr, sig_cidr = check_cidr_matching(flow["server_ip"])
            conf_inf, sig_inf = check_inference_matching(flow["server_ip"])
            
            signals = sig_domain + sig_cidr + sig_inf
            if conf_domain == "high" or conf_cidr == "high":
                flow["whatsapp_confidence"] = "high"
                seed_confirmed_servers(flow["server_ip"])
            elif conf_domain == "low" or conf_inf == "medium":
                flow["whatsapp_confidence"] = "medium"
            else:
                flow["whatsapp_confidence"] = "none"
            flow["whatsapp_signals"] = ",".join(signals)
            
            # Sub-classify
            flow["media_type"] = guess_media_type(
                flow["packet_count"], flow["upload_bytes"], 
                flow["download_bytes"], flow["protocol_type"], False
            )
            
            # Prepare packets for DB insertion
            if flow["whatsapp_confidence"] in ["high", "medium"]:
                for p in flow["packets"]:
                    p["whatsapp_confidence"] = flow["whatsapp_confidence"]
                    p["whatsapp_media_guess"] = flow["media_type"]
                    p["flow_id"] = str(flow["flow_id"])
                    all_whatsapp_packets.append(p)
            
        # Write flow_summary.csv
        flow_csv_path = os.path.join(output_dir, "flow_summary.csv")
        flow_fieldnames = list(flows[0].keys())
        if 'packets' in flow_fieldnames: flow_fieldnames.remove('packets')
        if 'key' in flow_fieldnames: flow_fieldnames.remove('key')
        
        with open(flow_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flow_fieldnames)
            writer.writeheader()
            for flow in flows:
                row = {k: v for k, v in flow.items() if k in flow_fieldnames}
                writer.writerow(row)
        
        # Insert into DB
        insert_whatsapp_packets(os.path.basename(pcap_path), all_whatsapp_packets)
        
        # Group packets into parties
        from src.party_grouper import group_packets_into_parties
        group_packets_into_parties(os.path.basename(pcap_path))
        
        # Generate charts
        from src.party_chart import generate_party_charts
        generate_party_charts(os.path.basename(pcap_path), output_dir)
                
        print(f"Pipeline complete. Outputs: {packet_csv_path}, {flow_csv_path}")
        
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhatsApp Traffic Analysis Pipeline")
    parser.add_argument("--gui", action="store_true", help="Start the web interface")
    parser.add_argument("pcap_file", nargs='?', help="Path to the input PCAP file")
    parser.add_argument("output_dir", nargs='?', help="Directory for CSV outputs")
    args = parser.parse_args()
    
    if args.gui:
        if args.pcap_file or args.output_dir:
            parser.error("--gui takes no positional arguments; upload files via the web interface instead.")
        
        from src.webapp.app import create_app
        app = create_app()
        app.run(debug=True, port=5000)
    else:
        if not args.pcap_file or not args.output_dir:
            parser.error("The following arguments are required: pcap_file, output_dir")
        
        run_pipeline(args.pcap_file, args.output_dir)
