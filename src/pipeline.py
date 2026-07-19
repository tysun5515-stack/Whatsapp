import sys
import os
import csv
import argparse
from typing import List, Dict, Any, Tuple

# Ensure src is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.whatsapp_filter import (
    check_domain_matching, check_cidr_matching, 
    check_inference_matching, check_port_matching,
    seed_confirmed_servers, guess_media_type, CONFIRMED_WHATSAPP_SERVERS
)
from src.os_fingerprint import fingerprint_os, OS_TIMEOUTS


def process_pcap_to_whatsapp_packets(pcap_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Runs the core parsing and filtering pipeline.
    Returns (stats_dict, all_classified_packets, all_flows).
    Designed to be called by the forensic web UI.
    """
    # 1. Parse packets
    packet_records = []
    packet_no = 0
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        packet_records.append(parse_packet(packet_no, ts, link, data))
        
    # 2. OS Fingerprinting & OS-aware flow building
    detected_os = fingerprint_os(packet_records)
    timeout = OS_TIMEOUTS.get(detected_os, OS_TIMEOUTS['unknown'])
    
    flows = rebuild_flows(
        packet_records, 
        pcap_id=os.path.basename(pcap_path),
        inactivity_timeout=timeout, 
        burst_threshold=1.0
    )
    
    # 3. Classify flows
    CONFIRMED_WHATSAPP_SERVERS.clear()
    all_whatsapp_packets = []
    whatsapp_flow_count = 0
    
    for flow in flows:
        sni, dns = None, None
        for p in flow["packets"]:
            if p.get("sni"): sni = p["sni"]
            if p.get("dns_query"): dns = p["dns_query"]
            
        conf_domain, sig_domain, sub_activity_domain = check_domain_matching(sni, dns)
        conf_cidr, sig_cidr = check_cidr_matching(flow["server_ip"])
        conf_inf, sig_inf = check_inference_matching(flow["server_ip"])
        conf_port, sig_port, port_activity = check_port_matching(flow["client_port"], flow["server_port"])
        
        signals = sig_domain + sig_cidr + sig_inf + sig_port
        
        # High confidence triggers
        if conf_domain == "high" or conf_cidr == "high" or conf_port == "high":
            flow["whatsapp_confidence"] = "high"
            seed_confirmed_servers(flow["server_ip"])
        elif conf_domain == "low" or conf_inf == "medium" or conf_port == "medium":
            flow["whatsapp_confidence"] = "medium"
        else:
            flow["whatsapp_confidence"] = "none"
            
        flow["whatsapp_signals"] = ",".join(signals)
        
        # Sub-activity (prioritize domain over port)
        flow["sub_activity"] = sub_activity_domain or port_activity
        
        # Sub-classify media type with burst-aware logic
        flow_duration = (flow.get("last_seen", 0) - flow.get("first_seen", 0)) or 1.0
        flow["media_type"] = guess_media_type(
            flow["packets"], 
            flow["protocol_type"], 
            flow_duration,
            sub_activity_hint=flow["sub_activity"]
        )
        
        # Extract packets
        if flow["whatsapp_confidence"] in ["high", "medium"]:
            whatsapp_flow_count += 1
            for p in flow["packets"]:
                p["whatsapp_confidence"] = flow["whatsapp_confidence"]
                p["whatsapp_media_guess"] = flow["media_type"]
                p["sub_activity"] = flow["sub_activity"]
                p["flow_id"] = str(flow["flow_id"])
                all_whatsapp_packets.append(p)
                
    stats = {
        'packet_count': len(packet_records),
        'flow_count': len(flows),
        'whatsapp_flow_count': whatsapp_flow_count,
        'whatsapp_count': len(all_whatsapp_packets),
        'detected_os': detected_os,
        'os_timeout_used': timeout
    }
    
    return stats, all_whatsapp_packets, flows


def run_pipeline(pcap_path, output_dir):
    """Legacy CLI pipeline entry point."""
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        stats, all_whatsapp_packets, flows = process_pcap_to_whatsapp_packets(pcap_path)
        
        # We don't save CSVs or write to old DB in the new architecture,
        # but for legacy compatibility we can just print stats.
        print(f"Pipeline complete. Parsed {stats['packet_count']} packets -> {stats['flow_count']} flows.")
        print(f"Detected OS: {stats['detected_os']} (Timeout: {stats['os_timeout_used']}s)")
        print(f"Found {stats['whatsapp_count']} WhatsApp packets.")
        
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhatsApp Traffic Analysis Pipeline")
    parser.add_argument("pcap_file", help="Path to the input PCAP file")
    parser.add_argument("output_dir", nargs='?', default="results", help="Directory for CSV outputs (Legacy)")
    args = parser.parse_args()
    
    run_pipeline(args.pcap_file, args.output_dir)
