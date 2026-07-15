import os
import sys
import itertools
from collections import defaultdict

# Add root to the path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.whatsapp_filter import check_domain_matching, check_cidr_matching, check_inference_matching, seed_confirmed_servers, guess_media_type

def process_file(pcap_path, inactivity_timeout, burst_threshold):
    # 1. Parse
    packet_records = []
    packet_no = 0
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        packet_records.append(parse_packet(packet_no, ts, link, data))
        
    # 2. Re-implement reconstruction to maintain flow packets
    ip_packets = [p for p in packet_records if p["src_ip"] is not None and p["dst_ip"] is not None]
    ip_packets.sort(key=lambda x: x["timestamp"])
    active_flows = {}
    completed_flows = []
    
    for packet in ip_packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        protocol = packet["protocol"]
        if (src_ip, src_port) < (dst_ip, dst_port):
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            key = (dst_ip, dst_port, src_ip, src_port, protocol)
        if key in active_flows:
            flow = active_flows[key]
            last_pkt = flow["packets"][-1]
            if packet["timestamp"] - last_pkt["timestamp"] > inactivity_timeout:
                completed_flows.append(flow)
                active_flows[key] = {'key': key, 'server_ip': packet["dst_ip"], 'packets': [packet], 'packet_count': 1, 'upload_bytes': 0, 'download_bytes': 0, 'protocol_type': packet["protocol"]}
            else:
                flow["packets"].append(packet)
                flow["packet_count"] += 1
        else:
            active_flows[key] = {'key': key, 'server_ip': packet["dst_ip"], 'packets': [packet], 'packet_count': 1, 'upload_bytes': 0, 'download_bytes': 0, 'protocol_type': packet["protocol"]}
    completed_flows.extend(active_flows.values())

    # 3. Classify
    from src.whatsapp_filter import CONFIRMED_WHATSAPP_SERVERS
    CONFIRMED_WHATSAPP_SERVERS.clear()
    
    classified_flows = []
    for flow in completed_flows:
        sni, dns = None, None
        for p in flow["packets"]:
            if p["sni"]: sni = p["sni"]
            if p["dns_query"]: dns = p["dns_query"]
            
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
        
        # Simple media type
        flow["media_type"] = guess_media_type(flow["packet_count"], 0, 0, flow["protocol_type"], False)
        classified_flows.append(flow)
        
    return classified_flows

def validate():
    resources_dir = "resources"
    # Filter PCAP files to only include the labeled ones
    pcap_files = [f for f in os.listdir(resources_dir) if f.endswith(".pcap") and "NoFilters" not in f and "YesFilters" not in f]
    
    param_grid = list(itertools.product([30, 60, 120, 300], [0.3, 1.0, 2.0]))
    best_params = None
    best_f1 = -1
    
    for inactivity, burst in param_grid:
        true_pos = 0
        false_pos = 0
        false_neg = 0
        
        for pcap_file in pcap_files:
            pcap_path = os.path.join(resources_dir, pcap_file)
            # The file name is something like 'Audios_record.pcap'
            label = pcap_file.split('_')[0].lower() # 'audios'
            
            flows = process_file(pcap_path, inactivity, burst)
            
            for flow in flows:
                is_whatsapp = flow["whatsapp_confidence"] in ["high", "medium"]
                
                # Check against ground truth
                if label in ["audios", "messages", "photos", "videos"]:
                    if is_whatsapp: true_pos += 1
                    else: false_neg += 1
                else:
                    if is_whatsapp: false_pos += 1
        
        precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0
        recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        if f1 > best_f1:
            best_f1 = f1
            best_params = (inactivity, burst)
            
    print(f"Best Parameters: Inactivity Timeout={best_params[0]}s, Burst Threshold={best_params[1]}s")
    print(f"Best F1: {best_f1:.4f}")

if __name__ == "__main__":
    validate()
