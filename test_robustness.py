import sys
import os

# Add src to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from pcap_reader import read_packets
from packet_parser import parse_packet
from flow_builder import rebuild_flows
from whatsapp_filter import check_domain_matching, check_cidr_matching, check_inference_matching, seed_confirmed_servers

def classify_flows(packet_records, pcap_id):
    # This rebuild_flows returns summary records, not the active flow state with 'packets'
    # I need to modify it or access the flow object differently.
    # Let's modify rebuild_flows or create a version that returns flow objects with packets.
    pass
    
def classify_flows_with_packets(packet_records, pcap_id):
    # Need to reimplement logic to get flow with packets
    # 1. Grouping logic (same as rebuild_flows)
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
            if packet["timestamp"] - last_pkt["timestamp"] > 1.0:
                completed_flows.append(flow)
                active_flows[key] = {'key': key, 'client_ip': packet["src_ip"], 'client_port': packet["src_port"], 'server_ip': packet["dst_ip"], 'server_port': packet["dst_port"], 'protocol_type': packet["protocol"], 'start_time': packet["timestamp"], 'packets': [packet]}
            else:
                flow["packets"].append(packet)
        else:
            active_flows[key] = {'key': key, 'client_ip': packet["src_ip"], 'client_port': packet["src_port"], 'server_ip': packet["dst_ip"], 'server_port': packet["dst_port"], 'protocol_type': packet["protocol"], 'start_time': packet["timestamp"], 'packets': [packet]}
    completed_flows.extend(active_flows.values())
    
    # 2. Add classification
    for flow in completed_flows:
        # Determine signals
        sni = None
        dns = None
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
        flow["whatsapp_signals"] = signals
    return completed_flows

def run_robustness_test():
    pcap_path = "resources/NoFilters_record.pcap"
    
    # 1. Parse everything
    all_packets = []
    packet_no = 0
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        all_packets.append(parse_packet(packet_no, ts, link, data))
        
    # 2. Filter packets to create "mid-stream" dataset (remove packets 47-50, 61)
    evidence_nos = {47, 48, 49, 50, 61}
    filtered_packets = [p for p in all_packets if p["packet_no"] not in evidence_nos]
    
    print(f"Original packets: {len(all_packets)}")
    print(f"Filtered packets: {len(filtered_packets)}")
    
    # 3. Classify both
    print("Classifying original...")
    flows_orig = classify_flows_with_packets(all_packets, "orig")
    
    print("Classifying filtered...")
    # Reset inference
    from whatsapp_filter import CONFIRMED_WHATSAPP_SERVERS
    CONFIRMED_WHATSAPP_SERVERS.clear()
    flows_filt = classify_flows_with_packets(filtered_packets, "filt")
    
    # 4. Analyze results
    print("\nRobustness Check Results:")
    for f_orig in flows_orig:
        # Find corresponding flow in filtered
        for f_filt in flows_filt:
            if f_orig["server_ip"] == f_filt["server_ip"] and f_orig["server_port"] == f_filt["server_port"]:
                print(f"Server {f_orig['server_ip']}:{f_orig['server_port']} | "
                      f"Orig Conf: {f_orig['whatsapp_confidence']} ({f_orig['whatsapp_signals']}) | "
                      f"Filt Conf: {f_filt['whatsapp_confidence']} ({f_filt['whatsapp_signals']})")

if __name__ == "__main__":
    run_robustness_test()
