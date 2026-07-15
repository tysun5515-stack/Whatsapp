"""
flow_builder.py: Reconstructs network flows from packet records and calculates flow summary statistics.
"""

import math
from typing import List, Dict, Any, Tuple

def create_new_flow(packet: Dict[str, Any], key: Tuple) -> Dict[str, Any]:
    """
    Helper function to initialize a new active flow dictionary.
    """
    return {
        "key": key,
        "client_ip": packet["src_ip"],
        "client_port": packet["src_port"],
        "server_ip": packet["dst_ip"],
        "server_port": packet["dst_port"],
        "protocol_type": packet["protocol"],
        "start_time": packet["timestamp"],
        "packets": [packet]
    }

def rebuild_flows(
    packet_records: List[Dict[str, Any]], 
    pcap_id: str, 
    inactivity_timeout: float = 120.0, 
    burst_threshold: float = 1.0
) -> List[Dict[str, Any]]:
    """
    Groups packet records into flows and computes statistics.
    Returns the full flow dictionaries including 'packets'.
    """
    # 1. Filter out non-IP packets (must have src_ip and dst_ip)
    ip_packets = [p for p in packet_records if p["src_ip"] is not None and p["dst_ip"] is not None]
    
    # 2. Sort packets chronologically by timestamp
    ip_packets.sort(key=lambda x: x["timestamp"])
    
    active_flows: Dict[Tuple, Dict[str, Any]] = {}
    completed_flows: List[Dict[str, Any]] = []
    
    for packet in ip_packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        protocol = packet["protocol"]
        
        # Normalize direction-agnostic 5-tuple
        if (src_ip, src_port) < (dst_ip, dst_port):
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            key = (dst_ip, dst_port, src_ip, src_port, protocol)
            
        if key in active_flows:
            flow = active_flows[key]
            last_pkt = flow["packets"][-1]
            gap = packet["timestamp"] - last_pkt["timestamp"]
            
            if gap > inactivity_timeout:
                # Close the active flow and add to completed list
                completed_flows.append(flow)
                # Open a new flow on the same key
                new_flow = create_new_flow(packet, key)
                active_flows[key] = new_flow
            else:
                flow["packets"].append(packet)
        else:
            new_flow = create_new_flow(packet, key)
            active_flows[key] = new_flow
            
    # Add any remaining active flows to completed
    completed_flows.extend(active_flows.values())
    
    # Sort completed flows by start_time
    completed_flows.sort(key=lambda x: x["start_time"])
    
    # 3. Compute detailed statistics (adding fields to 'flow' dict)
    for idx, flow in enumerate(completed_flows, start=1):
        # Back-fill each packet's direction based on flow's client
        client_ip = flow["client_ip"]
        client_port = flow["client_port"]
        
        for packet in flow["packets"]:
            if packet["src_ip"] == client_ip and packet["src_port"] == client_port:
                packet["direction"] = "upload"
            else:
                packet["direction"] = "download"
                
        packets = flow["packets"]
        packet_count = len(packets)
        
        # End time and duration
        start_time = flow["start_time"]
        end_time = packets[-1]["timestamp"]
        duration = end_time - start_time
        
        # Directions and Bytes
        upload_packets = [p for p in packets if p["direction"] == "upload"]
        download_packets = [p for p in packets if p["direction"] == "download"]
        
        # Sizes
        lengths = [p["length"] for p in packets]
        
        # Update flow object in-place
        flow.update({
            "flow_id": idx,
            "pcap_id": pcap_id,
            "end_time": end_time,
            "duration": duration,
            "packet_count": packet_count,
            "upload_packet_count": len(upload_packets),
            "download_packet_count": len(download_packets),
            "upload_bytes": sum(p["length"] for p in upload_packets),
            "download_bytes": sum(p["length"] for p in download_packets),
            "average_packet_size": sum(lengths) / packet_count if packet_count > 0 else 0.0,
            "maximum_packet_size": max(lengths) if packet_count > 0 else 0,
            "minimum_packet_size": min(lengths) if packet_count > 0 else 0
        })
        
        # Inter-arrival Times (IAT)
        iats = [packets[i]["timestamp"] - packets[i-1]["timestamp"] for i in range(1, packet_count)]
        flow["inter_arrival_mean"] = sum(iats) / len(iats) if len(iats) > 0 else 0.0
        
        if len(iats) < 2:
            flow["inter_arrival_std"] = 0.0
        else:
            mean_iat = flow["inter_arrival_mean"]
            variance = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
            flow["inter_arrival_std"] = math.sqrt(variance)
            
        # Burst Count
        burst_count = 0
        in_burst = False
        for gap in iats:
            if gap < burst_threshold:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
            else:
                in_burst = False
        flow["burst_count"] = burst_count
        
    return completed_flows
