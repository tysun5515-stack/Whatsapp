"""
geo_mapping.py: Annotates limitations and caveats for geospatial data mapping.
"""

import ipaddress
from typing import Optional

VPN_KEYWORDS = [
    'hosting', 'vpn', 'cloud', 'aws', 'amazon', 'google cloud', 
    'digitalocean', 'linode', 'hetzner', 'ovh', 'choopa', 'vultr', 
    'mullvad', 'expressvpn'
]

def get_row_caveat(src_ip: str, dst_asn_org: Optional[str]) -> str:
    """
    Evaluates known limitations for a given party connection row and returns
    a formatted caveat string if applicable.
    
    1. Checks if the destination ASN org looks like a hosting/VPN provider.
    2. Checks if the source IP is private or within CGNAT range.
    """
    caveats = []
    
    # 1. Check Source IP for CGNAT or Private range
    try:
        ip_obj = ipaddress.ip_address(src_ip)
        if ip_obj.is_private:
            caveats.append("private IP range - location is local network, not necessarily real geographic origin")
        elif ipaddress.ip_network('100.64.0.0/10').overlaps(ipaddress.ip_network(src_ip)):
            caveats.append("carrier-grade NAT - source location is the operator gateway, not necessarily the device")
    except ValueError:
        pass
        
    # 2. Check destination ASN org for VPN/hosting providers
    if dst_asn_org:
        org_lower = dst_asn_org.lower()
        if any(keyword in org_lower for keyword in VPN_KEYWORDS):
            caveats.append("possible VPN exit node - location may not reflect the real endpoint")
            
    if caveats:
        return "; ".join(caveats)
    return ""

