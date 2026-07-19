from src.geo_mapping import get_row_caveat

def run_tests():
    print("TEST 1: Carrier-grade NAT (100.64.x.x)")
    src_ip = "100.64.1.1"
    dst_asn_org = "Facebook, Inc."
    caveat = get_row_caveat(src_ip, dst_asn_org)
    print(f"Caveat: {caveat}")
    assert "carrier-grade NAT" in caveat
    print("PASS\n")

    print("TEST 2: Private IP (10.x.x.x)")
    src_ip = "10.0.0.1"
    dst_asn_org = "Facebook, Inc."
    caveat = get_row_caveat(src_ip, dst_asn_org)
    print(f"Caveat: {caveat}")
    assert "private IP" in caveat
    print("PASS\n")
    
    print("TEST 3: VPN Exit Node (DigitalOcean)")
    src_ip = "8.8.8.8"
    dst_asn_org = "DigitalOcean, LLC"
    caveat = get_row_caveat(src_ip, dst_asn_org)
    print(f"Caveat: {caveat}")
    assert "possible VPN exit node" in caveat
    print("PASS\n")
    
    print("TEST 4: Combined CGNAT and VPN Exit Node")
    src_ip = "100.65.2.3"
    dst_asn_org = "Amazon.com Services LLC" # "amazon" is in VPN_KEYWORDS
    caveat = get_row_caveat(src_ip, dst_asn_org)
    print(f"Caveat: {caveat}")
    assert "carrier-grade NAT" in caveat
    assert "possible VPN exit node" in caveat
    print("PASS\n")

    print("TEST 5: Normal ISPs (No caveats)")
    src_ip = "8.8.8.8"
    dst_asn_org = "Comcast Cable Communications, LLC"
    caveat = get_row_caveat(src_ip, dst_asn_org)
    print(f"Caveat: '{caveat}'")
    assert caveat == ""
    print("PASS\n")

if __name__ == "__main__":
    run_tests()
    print("ALL TESTS PASSED")
