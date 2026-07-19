"""
verify_reverse_dns.py: Verification script for Task 6 — Reverse DNS lookup.

Tests:
1. reverse_dns() on a known Meta/WhatsApp server IP from the capture DB.
2. reverse_dns() on a private IP (should return None immediately).
3. reverse_dns() on a bogus/unreachable IP (should return None, not hang).
4. check_verified_whatsapp_domain() flags matches correctly.
5. Cache hit on re-call (confirms caching works).
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from src.db import init_db
from src.geolocation import reverse_dns, check_verified_whatsapp_domain

# Ensure the DB schema is up to date (adds rdns_hostname column if missing)
init_db()

def test_known_meta_ip():
    """Test rDNS on 157.240.214.60 - a known Meta/Facebook IP from the capture."""
    ip = "157.240.214.60"
    print(f"\n{'='*60}")
    print(f"TEST 1: reverse_dns('{ip}') - known Meta server IP")
    print(f"{'='*60}")
    
    start = time.time()
    hostname = reverse_dns(ip)
    elapsed = time.time() - start
    
    print(f"  Hostname : {hostname}")
    print(f"  Time     : {elapsed:.3f}s")
    
    if hostname:
        verified = check_verified_whatsapp_domain(hostname)
        print(f"  Verified WhatsApp/Meta domain: {verified}")
        if verified:
            print(f"  [OK] PASS - rDNS resolved to a WhatsApp/Meta domain")
        else:
            print(f"  [WARN] PASS - rDNS resolved but hostname '{hostname}' is not a known WA/Meta suffix")
    else:
        print(f"  [WARN] PASS - No PTR record exists (common). Returned None cleanly, no hang.")
    
    assert elapsed < 5.0, f"FAIL: Lookup took {elapsed:.1f}s - timeout should have kicked in"
    print(f"  [OK] Timing OK (completed in under 5s)")


def test_private_ip():
    """Private IPs should be short-circuited to None without any network call."""
    ip = "10.0.2.15"
    print(f"\n{'='*60}")
    print(f"TEST 2: reverse_dns('{ip}') - private IP")
    print(f"{'='*60}")
    
    start = time.time()
    hostname = reverse_dns(ip)
    elapsed = time.time() - start
    
    print(f"  Hostname : {hostname}")
    print(f"  Time     : {elapsed:.3f}s")
    
    assert hostname is None, f"FAIL: Expected None for private IP, got '{hostname}'"
    assert elapsed < 0.1, f"FAIL: Private IP check took {elapsed:.1f}s - should be instant"
    print(f"  [OK] PASS - returned None instantly")


def test_unreachable_ip():
    """A reserved/documentation IP should timeout or fail gracefully, not hang."""
    ip = "192.0.2.1"  # TEST-NET-1 - guaranteed non-routable
    print(f"\n{'='*60}")
    print(f"TEST 3: reverse_dns('{ip}') - unreachable/documentation IP")
    print(f"{'='*60}")
    
    start = time.time()
    hostname = reverse_dns(ip)
    elapsed = time.time() - start
    
    print(f"  Hostname : {hostname}")
    print(f"  Time     : {elapsed:.3f}s")
    
    assert hostname is None, f"FAIL: Expected None for unreachable IP, got '{hostname}'"
    assert elapsed < 5.0, f"FAIL: Took {elapsed:.1f}s - should timeout within RDNS_TIMEOUT"
    print(f"  [OK] PASS - returned None within timeout window")


def test_verified_domain_flag():
    """Directly test check_verified_whatsapp_domain with known strings."""
    print(f"\n{'='*60}")
    print(f"TEST 4: check_verified_whatsapp_domain() - domain flag logic")
    print(f"{'='*60}")
    
    cases = [
        ("edge-mqtt-mini-shv-01-bom1.whatsapp.net", True),
        ("media-bom1-1.whatsapp.net",                True),
        ("some-server.fbcdn.net",                    True),
        ("edge.facebook.com",                        True),
        ("cdn.cdninstagram.com",                     True),
        ("unrelated.example.com",                    False),
        ("google.com",                               False),
        (None,                                       False),
        ("",                                         False),
    ]
    
    all_passed = True
    for hostname, expected in cases:
        result = check_verified_whatsapp_domain(hostname)
        status = "[OK]" if result == expected else "[FAIL]"
        if result != expected:
            all_passed = False
        print(f"  {status}  check_verified_whatsapp_domain({hostname!r:50s}) -> {result} (expected {expected})")
    
    assert all_passed, "Some domain flag checks failed"
    print(f"  [OK] All domain flag tests passed")


def test_cache_hit():
    """Second call for the same IP should be a cache hit (much faster)."""
    ip = "157.240.214.60"
    print(f"\n{'='*60}")
    print(f"TEST 5: Cache hit on second call for '{ip}'")
    print(f"{'='*60}")
    
    # First call already happened in test_known_meta_ip, so this is the cached path
    start = time.time()
    hostname = reverse_dns(ip)
    elapsed = time.time() - start
    
    print(f"  Hostname : {hostname}")
    print(f"  Time     : {elapsed:.3f}s")
    
    # Cache reads from SQLite should be well under 100ms
    assert elapsed < 0.5, f"FAIL: Cache hit took {elapsed:.1f}s - expected near-instant"
    print(f"  [OK] PASS - cache hit returned in {elapsed:.3f}s")


def test_second_capture_ip():
    """Test rDNS on 213.57.22.5 - the other server IP from the capture."""
    ip = "213.57.22.5"
    print(f"\n{'='*60}")
    print(f"TEST 6: reverse_dns('{ip}') - second server IP from capture")
    print(f"{'='*60}")
    
    start = time.time()
    hostname = reverse_dns(ip)
    elapsed = time.time() - start
    
    print(f"  Hostname : {hostname}")
    print(f"  Time     : {elapsed:.3f}s")
    
    if hostname:
        verified = check_verified_whatsapp_domain(hostname)
        print(f"  Verified WhatsApp/Meta domain: {verified}")
    else:
        print(f"  [WARN] No PTR record (normal). Returned None cleanly.")
    
    assert elapsed < 5.0, f"FAIL: Lookup took {elapsed:.1f}s"
    print(f"  [OK] PASS - completed within timeout")


if __name__ == "__main__":
    print("=" * 60)
    print("TASK 6 VERIFICATION: Reverse DNS Lookup")
    print("=" * 60)
    
    test_known_meta_ip()
    test_private_ip()
    test_unreachable_ip()
    test_verified_domain_flag()
    test_cache_hit()
    test_second_capture_ip()
    
    print(f"\n{'='*60}")
    print("ALL TESTS PASSED [OK]")
    print(f"{'='*60}")
