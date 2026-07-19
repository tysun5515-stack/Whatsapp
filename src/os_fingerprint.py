"""
os_fingerprint.py — Passive OS detection from unencrypted packet headers.
No decryption required. Uses TTL, inter-packet gap, and TCP window heuristics.
"""
from collections import Counter
from typing import List, Dict, Any

OS_TIMEOUTS = {
    'ios':     180,    # 3 minutes — aggressive iOS keepalive termination
    'android': 600,    # 10 minutes — conservative Android step
    'windows': 600,    # 10 minutes
    'unknown': 300,    # 5 minutes — safe default
}

# Known iOS TTL = 64, Android TTL = 64, Windows TTL = 128
# (Both iOS and Android start at 64 so TTL alone only eliminates Windows)
_WINDOWS_TTL = 128
_UNIX_TTL    = 64

# iOS inactivity timeout: ~180s (+/- 30s tolerance)
_IOS_GAP_LOW, _IOS_GAP_HIGH         = 150, 210
# Android inactivity timeouts: 10min, 15min, 24min
_ANDROID_GAPS = [(550, 650), (850, 950), (1380, 1500)]

# TCP initial window sizes (common heuristics)
_WINDOWS_TCP_WIN = 8192      # Windows default
_ANDROID_TCP_WIN = 65535     # Android / Linux default
_IOS_TCP_WIN     = 65535     # iOS also uses 65535 but with window scaling


def fingerprint_os(packet_records: List[Dict[str, Any]]) -> str:
    """
    Passively fingerprints the device OS from packet metadata.
    Priority: gap analysis > TTL > window size.
    Returns: 'ios', 'android', 'windows', or 'unknown'
    """
    if not packet_records:
        return 'unknown'

    # --- Method 1: IP TTL (fastest) ---
    ttls = [p.get('ip_ttl') for p in packet_records if p.get('ip_ttl')]
    dominant_ttl = None
    if ttls:
        dominant_ttl = Counter(ttls).most_common(1)[0][0]
        if dominant_ttl == _WINDOWS_TTL:
            return 'windows'
        # TTL=64 → Linux/Android/iOS → continue to next method

    # --- Method 2: Inactivity gap analysis (most reliable for WhatsApp) ---
    timestamps = sorted(
        p['timestamp'] for p in packet_records if p.get('timestamp') is not None
    )
    if len(timestamps) > 1:
        gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        max_gap = max(gaps)

        if _IOS_GAP_LOW <= max_gap <= _IOS_GAP_HIGH:
            return 'ios'

        for (lo, hi) in _ANDROID_GAPS:
            if lo <= max_gap <= hi:
                return 'android'

    # --- Method 3: TCP window size heuristic ---
    tcp_windows = [p.get('tcp_window_size') for p in packet_records if p.get('tcp_window_size')]
    if tcp_windows:
        dominant_win = Counter(tcp_windows).most_common(1)[0][0]
        if dominant_win == _WINDOWS_TCP_WIN:
            return 'windows'
        # Both iOS and Android use 65535 — cannot distinguish without scaling factor
        # Fall through to TTL tie-break
        if dominant_ttl == _UNIX_TTL:
            # Lean Android as more common in WhatsApp captures
            return 'android'

    return 'unknown'


def os_inactivity_timeout(packet_records: List[Dict[str, Any]]) -> float:
    """Returns the appropriate inactivity timeout (seconds) for detected OS."""
    detected = fingerprint_os(packet_records)
    return float(OS_TIMEOUTS[detected])
