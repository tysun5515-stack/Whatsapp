"""
geolocation.py: Handles Geolocation lookups for IP addresses with caching.
"""

import os
import sqlite3
import ipaddress
import socket
import time
import sys
import threading
from typing import Optional, Dict, Any, Tuple
import geoip2.database
from dataclasses import dataclass

from src.whatsapp_filter import STRONG_DOMAINS, WEAK_DOMAINS

@dataclass
class GeoResult:
    country: str
    city: str
    latitude: float
    longitude: float
    asn: str
    asn_org: str

# Config via environment variable or default to project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CITY_DB_PATH = os.environ.get("GEOLITE2_CITY_DB", os.path.join(BASE_DIR, "GeoLite2-City.mmdb"))
ASN_DB_PATH = os.environ.get("GEOLITE2_ASN_DB", os.path.join(BASE_DIR, "GeoLite2-ASN.mmdb"))
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'whatsapp.db'))

# Timeout in seconds for reverse DNS lookups
RDNS_TIMEOUT = 2.0

def _check_db_files():
    if not os.path.exists(CITY_DB_PATH):
        print(f"GeoLite2 database not found. \n"
              f"City DB: {CITY_DB_PATH} exists: False\n"
              f"Prerequisite: See Task 5's instructions to download mmdb files.")
        sys.exit(1)

def reverse_dns(ip: str) -> Optional[str]:
    """
    Performs a reverse DNS lookup on the given IP address.
    
    Uses a background thread with a timeout to prevent hanging lookups
    from stalling the pipeline. Results (including None for failures)
    are cached in the geo_cache table's rdns_hostname column.
    
    Args:
        ip: The IP address to look up.
        
    Returns:
        The rDNS hostname if found, or None if the lookup fails/times out.
    """
    # 1. Skip private IPs — rDNS on private ranges is meaningless for our use case
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    # Sentinel value: distinguishes "rDNS attempted, no result" from
    # "rDNS never attempted" (SQL NULL left by geolocate()).
    _RDNS_NONE_SENTINEL = "__RDNS_NONE__"

    # 2. Check cache first
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT rdns_hostname FROM geo_cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row is not None and row['rdns_hostname'] is not None:
        # Cache hit — rDNS was previously attempted for this IP
        conn.close()
        stored = row['rdns_hostname']
        return None if stored == _RDNS_NONE_SENTINEL else stored
    conn.close()

    # 3. Perform threaded rDNS lookup with timeout
    result_holder = [None]

    def _do_lookup():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result_holder[0] = hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            result_holder[0] = None

    lookup_thread = threading.Thread(target=_do_lookup, daemon=True)
    lookup_thread.start()
    lookup_thread.join(timeout=RDNS_TIMEOUT)

    # If the thread is still alive after the timeout, treat as failure
    if lookup_thread.is_alive():
        print(f"rDNS lookup timed out for {ip} after {RDNS_TIMEOUT}s")
        hostname = None
    else:
        hostname = result_holder[0]

    # 4. Cache the result (upsert into geo_cache)
    # Store the sentinel for failed lookups so we don't re-attempt on future calls.
    store_value = hostname if hostname else _RDNS_NONE_SENTINEL
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # If the IP already has a geo_cache row (from geolocate()), update it;
    # otherwise insert a minimal row so future calls hit the cache.
    cursor.execute("SELECT ip FROM geo_cache WHERE ip = ?", (ip,))
    if cursor.fetchone():
        cursor.execute(
            "UPDATE geo_cache SET rdns_hostname = ? WHERE ip = ?",
            (store_value, ip)
        )
    else:
        cursor.execute(
            "INSERT INTO geo_cache (ip, rdns_hostname, looked_up_at) VALUES (?, ?, ?)",
            (ip, store_value, time.time())
        )
    conn.commit()
    conn.close()


    return hostname


def check_verified_whatsapp_domain(rdns_hostname: Optional[str]) -> bool:
    """
    Checks whether a reverse DNS hostname matches a known WhatsApp/Meta domain.
    
    Reuses the STRONG_DOMAINS and WEAK_DOMAINS sets from whatsapp_filter.py
    to avoid maintaining a third copy of the domain list.
    
    Args:
        rdns_hostname: The rDNS hostname to check, or None.
        
    Returns:
        True if the hostname ends with any known WhatsApp/Meta domain suffix.
    """
    if not rdns_hostname:
        return False

    all_known_domains = STRONG_DOMAINS | WEAK_DOMAINS
    return any(rdns_hostname.endswith(domain) for domain in all_known_domains)


def geolocate(ip: str) -> Optional[GeoResult]:
    # 1. Skip private IPs
    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None

    # 2. Check Cache
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return GeoResult(
            country=row['country'], city=row['city'], 
            latitude=row['latitude'], longitude=row['longitude'], 
            asn=row['asn'], asn_org=row['asn_org']
        )
    
    # 3. Perform Lookup
    _check_db_files()
    
    try:
        country = 'Unknown'
        city = 'Unknown'
        latitude = 0.0
        longitude = 0.0
        asn = 'Unknown'
        asn_org = 'Unknown'
        
        with geoip2.database.Reader(CITY_DB_PATH) as city_reader:
            city_response = city_reader.city(ip)
            country = city_response.country.name or 'Unknown'
            city = city_response.city.name or 'Unknown'
            latitude = city_response.location.latitude or 0.0
            longitude = city_response.location.longitude or 0.0
        
        asn_db_path = os.environ.get("GEOLITE2_ASN_DB", ASN_DB_PATH)
        if os.path.exists(asn_db_path):
            try:
                asn_reader = geoip2.database.Reader(asn_db_path)
                asn_response = asn_reader.asn(ip)
                asn = str(asn_response.autonomous_system_number)
                asn_org = asn_response.autonomous_system_organization
                asn_reader.close()
            except Exception as e:
                print(f"Optional ASN lookup failed for {ip}: {e}")
                
        result = GeoResult(
            country=country, city=city, 
            latitude=latitude, longitude=longitude, 
            asn=asn, asn_org=asn_org
        )
        
        # 4. Cache result
        cursor.execute("""
            INSERT INTO geo_cache 
            (ip, country, city, latitude, longitude, asn, asn_org, looked_up_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, result.country, result.city, result.latitude, 
              result.longitude, result.asn, result.asn_org, time.time()))
        conn.commit()
        conn.close()
        return result
            
    except Exception as e:
        print(f"Geolocation lookup failed for {ip}: {e}")
        conn.close()
        return None
