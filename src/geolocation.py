"""
geolocation.py: Handles Geolocation lookups for IP addresses with caching.
"""

import os
import sqlite3
import ipaddress
import time
import sys
from typing import Optional, Dict, Any, Tuple
import geoip2.database
from dataclasses import dataclass

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

def _check_db_files():
    if not os.path.exists(CITY_DB_PATH):
        print(f"GeoLite2 database not found. \n"
              f"City DB: {CITY_DB_PATH} exists: False\n"
              f"Prerequisite: See Task 5's instructions to download mmdb files.")
        sys.exit(1)

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
        
        print("DEBUG: Before city reader", file=sys.stderr)
        with geoip2.database.Reader(CITY_DB_PATH) as city_reader:
            city_response = city_reader.city(ip)
            country = city_response.country.name or 'Unknown'
            city = city_response.city.name or 'Unknown'
            latitude = city_response.location.latitude or 0.0
            longitude = city_response.location.longitude or 0.0
        
        print("DEBUG: After city reader", file=sys.stderr)
        asn_db_path = os.environ.get("GEOLITE2_ASN_DB", ASN_DB_PATH)
        print(f"DEBUG: Using ASN DB path: {asn_db_path}, Exists: {os.path.exists(asn_db_path)}", file=sys.stderr)
        if os.path.exists(asn_db_path):
            try:
                with geoip2.database.Reader(asn_db_path) as asn_reader:
                    asn_response = asn_reader.asn(ip)
                    asn = str(asn_response.autonomous_system_number) or 'Unknown'
                    asn_org = asn_response.autonomous_system_organization or 'Unknown'
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
