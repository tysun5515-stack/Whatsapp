import sys
import os
import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from src.geolocation import geolocate
from src.geo_plot import generate_map_html

def test_map():
    # Connect to db
    db_path = os.path.join(os.path.dirname(__file__), 'whatsapp.db')
    if not os.path.exists(db_path):
        print("whatsapp.db not found, skip test.")
        return
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT src_ip, dst_ip, party_type FROM parties LIMIT 50")
    parties_rows = cursor.fetchall()
    conn.close()
    
    if not parties_rows:
        print("No parties found in DB.")
        return
        
    parties_data = []
    for row in parties_rows:
        party = dict(row)
        src_geo = geolocate(party['src_ip'])
        dst_geo = geolocate(party['dst_ip'])
        
        party['src_lat'] = src_geo.latitude if src_geo else None
        party['src_lon'] = src_geo.longitude if src_geo else None
        party['dst_lat'] = dst_geo.latitude if dst_geo else None
        party['dst_lon'] = dst_geo.longitude if dst_geo else None
        
        parties_data.append(party)
        
    print(f"Geolocated {len(parties_data)} parties.")
    map_html = generate_map_html(parties_data)
    
    if map_html and isinstance(map_html, str) and len(map_html) > 1000:
        print("Map HTML generated successfully!")
    else:
        print("Map HTML generation failed or returned invalid string.")

if __name__ == "__main__":
    test_map()
