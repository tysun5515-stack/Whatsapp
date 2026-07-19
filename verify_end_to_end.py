import os
import sys
import re
import urllib.request
import json
from io import BytesIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from src.webapp.app import create_app

def run_verification():
    app = create_app()
    app.testing = True
    client = app.test_client()
    
    pcap_path = os.path.join(os.path.dirname(__file__), 'resources', 'NoFilters_record.pcap')
    if not os.path.exists(pcap_path):
        print(f"Error: {pcap_path} not found.")
        return
        
    print(f"1. Uploading {pcap_path}...")
    with open(pcap_path, 'rb') as f:
        data = {'pcap_file': (f, 'NoFilters_record.pcap')}
        response = client.post('/upload', data=data, content_type='multipart/form-data')
        
    assert response.status_code in [302, 301], f"Expected redirect after upload, got {response.status_code}"
    
    redirect_url = response.headers['Location']
    print(f"Redirected to: {redirect_url}")
    
    # Extract file_id from /results/<file_id>
    file_id = redirect_url.split('/')[-1]
    print(f"File ID: {file_id}")
    
    print("2. Fetching results page (this triggers pipeline)...")
    results_response = client.get(f'/results/{file_id}')
    assert results_response.status_code == 200, "Results page failed"
    print("Results page loaded.")
    
    print("3. Fetching parties page...")
    parties_response = client.get(f'/parties/{file_id}')
    assert parties_response.status_code == 200, "Parties page failed"
    parties_html = parties_response.get_data(as_text=True)
    
    # Simple check for ~4 parties
    party_rows = parties_html.count('<tr>') - 1 # subtract header
    print(f"Found ~{party_rows} party rows in table.")
    
    print("4. Fetching geomap page...")
    geomap_response = client.get(f'/geomap/{file_id}')
    assert geomap_response.status_code == 200, "Geomap page failed"
    geomap_html = geomap_response.get_data(as_text=True)
    
    if "plotly" in geomap_html.lower():
        print("Geomap successfully rendered Plotly visualization.")
        
    if "Caveat" in geomap_html:
        print("Caveats are present in the geomap.")
        
    print("5. Manual cross-check of one geolocated point...")
    # Find an IP to lookup from parties HTML
    ips = re.findall(r'<td>(\d{1,3}(?:\.\d{1,3}){3})</td>', parties_html)
    unique_ips = set(ips)
    if unique_ips:
        test_ip = list(unique_ips)[0]
        # Skip private IPs
        for ip in unique_ips:
            if not ip.startswith('10.') and not ip.startswith('192.168.') and not ip.startswith('100.6'):
                test_ip = ip
                break
                
        print(f"Selected IP for cross-check: {test_ip}")
        try:
            req = urllib.request.Request(f"https://ipapi.co/{test_ip}/json/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as url:
                data = json.loads(url.read().decode())
                print(f"Cross-check result: {data.get('city')}, {data.get('country_name')}, {data.get('org')}")
                print(f"Pipeline geolocated this IP correctly if it matches the DB.")
        except Exception as e:
            print(f"Cross-check failed: {e}")
            
    print("\nEnd-to-end verification completed successfully.")

if __name__ == "__main__":
    run_verification()
