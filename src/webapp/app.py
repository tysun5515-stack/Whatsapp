import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import sys

# Ensure src is in the path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(BASE_DIR)

from src.webapp.db_registry import (
    init_registry_db, register_upload, get_upload, list_uploads, update_status
)
from src.webapp.db_analysis import (
    init_analysis_db, insert_whatsapp_packets, insert_parties, 
    get_packets, get_parties, get_geo, upsert_geo
)
from src.pipeline import process_pcap_to_whatsapp_packets
from src.party_grouper import group_into_entities
from src.geolocation import geolocate, reverse_dns
from src.geo_plot import generate_map_html
from src.geo_mapping import get_row_caveat
from src.party_chart import generate_party_charts # Note: We will replace generate_party_charts logic for HTML or adapt it


def create_app():
    app = Flask(__name__)
    
    # Init databases
    init_registry_db()
    init_analysis_db()
    
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 # 100MB
    
    # ---------------------------------------------------------
    # Context Processor for Sidebar Data
    # ---------------------------------------------------------
    @app.context_processor
    def inject_sidebar():
        upload_id = request.args.get('upload_id')
        active_upload = get_upload(upload_id) if upload_id else None
        
        return dict(
            all_uploads=list_uploads(),
            active_upload_id=upload_id,
            active_upload=active_upload,
        )

    # ---------------------------------------------------------
    # UI Routes
    # ---------------------------------------------------------
    @app.route('/')
    def index():
        return redirect(url_for('interface1', **request.args))

    @app.route('/interface/1')
    def interface1():
        upload_id = request.args.get('upload_id')
        receipt = get_upload(upload_id) if upload_id else None
        error = request.args.get('error')
        return render_template('interface1.html', 
                               active_interface=1, 
                               receipt=receipt,
                               error=error)

    @app.route('/interface/2')
    def interface2():
        upload_id = request.args.get('upload_id')
        upload = get_upload(upload_id) if upload_id else None
        
        # If already filtered, load stats and sample packets
        filter_stats = None
        packets = []
        if upload and upload['status'] in ['filtered', 'analyzed']:
            packets = get_packets(upload_id)
            if packets:
                filter_stats = {
                    'packet_count': '?', # don't have original counts easily without saving them
                    'flow_count': '?',
                    'whatsapp_count': len(packets),
                    'detected_os': packets[0].get('os_hint', 'unknown') if packets else 'unknown'
                }
                
        return render_template('interface2.html',
                               active_interface=2,
                               upload=upload,
                               filter_stats=filter_stats,
                               packets=packets)

    @app.route('/interface/3')
    def interface3():
        upload_id = request.args.get('upload_id')
        upload = get_upload(upload_id) if upload_id else None
        
        parties = []
        map_html = ""
        bar_html = ""
        caveated_count = 0
        
        if upload and upload['status'] == 'analyzed':
            parties_data = get_parties(upload_id)
            for p in parties_data:
                # Add geo data for map
                geo = get_geo(p['remote_ip'])
                if geo:
                    p['remote_lat'] = geo.get('latitude')
                    p['remote_lon'] = geo.get('longitude')
                    p['geo_country'] = geo.get('country')
                    p['geo_city'] = geo.get('city')
                    p['asn_org'] = geo.get('asn_org')
                    p['rdns'] = geo.get('rdns_hostname')
                
                # Geolocate public_local_ip if available
                if p.get('public_local_ip'):
                    loc_ip = p['public_local_ip']
                    loc_geo = get_geo(loc_ip)
                    if not loc_geo:
                        loc_geo_new = geolocate(loc_ip)
                        if loc_geo_new:
                            upsert_geo(loc_ip, {
                                'country': loc_geo_new.country,
                                'city': loc_geo_new.city,
                                'latitude': loc_geo_new.latitude,
                                'longitude': loc_geo_new.longitude,
                                'asn': loc_geo_new.asn,
                                'asn_org': loc_geo_new.asn_org,
                                'rdns_hostname': '__RDNS_NONE__'
                            })
                            loc_geo = get_geo(loc_ip)
                    
                    if loc_geo:
                        p['local_lat'] = loc_geo.get('latitude')
                        p['local_lon'] = loc_geo.get('longitude')
                        p['local_geo_country'] = loc_geo.get('country')
                        p['local_geo_city'] = loc_geo.get('city')
                
                p['caveat'] = get_row_caveat(p.get('local_ips', ''), p.get('asn_org'))
                if p['caveat']:
                    caveated_count += 1
                    
            parties = parties_data
            map_html = generate_map_html(parties)
            
            # Simple bar chart HTML (using plotly)
            import plotly.graph_objects as go
            labels = [p['remote_ip'] for p in parties]
            counts = [p['packet_count'] for p in parties]
            colors = ['#4fc3f7' if p['party_type'] == 'client_to_server' else 
                      '#66bb6a' if p['party_type'] == 'peer_to_peer' else '#999999' 
                      for p in parties]
            
            fig = go.Figure(go.Bar(
                x=labels, y=counts, 
                marker_color=colors,
                text=counts, textposition='auto'
            ))
            fig.update_layout(
                paper_bgcolor='#2a2a2a',
                plot_bgcolor='#2a2a2a',
                font=dict(color='#e0e0e0'),
                margin=dict(l=10, r=10, t=10, b=10),
                height=250,
                xaxis=dict(showgrid=False),
                yaxis=dict(showgrid=True, gridcolor='#444444')
            )
            bar_html = fig.to_html(full_html=False, include_plotlyjs='cdn')
            
        return render_template('interface3.html',
                               active_interface=3,
                               upload=upload,
                               parties=parties,
                               map_html=map_html,
                               bar_html=bar_html,
                               caveated_count=caveated_count)

    # ---------------------------------------------------------
    # API Routes
    # ---------------------------------------------------------
    @app.route('/api/uploads', methods=['GET'])
    def api_uploads():
        return jsonify(list_uploads())

    @app.route('/api/register', methods=['POST'])
    def api_register():
        if 'pcap_file' not in request.files:
            return redirect(url_for('interface1', error='No file part'))
        file = request.files['pcap_file']
        if file.filename == '':
            return redirect(url_for('interface1', error='No selected file'))
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        receipt = register_upload(filename, filepath)
        
        return redirect(url_for('interface1', upload_id=receipt['upload_id']))

    @app.route('/api/filter/<upload_id>', methods=['POST'])
    def api_filter(upload_id):
        upload = get_upload(upload_id)
        if not upload:
            return jsonify({'error': 'Upload not found'}), 404
            
        try:
            stats, packets, _ = process_pcap_to_whatsapp_packets(upload['stored_path'])
            insert_whatsapp_packets(upload_id, packets)
            update_status(upload_id, 'filtered')
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analyze/<upload_id>', methods=['POST'])
    def api_analyze(upload_id):
        upload = get_upload(upload_id)
        if not upload:
            return jsonify({'error': 'Upload not found'}), 404
            
        try:
            packets = get_packets(upload_id)
            
            # The OS hint was added to packets during filter
            os_hint = 'unknown'
            if packets and 'os_hint' in packets[0]:
                os_hint = packets[0]['os_hint']
                
            parties = group_into_entities(packets, upload_id, os_hint)
            
            # Geolocate and reverse DNS each unique remote IP
            for p in parties:
                ip = p['remote_ip']
                cached = get_geo(ip)
                if not cached:
                    geo_data = geolocate(ip)
                    rdns = reverse_dns(ip)
                    
                    if geo_data:
                        upsert_geo(ip, {
                            'country': geo_data.country,
                            'city': geo_data.city,
                            'latitude': geo_data.latitude,
                            'longitude': geo_data.longitude,
                            'asn': geo_data.asn,
                            'asn_org': geo_data.asn_org,
                            'looked_up_at': 0, # not used currently
                            'rdns_hostname': rdns or '__RDNS_NONE__'
                        })
                    else:
                        upsert_geo(ip, {
                            'rdns_hostname': rdns or '__RDNS_NONE__'
                        })
                        
            insert_parties(upload_id, parties)
            update_status(upload_id, 'analyzed')
            return jsonify({'status': 'success', 'parties': len(parties)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000)
