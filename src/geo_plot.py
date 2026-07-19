"""
geo_plot.py: Generates an interactive world map visualization of WhatsApp traffic using Plotly.
"""

import plotly.graph_objects as go
from typing import List, Dict, Any
import collections

def generate_map_html(parties_data: List[Dict[str, Any]]) -> str:
    """
    Generates an interactive map using Plotly, plotting unique IPs and directed lines
    between communicating parties, colored by party_type.
    """
    fig = go.Figure()
    
    unique_points = {} # (lon, lat) -> dict of info
    
    color_map = {
        'client_to_server': '#4fc3f7',
        'peer_to_peer': '#66bb6a',  # Direct P2P
        'p2p_relay': '#ab47bc',     # Relayed call
        'unknown': '#999999'
    }
    
    lines_by_type = collections.defaultdict(lambda: {'lons': [], 'lats': []})
    
    for party in parties_data:
        # We need remote coordinates
        rem_lat = party.get('remote_lat')
        rem_lon = party.get('remote_lon')
        
        loc_lat = party.get('local_lat')
        loc_lon = party.get('local_lon')
        
        if rem_lat is None or rem_lon is None:
            continue
            
        party_type = party.get('party_type', 'unknown')
        is_p2p = party.get('is_p2p')
        if party_type == 'peer_to_peer' and is_p2p is False:
            party_type = 'p2p_relay'
            
        sub_activity = party.get('sub_activity') or 'unknown'
        caveat = party.get('caveat', '')
        
        rem_key = (rem_lon, rem_lat)
        if rem_key not in unique_points:
            unique_points[rem_key] = {
                'ips': set(),
                'city': party.get('geo_city') or '',
                'country': party.get('geo_country') or '',
                'asn': party.get('asn_org') or '',
                'rdns': party.get('rdns') or '',
                'activities': set(),
                'types': set(),
                'caveats': set(),
                'is_caveated': False
            }
            
        pt = unique_points[rem_key]
        pt['ips'].add(party['remote_ip'])
        pt['activities'].add(sub_activity)
        pt['types'].add(party_type)
        if caveat:
            pt['caveats'].add(caveat)
            pt['is_caveated'] = True
            
        # Draw lines if we have local coords (e.g. from a public IP or if we geolocated the private IP to a generic center)
        # Often local is RFC1918, so local_lat/lon might be None
        if loc_lat is not None and loc_lon is not None:
            lines_by_type[party_type]['lons'].extend([loc_lon, rem_lon, None])
            lines_by_type[party_type]['lats'].extend([loc_lat, rem_lat, None])
            
            loc_key = (loc_lon, loc_lat)
            if loc_key not in unique_points:
                unique_points[loc_key] = {
                    'ips': set(party.get('local_ips', '').split(',')),
                    'city': 'Local',
                    'country': '',
                    'asn': '',
                    'rdns': '',
                    'activities': set(),
                    'types': {party_type},
                    'caveats': set(),
                    'is_caveated': False
                }
        
    # Add line traces
    for p_type, coords in lines_by_type.items():
        if coords['lons']:
            fig.add_trace(
                go.Scattergeo(
                    lon=coords['lons'],
                    lat=coords['lats'],
                    mode='lines',
                    line=dict(width=1, color=color_map.get(p_type, 'gray')),
                    name=f'{p_type} links',
                    opacity=0.4,
                    hoverinfo='skip'
                )
            )
            
    # Prepare unique points
    normal_lons, normal_lats, normal_texts = [], [], []
    caveat_lons, caveat_lats, caveat_texts = [], [], []
    
    for (lon, lat), info in unique_points.items():
        ips_str = "<br>".join(info['ips'])
        
        text_lines = [f"<b>{ips_str}</b>"]
        if info['city'] or info['country']:
            text_lines.append(f"{info['city']}, {info['country']}".strip(", "))
        if info['asn']:
            text_lines.append(f"ASN: {info['asn']}")
        if info['rdns']:
            text_lines.append(f"rDNS: {info['rdns']}")
        
        acts = [a for a in info['activities'] if a and a != 'unknown']
        if acts:
            text_lines.append(f"Activity: {', '.join(acts)}")
            
        p_types = [t for t in info['types'] if t and t != 'unknown']
        if p_types:
            text_lines.append(f"Role: {', '.join(p_types)}")
            
        if info['caveats']:
            for c in info['caveats']:
                text_lines.append(f"<br><span style='color:#ffa726'><b>Caveat:</b> {c}</span>")
                
        hover_text = "<br>".join(text_lines)
        
        if info['is_caveated']:
            caveat_lons.append(lon)
            caveat_lats.append(lat)
            caveat_texts.append(hover_text)
        else:
            normal_lons.append(lon)
            normal_lats.append(lat)
            normal_texts.append(hover_text)
            
    # Normal markers
    if normal_lons:
        fig.add_trace(
            go.Scattergeo(
                lon=normal_lons, lat=normal_lats,
                mode='markers',
                marker=dict(size=7, color='#4fc3f7', line=dict(width=1, color='#1e1e1e')),
                text=normal_texts,
                name='Verified Locations',
                hoverinfo='text'
            )
        )
        
    # Caveated markers (Amber)
    if caveat_lons:
        fig.add_trace(
            go.Scattergeo(
                lon=caveat_lons, lat=caveat_lats,
                mode='markers',
                marker=dict(size=9, color='#ffa726', symbol='diamond', line=dict(width=1, color='#1e1e1e')),
                text=caveat_texts,
                name='Caveated Locations',
                hoverinfo='text'
            )
        )
        
    fig.update_layout(
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="#e0e0e0")
        ),
        geo=dict(
            bgcolor='#1e1e1e',
            showcoastlines=True,
            coastlinecolor="#444444",
            showland=True,
            landcolor="#2a2a2a",
            showocean=True,
            oceancolor="#1a1a1a",
            showcountries=True,
            countrycolor="#444444",
            projection_type="equirectangular"
        ),
        margin=dict(l=0, r=0, t=30, b=0),
        paper_bgcolor='#1e1e1e',
        plot_bgcolor='#1e1e1e'
    )
    
    return fig.to_html(full_html=False, include_plotlyjs='cdn')
