import os
import uuid
import csv
from flask import Flask, render_template, request, redirect, url_for, send_file

# Add src to the path to import the pipeline
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.pipeline import run_pipeline

UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# In-memory store for file paths (prototype only)
upload_registry = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['RESULTS_FOLDER'] = RESULTS_FOLDER
    
    for folder in [UPLOAD_FOLDER, RESULTS_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)
    
    @app.route('/')
    def index():
        return render_template('upload.html')
        
    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'pcap_file' not in request.files:
            return render_template('upload.html', error='No file part')
        file = request.files['pcap_file']
        if file.filename == '':
            return render_template('upload.html', error='No selected file')
        if file and allowed_file(file.filename):
            filename = f"{uuid.uuid4()}_{file.filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            upload_registry[filename] = filepath
            return redirect(url_for('results', file_id=filename))
        else:
            return render_template('upload.html', error='Invalid file type. Please upload .pcap or .pcapng files.')
        
    @app.route('/results/<file_id>')
    def results(file_id):
        filepath = upload_registry.get(file_id)
        if not filepath:
            return "File not found", 404
            
        output_dir = os.path.join(app.config['RESULTS_FOLDER'], file_id)
        
        try:
            # Synchronously run the pipeline
            run_pipeline(filepath, output_dir)
            
            # Read CSV results
            packet_data = []
            with open(os.path.join(output_dir, 'packet_metadata.csv'), 'r') as f:
                packet_data = list(csv.DictReader(f))
                
            flow_data = []
            with open(os.path.join(output_dir, 'flow_summary.csv'), 'r') as f:
                flow_data = list(csv.DictReader(f))
                
            return render_template('results.html', file_id=file_id, packets=packet_data, flows=flow_data)
        except Exception as e:
            return render_template('results.html', error=f"Pipeline failed: {str(e)}")

    @app.route('/results/<file_id>/packet_metadata.csv')
    def download_packets(file_id):
        output_dir = os.path.join(app.config['RESULTS_FOLDER'], file_id)
        return send_file(os.path.join(output_dir, 'packet_metadata.csv'), as_attachment=True)

    @app.route('/results/<file_id>/flow_summary.csv')
    def download_flows(file_id):
        output_dir = os.path.join(app.config['RESULTS_FOLDER'], file_id)
        return send_file(os.path.join(output_dir, 'flow_summary.csv'), as_attachment=True)
        
    return app
