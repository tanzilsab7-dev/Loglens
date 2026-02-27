# Main Flask application
from flask import Flask, request, jsonify, render_template
import os
from parser.log_parser import LogParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB limit
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Home page - upload form"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and parsing"""
    
    # Check if file exists in request
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Initialize parser
    parser = LogParser(chunk_size=16384)  # 16KB chunks
    
    parsed_lines = []
    line_count = 0
    
    try:
        # Stream process file - line by line
        for parsed_line in parser.parse_file_stream(file.stream):
            parsed_lines.append(parsed_line)
            line_count += 1
            
            # Har 1000 lines pe progress print karo (console ke liye)
            if line_count % 1000 == 0:
                print(f"Processed {line_count} lines...")
        
        # Basic statistics
        stats = {
            'total_lines': line_count,
            'unique_ips': len(set(line['ip'] for line in parsed_lines if line)),
            'status_codes': {},
            'methods': {},
            'sample': parsed_lines[:20]  # Pehle 20 lines sample ke liye
        }
        
        # Count status codes and methods
        for line in parsed_lines:
            if line:
                # Status code count
                sc = str(line.get('status_code', 0))
                stats['status_codes'][sc] = stats['status_codes'].get(sc, 0) + 1
                
                # Method count
                method = line.get('method', 'UNKNOWN')
                stats['methods'][method] = stats['methods'].get(method, 0) + 1
        
        return jsonify({
            'success': True,
            'message': f'Successfully processed {line_count} lines',
            'stats': stats,
            'preview': parsed_lines[:50]  # Preview ke liye 50 lines
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats/<filename>')
def get_stats(filename):
    """Get parsing statistics for a file"""
    # Yahan tum file analysis stats return kar sakte ho
    return jsonify({'message': 'Stats endpoint'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)