# app.py - Phase 4 (Threading for Windows)
from flask import Flask, request, jsonify, render_template, url_for, redirect
import os
import uuid
import worker

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'logfile' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    job_id = str(uuid.uuid4())
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_{filename}")
    file.save(filepath)

    worker.job_queue.put((job_id, filepath, filename))
    worker.job_status[job_id] = 'queued'

    return jsonify({'job_id': job_id}), 202

@app.route('/status/<job_id>')
def job_status(job_id):
    status = worker.job_status.get(job_id, 'not_found')
    
    if status == 'finished':
        return redirect(url_for('show_report', job_id=job_id))
    elif status == 'failed':
        return f"<h1>Job Failed</h1><p>{worker.job_results.get(job_id)}</p>"
    else:
        progress = worker.job_progress.get(job_id, 0)
        return render_template('job_status.html', job_id=job_id, progress=progress)

@app.route('/status_json/<job_id>')
def job_status_json(job_id):
    status = worker.job_status.get(job_id, 'not_found')
    
    if status == 'finished':
        return jsonify({'status': 'finished'})
    elif status == 'failed':
        return jsonify({
            'status': 'failed',
            'error': worker.job_results.get(job_id, 'Unknown error')
        })
    elif status == 'processing':
        progress = worker.job_progress.get(job_id, 0)
        return jsonify({'status': 'processing', 'progress': progress})
    elif status == 'queued':
        return jsonify({'status': 'queued', 'progress': 0})
    else:
        return jsonify({'status': 'not_found'}), 404

@app.route('/report/<job_id>')
def show_report(job_id):
    if worker.job_status.get(job_id) == 'finished':
        return render_template('report.html', data=worker.job_results.get(job_id))
    else:
        return redirect(url_for('index'))

@app.route('/demo')
def load_demo():
    demo_path = os.path.join(app.root_path, 'sample_demo.log')
    if not os.path.exists(demo_path):
        with open(demo_path, 'w') as f:
            f.write('8.8.8.8 - - [24/Feb/2026:10:15:23 +0530] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"\n')
            f.write('4.4.4.4 - - [24/Feb/2026:10:16:45 +0530] "GET /admin.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
            f.write('1.1.1.1 - - [24/Feb/2026:10:17:12 +0530] "GET /../../etc/passwd HTTP/1.1" 404 256 "-" "curl/7.68.0"\n')
    
    job_id = str(uuid.uuid4())
    worker.job_queue.put((job_id, demo_path, 'sample_demo.log'))
    worker.job_status[job_id] = 'queued'
    
    return jsonify({'job_id': job_id})

if __name__ == '__main__':
    app.run(debug=True)