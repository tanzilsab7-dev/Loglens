# worker.py - Simple threading worker for Windows
import threading
import time
import queue
import sys
import os

sys.path.append(os.path.dirname(__file__))
from parser.log_parser import LogParser
from detector.enhanced_threat_detector import EnhancedThreatDetector

# Job queue - YEH LINE IMPORTANT HAI!
job_queue = queue.Queue()
job_results = {}
job_status = {}
job_progress = {}

def process_log_file(file_path, filename, job_id):
    """Background task to parse and analyze log file."""
    try:
        job_status[job_id] = 'processing'
        job_progress[job_id] = 0
        
        parser = LogParser(chunk_size=16384)
        detector = EnhancedThreatDetector()
        
        parsed_lines = []
        line_count = 0
        alerts_count = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for parsed_line in parser.parse_file_stream(f):
                if parsed_line:
                    parsed_lines.append(parsed_line)
                    line_count += 1
                    alerts = detector.analyze_log_entry(parsed_line)
                    if alerts:
                        alerts_count += len(alerts)
                
                # Update progress every 100 lines
                if line_count % 100 == 0:
                    progress = min(90, int((line_count / 1000) * 100))
                    job_progress[job_id] = progress
        
        detection_report = detector.get_enhanced_report()
        detector.close()
        
        # Basic stats
        unique_ips = set()
        status_codes = {}
        methods = {}
        for line in parsed_lines:
            if line:
                if 'ip' in line:
                    unique_ips.add(line['ip'])
                sc = str(line.get('status_code', 0))
                status_codes[sc] = status_codes.get(sc, 0) + 1
                method = line.get('method', 'UNKNOWN')
                methods[method] = methods.get(method, 0) + 1
        
        stats = {
            'total_lines': line_count,
            'unique_ips': len(unique_ips),
            'status_codes': status_codes,
            'methods': methods,
            'total_alerts': alerts_count,
            'critical_alerts': detection_report['summary']['detection_summary']['CRITICAL'],
            'high_alerts': detection_report['summary']['detection_summary']['HIGH'],
            'medium_alerts': detection_report['summary']['detection_summary']['MEDIUM']
        }
        
        result = {
            'stats': stats,
            'detection': detection_report,
            'preview': parsed_lines[:50],
            'filename': filename
        }
        
        job_results[job_id] = result
        job_status[job_id] = 'finished'
        job_progress[job_id] = 100
        
    except Exception as e:
        job_status[job_id] = 'failed'
        job_results[job_id] = str(e)
        print(f"Error processing job {job_id}: {e}")
    finally:
        # Clean up uploaded file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass

def start_worker():
    """Start worker thread"""
    def worker_loop():
        print("Worker thread started - waiting for jobs...")
        while True:
            try:
                job_id, file_path, filename = job_queue.get(timeout=1)
                print(f"Processing job: {job_id}, file: {filename}")
                process_log_file(file_path, filename, job_id)
                print(f"Job completed: {job_id}")
            except queue.Empty:
                time.sleep(0.1)
            except Exception as e:
                print(f"Worker error: {e}")
    
    thread = threading.Thread(target=worker_loop, daemon=True)
    thread.start()

# Start worker when module is imported
start_worker()

# Export these variables for app.py to use
__all__ = ['job_queue', 'job_results', 'job_status', 'job_progress']