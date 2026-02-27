# tasks.py
import sys
import os
import time
from rq import get_current_job
sys.path.append(os.path.dirname(__file__))

from parser.log_parser import LogParser
from detector.enhanced_threat_detector import EnhancedThreatDetector

def process_log_file(file_path, filename):
    """
    Background task to parse and analyze log file.
    Updates job meta with progress.
    """
    job = get_current_job()
    job.meta['progress'] = 0
    job.save_meta()

    parser = LogParser(chunk_size=16384)
    detector = EnhancedThreatDetector()

    parsed_lines = []
    line_count = 0
    alerts_count = 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for parsed_line in parser.parse_file_stream(f):
                if parsed_line:
                    parsed_lines.append(parsed_line)
                    line_count += 1
                    alerts = detector.analyze_log_entry(parsed_line)
                    if alerts:
                        alerts_count += len(alerts)

                # Update progress every 1000 lines
                if line_count % 1000 == 0:
                    job.meta['progress'] = min(90, int((line_count / 100000) * 100))
                    job.meta['lines_processed'] = line_count
                    job.save_meta()

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

        job.meta['progress'] = 100
        job.save_meta()
        return result

    except Exception as e:
        job.meta['error'] = str(e)
        job.save_meta()
        raise e
    finally:
        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)