# detector/bruteforce_detector.py
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List

class BruteForceDetector:
    def __init__(self, window_minutes: int = 5, threshold: int = 10):
        self.window_minutes = window_minutes
        self.threshold = threshold
        self.ip_attempts = defaultdict(deque)
        self.ip_failures = defaultdict(int)
        self.ip_success = defaultdict(int)
        
    def analyze(self, ip: str, timestamp: str, status_code: int, path: str) -> List[Dict]:
        """Analyze for brute force patterns"""
        alerts = []
        
        # Parse timestamp
        try:
            if '[' in timestamp:
                timestamp = timestamp.split('[')[1].split(']')[0]
            current_time = datetime.strptime(timestamp[:20], "%d/%b/%Y:%H:%M:%S")
        except:
            current_time = datetime.now()
        
        # Track failed logins (401, 403)
        if status_code in [401, 403]:
            self.ip_failures[ip] += 1
            
            # Store attempt time
            self.ip_attempts[ip].append(current_time)
            
            # Clean old attempts
            cutoff = current_time - timedelta(minutes=self.window_minutes)
            while self.ip_attempts[ip] and self.ip_attempts[ip][0] < cutoff:
                self.ip_attempts[ip].popleft()
            
            # Check threshold
            attempts_in_window = len(self.ip_attempts[ip])
            
            if attempts_in_window >= self.threshold:
                severity = 'CRITICAL' if attempts_in_window >= self.threshold * 2 else 'HIGH'
                alerts.append({
                    'type': 'Brute Force Attack',
                    'category': 'bruteforce',
                    'severity': severity,
                    'description': f'{attempts_in_window} failed attempts in {self.window_minutes} minutes',
                    'details': {
                        'ip': ip,
                        'failed_attempts': attempts_in_window,
                        'time_window': self.window_minutes,
                        'threshold': self.threshold
                    },
                    'confidence': min(attempts_in_window / self.threshold, 1.0)
                })
        
        # Track successful logins after failures
        elif status_code == 200 and ('/login' in path or '/admin' in path):
            self.ip_success[ip] += 1
            
            if self.ip_failures[ip] > 5:
                alerts.append({
                    'type': 'Successful Brute Force',
                    'category': 'bruteforce_success',
                    'severity': 'CRITICAL',
                    'description': 'Successful login after multiple failures',
                    'details': {
                        'ip': ip,
                        'previous_failures': self.ip_failures[ip],
                        'successful_at': timestamp
                    },
                    'confidence': 0.9
                })
        
        # Check for rapid requests
        if len(self.ip_attempts[ip]) > self.threshold * 2:
            alerts.append({
                'type': 'Rapid Requests',
                'category': 'dos',
                'severity': 'MEDIUM',
                'description': 'Unusually high request rate',
                'details': {
                    'ip': ip,
                    'request_count': len(self.ip_attempts[ip]),
                    'time_window': self.window_minutes
                },
                'confidence': 0.7
            })
        
        return alerts
    
    def reset(self):
        """Reset detector state"""
        self.ip_attempts.clear()
        self.ip_failures.clear()
        self.ip_success.clear()