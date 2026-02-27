# detector/threat_detector.py
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List
from .signatures import AttackSignatures
from .bruteforce_detector import BruteForceDetector

class ThreatDetector:
    def __init__(self):
        self.signatures = AttackSignatures()
        self.bruteforce = BruteForceDetector(window_minutes=5, threshold=10)
        
        # Statistics
        self.alerts = []
        self.stats = {
            'total_attacks': 0,
            'unique_attackers': set(),
            'attack_types': Counter(),
            'severity_counts': Counter(),
            'top_attackers': Counter(),
            'categories': Counter(),
            'timeline': defaultdict(list),
            'detection_summary': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            }
        }
        
        # IP tracking
        self.ip_threats = defaultdict(list)
        self.path_threats = defaultdict(list)
        
    def analyze_log_entry(self, log_entry: Dict) -> List[Dict]:
        """Analyze a single log entry for threats"""
        alerts = []
        
        if not log_entry:
            return alerts
        
        # Extract fields
        ip = log_entry.get('ip', 'unknown')
        path = log_entry.get('path', '')
        user_agent = log_entry.get('user_agent', '-')
        referer = log_entry.get('referer', '-')
        status_code = log_entry.get('status_code', 0)
        timestamp = log_entry.get('timestamp', 'unknown')
        method = log_entry.get('method', 'UNKNOWN')
        
        # Check each field for attack signatures
        threats_found = []
        
        # Check URL path
        if path and path != 'unknown':
            path_threats = self.signatures.check_all(path)
            for threat in path_threats:
                threat['location'] = 'URL Path'
                threat['value'] = path
                threats_found.append(threat)
        
        # Check User Agent
        if user_agent and user_agent != '-' and user_agent != 'unknown':
            ua_threats = self.signatures.check_all(user_agent)
            for threat in ua_threats:
                threat['location'] = 'User Agent'
                threat['value'] = user_agent[:100]
                threats_found.append(threat)
        
        # Check Referer
        if referer and referer != '-' and referer != 'unknown':
            ref_threats = self.signatures.check_all(referer)
            for threat in ref_threats:
                threat['location'] = 'Referer'
                threat['value'] = referer
                threats_found.append(threat)
        
        # Check for brute force patterns
        bf_alerts = self.bruteforce.analyze(ip, timestamp, status_code, path)
        threats_found.extend(bf_alerts)
        
        # Check for directory enumeration
        if status_code == 404 and path.count('/') > 2:
            threats_found.append({
                'type': 'Directory Enumeration',
                'category': 'recon',
                'severity': 'MEDIUM',
                'description': 'Directory/file not found - possible enumeration',
                'location': 'Status Code',
                'value': f'404 on {path}',
                'confidence': 0.5
            })
        
        # Check for sensitive file access
        sensitive_extensions = ['.bak', '.backup', '.old', '.swp', '.sql', '.env', '.git']
        if any(path.endswith(ext) for ext in sensitive_extensions):
            threats_found.append({
                'type': 'Sensitive File Access',
                'category': 'info_disclosure',
                'severity': 'HIGH',
                'description': 'Attempt to access backup/sensitive file',
                'location': 'URL Path',
                'value': path,
                'confidence': 0.8
            })
        
        # Check for admin panel access with parameters
        if 'admin' in path.lower() and '?' in path and len(path.split('?')) > 1:
            threats_found.append({
                'type': 'Admin Parameter Injection',
                'category': 'admin_attack',
                'severity': 'HIGH',
                'description': 'Admin page with parameters',
                'location': 'URL Path',
                'value': path,
                'confidence': 0.6
            })
        
        # If threats found, create alert
        if threats_found:
            alert = self.create_alert(log_entry, threats_found)
            self.alerts.append(alert)
            self.update_stats(alert)
            self.ip_threats[ip].append(alert)
            
            for threat in threats_found:
                path_key = path.split('?')[0]
                self.path_threats[path_key].append(threat)
            
            alerts.append(alert)
        
        return alerts
    
    def create_alert(self, log_entry: Dict, threats_found: List[Dict]) -> Dict:
        """Create structured alert"""
        
        # Calculate overall severity
        severity_scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        
        max_severity = 'INFO'
        max_score = -1
        
        for threat in threats_found:
            score = severity_scores.get(threat.get('severity', 'INFO'), 0)
            if score > max_score:
                max_score = score
                max_severity = threat.get('severity', 'INFO')
        
        # Calculate average confidence
        avg_confidence = sum(t.get('confidence', 0.5) for t in threats_found) / len(threats_found)
        
        # Group threats by type
        threat_types = list(set(t['type'] for t in threats_found))
        
        return {
            'alert_id': len(self.alerts) + 1,
            'timestamp': log_entry.get('timestamp', 'Unknown'),
            'source_ip': log_entry.get('ip', 'Unknown'),
            'method': log_entry.get('method', 'UNKNOWN'),
            'path': log_entry.get('path', 'Unknown'),
            'status_code': log_entry.get('status_code', 0),
            'user_agent': log_entry.get('user_agent', 'Unknown'),
            'referer': log_entry.get('referer', '-'),
            'threats': threats_found,
            'threat_types': threat_types,
            'severity': max_severity,
            'confidence': round(avg_confidence, 2),
            'attack_count': len(threats_found),
            'raw_log': log_entry.get('raw', '')
        }
    
    def update_stats(self, alert: Dict):
        """Update detection statistics"""
        self.stats['total_attacks'] += 1
        self.stats['unique_attackers'].add(alert['source_ip'])
        self.stats['detection_summary'][alert['severity']] += 1
        self.stats['top_attackers'][alert['source_ip']] += 1
        
        for threat in alert['threats']:
            self.stats['attack_types'][threat['type']] += 1
            self.stats['severity_counts'][threat['severity']] += 1
            self.stats['categories'][threat.get('category', 'unknown')] += 1
        
        # Timeline
        if alert['timestamp'] != 'Unknown':
            try:
                if '[' in alert['timestamp']:
                    ts = alert['timestamp'].split('[')[1].split(']')[0]
                    hour = ts[:13]
                else:
                    hour = alert['timestamp'][:13]
                self.stats['timeline'][hour].append(alert)
            except:
                pass
    
    def get_report(self) -> Dict:
        """Generate comprehensive detection report"""
        
        # Calculate threat score
        threat_score = 0
        threat_score += self.stats['detection_summary']['CRITICAL'] * 10
        threat_score += self.stats['detection_summary']['HIGH'] * 5
        threat_score += self.stats['detection_summary']['MEDIUM'] * 2
        threat_score += self.stats['detection_summary']['LOW'] * 1
        
        # Get most attacked paths
        top_paths = []
        for path, threats in self.path_threats.items():
            if path and path != 'unknown':
                top_paths.append({
                    'path': path,
                    'attack_count': len(threats),
                    'severity': max([t.get('severity', 'LOW') for t in threats], 
                                   key=lambda x: {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(x,0))
                })
        
        top_paths.sort(key=lambda x: x['attack_count'], reverse=True)
        
        return {
            'summary': {
                'total_attacks': self.stats['total_attacks'],
                'unique_attackers': len(self.stats['unique_attackers']),
                'threat_score': threat_score,
                'risk_level': self.get_risk_level(threat_score),
                'detection_summary': dict(self.stats['detection_summary'])
            },
            'attack_breakdown': {
                'by_type': dict(self.stats['attack_types'].most_common(10)),
                'by_category': dict(self.stats['categories'].most_common()),
                'by_severity': dict(self.stats['severity_counts'])
            },
            'top_attackers': [
                {'ip': ip, 'count': count} 
                for ip, count in self.stats['top_attackers'].most_common(10)
            ],
            'top_paths': top_paths[:10],
            'recent_alerts': self.alerts[-50:],
            'timeline': dict(self.stats['timeline']),
            'ip_details': {
                ip: {
                    'total_alerts': len(alerts),
                    'severity': max([a['severity'] for a in alerts], 
                                   key=lambda x: {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(x,0)),
                    'last_seen': alerts[-1]['timestamp'] if alerts else 'Unknown'
                }
                for ip, alerts in list(self.ip_threats.items())[:20]
            }
        }
    
    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level"""
        if score >= 100:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 20:
            return 'MEDIUM'
        elif score >= 5:
            return 'LOW'
        else:
            return 'INFO'
    
    def reset(self):
        """Reset detector state"""
        self.alerts = []
        self.stats = {
            'total_attacks': 0,
            'unique_attackers': set(),
            'attack_types': Counter(),
            'severity_counts': Counter(),
            'top_attackers': Counter(),
            'categories': Counter(),
            'timeline': defaultdict(list),
            'detection_summary': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0
            }
        }
        self.ip_threats.clear()
        self.path_threats.clear()
        self.bruteforce.reset()