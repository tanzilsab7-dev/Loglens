# detector/enhanced_threat_detector.py
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector.threat_detector import ThreatDetector
from utils.geoip import GeoIPLookup

class EnhancedThreatDetector(ThreatDetector):
    def __init__(self):
        super().__init__()
        self.geoip = GeoIPLookup()
        
        self.timeline_data = defaultdict(lambda: defaultdict(int))
        self.attack_timeline = defaultdict(list)
        self.geo_distribution = defaultdict(lambda: defaultdict(int))
        self.hourly_attacks = defaultdict(int)
        
    def analyze_log_entry(self, log_entry: Dict) -> List[Dict]:
        alerts = super().analyze_log_entry(log_entry)
        
        if log_entry:
            timestamp = log_entry.get('timestamp', 'unknown')
            ip = log_entry.get('ip', 'unknown')
            
            hour = self.extract_hour(timestamp)
            
            self.timeline_data[hour]['total_requests'] += 1
            
            if alerts:
                for alert in alerts:
                    self.hourly_attacks[hour] += 1
                    
                    for threat in alert['threats']:
                        attack_type = threat.get('type', 'unknown')
                        self.timeline_data[hour][attack_type] += 1
                        self.attack_timeline[hour].append({
                            'type': attack_type,
                            'severity': threat.get('severity', 'UNKNOWN'),
                            'ip': ip
                        })
                    
                    if ip not in self.stats['unique_attackers']:
                        geo_info = self.geoip.lookup(ip)
                        country = geo_info.get('country', 'Unknown')
                        self.geo_distribution[country]['count'] += 1
                        self.geo_distribution[country]['ips'].append({
                            'ip': ip,
                            'city': geo_info.get('city', 'Unknown'),
                            'alerts': len(self.ip_threats[ip])
                        })
        
        return alerts
    
    def extract_hour(self, timestamp: str) -> str:
        try:
            if '[' in timestamp:
                ts = timestamp.split('[')[1].split(']')[0]
                parts = ts.split(':')
                if len(parts) >= 2:
                    date_part = parts[0]
                    hour = parts[1]
                    return f"{date_part} {hour}:00"
        except:
            pass
        return "Unknown Hour"
    
    def get_timeline_data(self) -> Dict:
        hours = sorted(self.hourly_attacks.keys())
        
        return {
            'labels': hours,
            'datasets': [
                {
                    'label': 'Total Attacks',
                    'data': [self.hourly_attacks[h] for h in hours],
                    'borderColor': '#dc3545',
                    'backgroundColor': 'rgba(220, 53, 69, 0.1)'
                },
                {
                    'label': 'SQL Injection',
                    'data': [self.timeline_data[h].get('SQL Injection', 0) for h in hours],
                    'borderColor': '#fd7e14',
                    'backgroundColor': 'rgba(253, 126, 20, 0.1)'
                },
                {
                    'label': 'XSS Attacks',
                    'data': [self.timeline_data[h].get('XSS Attacks', 0) for h in hours],
                    'borderColor': '#ffc107',
                    'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                }
            ]
        }
    
    def get_geo_distribution(self) -> Dict:
        countries = []
        counts = []
        
        for country, data in sorted(self.geo_distribution.items(), 
                                   key=lambda x: x[1]['count'], 
                                   reverse=True)[:10]:
            countries.append(country)
            counts.append(data['count'])
        
        return {
            'countries': countries,
            'counts': counts,
            'details': dict(self.geo_distribution)
        }
    
    def get_top_attackers_detailed(self, limit: int = 10) -> List[Dict]:
        top_attackers = []
        
        for ip, count in self.stats['top_attackers'].most_common(limit):
            geo_info = self.geoip.lookup(ip)
            alerts = self.ip_threats.get(ip, [])
            
            attack_types = Counter()
            severities = Counter()
            
            for alert in alerts:
                for threat in alert['threats']:
                    attack_types[threat.get('type', 'unknown')] += 1
                    severities[threat.get('severity', 'UNKNOWN')] += 1
            
            top_attackers.append({
                'ip': ip,
                'attack_count': count,
                'country': geo_info.get('country', 'Unknown'),
                'country_code': geo_info.get('country_code', 'XX'),
                'city': geo_info.get('city', 'Unknown'),
                'latitude': geo_info.get('latitude', 0),
                'longitude': geo_info.get('longitude', 0),
                'attack_types': dict(attack_types.most_common(3)),
                'severities': dict(severities),
                'last_seen': alerts[-1]['timestamp'] if alerts else 'Unknown',
                'total_alerts': len(alerts)
            })
        
        return top_attackers
    
    def get_enhanced_report(self) -> Dict:
        base_report = super().get_report()
        
        return {
            **base_report,
            'visualizations': {
                'timeline': self.get_timeline_data(),
                'geo_distribution': self.get_geo_distribution(),
                'top_attackers_detailed': self.get_top_attackers_detailed(10)
            },
            'summary': {
                **base_report['summary'],
                'total_hours_analyzed': len(self.hourly_attacks),
                'peak_attack_hour': max(self.hourly_attacks.items(), 
                                       key=lambda x: x[1])[0] if self.hourly_attacks else 'None',
                'countries_affected': len(self.geo_distribution)
            }
        }
    
    def close(self):
        self.geoip.close()