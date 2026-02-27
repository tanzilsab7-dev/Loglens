# detector/signatures.py
import re
from typing import List, Dict

class AttackSignatures:
    def __init__(self):
        # Attack signatures database with patterns and metadata
        self.signatures = {
            'SQL Injection': [
                {
                    'pattern': r"(?i)(\bOR\b.*\b=\b.*\bOR\b)|(\bOR\b.*=.*--)|(\bOR\b.*=.*#)",
                    'severity': 'CRITICAL',
                    'description': 'SQL OR condition bypass attempt',
                    'category': 'sql_injection'
                },
                {
                    'pattern': r"(?i)(\bUNION\b.*\bSELECT\b)",
                    'severity': 'CRITICAL',
                    'description': 'UNION-based SQL injection',
                    'category': 'sql_injection'
                },
                {
                    'pattern': r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)|(\bINSERT\b.*\bINTO\b)|(\bDROP\b.*\bTABLE\b)",
                    'severity': 'HIGH',
                    'description': 'SQL command injection',
                    'category': 'sql_injection'
                },
                {
                    'pattern': r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\%3B)|(;)",
                    'severity': 'MEDIUM',
                    'description': 'SQL special characters detected',
                    'category': 'sql_injection'
                },
                {
                    'pattern': r"(?i)(waitfor\s+delay|sleep\()",
                    'severity': 'HIGH',
                    'description': 'Time-based SQL injection',
                    'category': 'sql_injection'
                },
                {
                    'pattern': r"(?i)(admin'|' or 1=1|' or '1'='1|' or 1=1--|' or '1'='1'--)",
                    'severity': 'CRITICAL',
                    'description': 'Admin bypass SQL injection',
                    'category': 'sql_injection'
                }
            ],
            
            'XSS Attacks': [
                {
                    'pattern': r"(?i)(<script[^>]*>.*?</script[^>]*>)",
                    'severity': 'CRITICAL',
                    'description': 'Script tag injection',
                    'category': 'xss'
                },
                {
                    'pattern': r"(?i)(javascript:|vbscript:|data:|onerror=|onload=|onclick=|onmouseover=)",
                    'severity': 'HIGH',
                    'description': 'JavaScript event handler',
                    'category': 'xss'
                },
                {
                    'pattern': r"(?i)(alert\(|confirm\(|prompt\(|document\.cookie|window\.location)",
                    'severity': 'HIGH',
                    'description': 'JavaScript function injection',
                    'category': 'xss'
                },
                {
                    'pattern': r"(?i)(%3Cscript%3E|%3C/script%3E|%3Csvg%3E|%3Cimg%20src=)",
                    'severity': 'HIGH',
                    'description': 'Encoded XSS payload',
                    'category': 'xss'
                },
                {
                    'pattern': r"(?i)(<iframe[^>]*src=|<embed[^>]*src=|<object[^>]*data=)",
                    'severity': 'MEDIUM',
                    'description': 'Embedded content injection',
                    'category': 'xss'
                }
            ],
            
            'Path Traversal': [
                {
                    'pattern': r"(\.\./|\.\.\\)|(\.\.\%2f|\.\.\%5c|\.\.%252f|\.\.%255c)",
                    'severity': 'HIGH',
                    'description': 'Directory traversal attempt',
                    'category': 'path_traversal'
                },
                {
                    'pattern': r"(/etc/passwd|/etc/shadow|/etc/hosts|/windows/win.ini|/boot.ini|/proc/self/environ)",
                    'severity': 'CRITICAL',
                    'description': 'Sensitive file access attempt',
                    'category': 'path_traversal'
                },
                {
                    'pattern': r"(\.\./\.\./\.\./|\.\.\\\.\.\\\.\.\\)",
                    'severity': 'HIGH',
                    'description': 'Deep directory traversal',
                    'category': 'path_traversal'
                },
                {
                    'pattern': r"(%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%2e%2e%2f)",
                    'severity': 'HIGH',
                    'description': 'URL encoded traversal',
                    'category': 'path_traversal'
                }
            ],
            
            'Bot/Scanner Activity': [
                {
                    'pattern': r"(?i)(bot|crawler|spider|scanner|nikto|nmap|sqlmap|nessus|openvas|acunetix|appscan)",
                    'severity': 'MEDIUM',
                    'description': 'Security scanner detected',
                    'category': 'bot_activity'
                },
                {
                    'pattern': r"(?i)(curl|wget|python-requests|go-http-client|java/|ruby|perl|php)",
                    'severity': 'LOW',
                    'description': 'Non-browser user agent',
                    'category': 'automated_tool'
                },
                {
                    'pattern': r"(?i)(masscan|zmap|hydra|medusa|john|hashcat)",
                    'severity': 'HIGH',
                    'description': 'Attack tool detected',
                    'category': 'attack_tool'
                }
            ],
            
            'Admin Panel Attempts': [
                {
                    'pattern': r"(/admin|/administrator|/wp-admin|/wp-login|/phpmyadmin|/myadmin|/mysql|/dbadmin|/webadmin)",
                    'severity': 'MEDIUM',
                    'description': 'Admin panel access attempt',
                    'category': 'admin_bruteforce'
                },
                {
                    'pattern': r"(\.php\?.*=.*\.\./|\.asp\?.*=.*\.\./|\.jsp\?.*=.*\.\./)",
                    'severity': 'HIGH',
                    'description': 'LFI/RFI attempt',
                    'category': 'file_inclusion'
                },
                {
                    'pattern': r"(/\.git/|/\.env|/\.aws|/\.svn|/\.bak|/backup|/temp|/test)",
                    'severity': 'MEDIUM',
                    'description': 'Sensitive directory access',
                    'category': 'info_disclosure'
                }
            ],
            
            'Command Injection': [
                {
                    'pattern': r"(?i)(\|\||\||&&|;|\$\(|`|\|\s*(whoami|id|pwd|ls|dir|cat|echo|rm|wget|curl))",
                    'severity': 'CRITICAL',
                    'description': 'Command injection attempt',
                    'category': 'command_injection'
                },
                {
                    'pattern': r"(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell\.exe|wscript\.exe)",
                    'severity': 'HIGH',
                    'description': 'Shell execution attempt',
                    'category': 'command_injection'
                }
            ]
        }
    
    def check_all(self, text: str) -> List[Dict]:
        """Check text against all signatures"""
        findings = []
        
        if not text or text == '-' or text == 'unknown':
            return findings
        
        for attack_type, patterns in self.signatures.items():
            for sig in patterns:
                try:
                    if re.search(sig['pattern'], text, re.IGNORECASE):
                        match = re.search(sig['pattern'], text, re.IGNORECASE)
                        findings.append({
                            'type': attack_type,
                            'category': sig['category'],
                            'severity': sig['severity'],
                            'description': sig['description'],
                            'matched_pattern': match.group(0) if match else '',
                            'confidence': self.calculate_confidence(text, sig)
                        })
                except Exception as e:
                    print(f"Regex error for {attack_type}: {e}")
                    continue
        
        # Remove duplicates
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f['type'], f['category'], f['matched_pattern'][:20])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        return unique_findings
    
    def calculate_confidence(self, text: str, signature: Dict) -> float:
        """Calculate confidence score for detection"""
        confidence = 1.0
        
        # Boost confidence for exact matches
        if signature['pattern'] in text:
            confidence += 0.2
        
        # Check for multiple indicators
        text_lower = text.lower()
        
        if signature['category'] == 'sql_injection':
            if 'select' in text_lower and 'from' in text_lower:
                confidence += 0.3
            if 'union' in text_lower and 'select' in text_lower:
                confidence += 0.4
            if 'where' in text_lower and '=' in text_lower:
                confidence += 0.2
        
        elif signature['category'] == 'xss':
            if '<script' in text_lower and '</script>' in text_lower:
                confidence += 0.3
            if 'alert' in text_lower and '(' in text_lower:
                confidence += 0.2
        
        # Cap at 1.0
        return min(confidence, 1.0)