# Parser module - Log files ko parse karega
import re
from typing import Dict, Generator

class LogParser:
    def __init__(self, chunk_size=8192):  # 8KB chunks
        self.chunk_size = chunk_size
        self.partial_line = ""  # Adhoori line agle chunk ke liye save
        
        # Common Log Format (CLF) ke liye regex pattern
        # Example: 127.0.0.1 - - [24/Feb/2026:10:15:23 +0530] "GET /index.html HTTP/1.1" 200 1024
        self.log_pattern = re.compile(
            r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+'
        )
        
        # Extended format (with User Agent)
        self.extended_pattern = re.compile(
            r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "([^"]*)" "([^"]*)"'
        )
    
    def parse_line(self, line: str) -> Dict:
        """Ek single log line parse karo"""
        line = line.strip()
        if not line:
            return None
        
        # Pehle extended format try karo (with User Agent)
        match = self.extended_pattern.match(line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'status_code': int(match.group(5)),
                'referer': match.group(6),
                'user_agent': match.group(7),
                'raw': line[:100] + '...' if len(line) > 100 else line
            }
        
        # Agar extended format nahi mila to simple CLF try karo
        match = self.log_pattern.match(line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'status_code': int(match.group(5)),
                'referer': '-',
                'user_agent': '-',
                'raw': line[:100] + '...' if len(line) > 100 else line
            }
        
        # Agar kuch bhi match nahi hua
        return {
            'ip': 'unknown',
            'timestamp': 'unknown',
            'method': 'unknown',
            'path': 'unknown',
            'status_code': 0,
            'referer': '-',
            'user_agent': '-',
            'raw': line[:100] + '...',
            'error': 'Failed to parse'
        }
    
    def parse_chunk(self, chunk: str) -> Generator[Dict, None, None]:
        """Ek chunk process karo aur complete lines return karo"""
        
        # Purani adhoori line + naya chunk
        data = self.partial_line + chunk
        lines = data.split('\n')
        
        # Last line ho sakti hai adhoori - save for next chunk
        self.partial_line = lines[-1]
        
        # Complete lines process karo
        for line in lines[:-1]:
            if line.strip():
                parsed = self.parse_line(line)
                if parsed:
                    yield parsed
    
    def parse_file_stream(self, file_object):
        """File object ko stream karo"""
        self.partial_line = ""  # Reset for new file
        
        while True:
            chunk = file_object.read(self.chunk_size)
            if not chunk:
                break
            
            # Bytes to string (handle encoding errors)
            if isinstance(chunk, bytes):
                chunk = chunk.decode('utf-8', errors='ignore')
            
            # Parse chunk
            for parsed_line in self.parse_chunk(chunk):
                yield parsed_line
        
        # Last line check karo
        if self.partial_line.strip():
            last_line = self.parse_line(self.partial_line)
            if last_line:
                yield last_line