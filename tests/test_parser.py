import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.log_parser import LogParser

class TestLogParser(unittest.TestCase):
    
    def setUp(self):
        """Har test se pehle run hoga"""
        self.parser = LogParser()
    
    def test_simple_log_line(self):
        """Simple CLF format test karo"""
        line = '192.168.1.1 - - [24/Feb/2026:10:15:23 +0530] "GET /index.html HTTP/1.1" 200 1024'
        result = self.parser.parse_line(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '192.168.1.1')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['status_code'], 200)
    
    def test_extended_log_line(self):
        """Extended format with User Agent test karo"""
        line = '192.168.1.1 - - [24/Feb/2026:10:15:23 +0530] "GET /index.html HTTP/1.1" 200 1024 "http://google.com" "Mozilla/5.0"'
        result = self.parser.parse_line(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '192.168.1.1')
        self.assertEqual(result['referer'], 'http://google.com')
        self.assertEqual(result['user_agent'], 'Mozilla/5.0')
    
    def test_invalid_line(self):
        """Invalid line handle karna test karo"""
        line = 'This is not a valid log line'
        result = self.parser.parse_line(line)
        
        self.assertIsNotNone(result)  # Error case mein bhi dict return karega
        self.assertEqual(result['ip'], 'unknown')
    
    def test_empty_line(self):
        """Empty line handle karna test karo"""
        line = ''
        result = self.parser.parse_line(line)
        self.assertIsNone(result)
    
    def test_chunk_processing(self):
        """Chunk processing test karo"""
        lines = [
            '192.168.1.1 - - [24/Feb/2026:10:15:23] "GET /page1 HTTP/1.1" 200 1024',
            '192.168.1.2 - - [24/Feb/2026:10:15:24] "POST /api HTTP/1.1" 201 512',
            '192.168.1.3 - - [24/Feb/2026:10:15:25] "GET /page2 HTTP/1.1" 404 256'
        ]
        
        chunk = '\n'.join(lines)
        results = list(self.parser.parse_chunk(chunk))
        
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['ip'], '192.168.1.1')
        self.assertEqual(results[1]['ip'], '192.168.1.2')
        self.assertEqual(results[2]['ip'], '192.168.1.3')

if __name__ == '__main__':
    unittest.main()