# utils/geoip.py
import geoip2.database
import geoip2.errors
import os
from typing import Dict

class GeoIPLookup:
    def __init__(self, db_path="GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None
        self.load_database()
    
    def load_database(self):
        """Load GeoIP database"""
        try:
            if os.path.exists(self.db_path):
                self.reader = geoip2.database.Reader(self.db_path)
                print(f"GeoIP database loaded from {self.db_path}")
            else:
                print(f"GeoIP database not found at {self.db_path}")
        except Exception as e:
            print(f"Error loading GeoIP database: {e}")
            self.reader = None
    
    def lookup(self, ip: str) -> Dict:
        """Look up IP address location"""
        if not self.reader:
            return {
                'ip': ip,
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
        
        try:
            response = self.reader.city(ip)
            
            if self.is_private_ip(ip):
                return {
                    'ip': ip,
                    'country': 'Private IP',
                    'city': 'Local Network',
                    'latitude': 0,
                    'longitude': 0
                }
            
            return {
                'ip': ip,
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX',
                'city': response.city.name or 'Unknown',
                'latitude': response.location.latitude or 0,
                'longitude': response.location.longitude or 0
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                'ip': ip,
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0
            }
        except Exception as e:
            return {
                'ip': ip,
                'country': 'Error',
                'city': str(e)[:50],
                'latitude': 0,
                'longitude': 0
            }
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '::1', 'localhost'
        ]
        
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        return False
    
    def batch_lookup(self, ip_list):
        """Look up multiple IPs"""
        results = {}
        for ip in ip_list:
            results[ip] = self.lookup(ip)
        return results
    
    def close(self):
        """Close database connection"""
        if self.reader:
            self.reader.close()