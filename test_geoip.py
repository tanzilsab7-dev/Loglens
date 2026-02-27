# test_geoip.py
import os
print("Current Directory:", os.getcwd())
print("File exists:", os.path.exists("GeoLite2-City.mmdb"))

from utils.geoip import GeoIPLookup
geo = GeoIPLookup()
result = geo.lookup('8.8.8.8')
print("Result:", result)
geo.close()