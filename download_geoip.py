# download_geoip.py
import urllib.request
import os

print("=" * 50)
print("Downloading GeoIP Database...")
print("=" * 50)

url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
filename = "GeoLite2-City.mmdb"

try:
    print(f"Downloading from: {url}")
    urllib.request.urlretrieve(url, filename)
    print(f"Successfully downloaded: {filename}")
    print(f"File size: {os.path.getsize(filename)} bytes")
    print(f"Location: {os.path.abspath(filename)}")
except Exception as e:
    print(f"Download failed: {e}")
    print("\nAlternative method:")
    print("1. Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
    print("2. Download GeoLite2-City.mmdb")
    print("3. Place it in your project folder")