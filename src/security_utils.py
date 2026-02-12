import requests
import io
import csv

class ThreatIntelUtility:
    def __init__(self):
        self.blacklisted_ips = set()
        self.url = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"

    def refresh_data(self):
        """מוריד את הרשימה המעודכנת מ-ThreatFox"""
        try:
            print("[*] Fetching latest threat intelligence...")
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            f = io.StringIO(response.text)
            reader = csv.reader(f, delimiter=',', quotechar='"')
            
            new_ips = set()
            for row in reader:
                if not row or row[0].startswith('#'): continue
                ip = row[2].split(':')[0] # חילוץ ה-IP מתוך ה-IOC
                new_ips.add(ip)
            
            self.blacklisted_ips = new_ips
            print(f"[+] Loaded {len(self.blacklisted_ips)} malicious IPs.")
            return True
        except Exception as e:
            print(f"[!] Error updating list: {e}")
            return False

    def is_malicious(self, ip):
        return ip in self.blacklisted_ips