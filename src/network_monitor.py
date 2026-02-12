import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import threading
from scapy.all import sniff, TCP, IP
from security_utils import ThreatIntelUtility  
from datetime import datetime

local_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")

class NetworkMonitor:
    def __init__(self, log_path=f"shared/reports/traffic_log_{local_time}.txt"):
        self.log_path = log_path
        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]
        self.intel_utility = ThreatIntelUtility()
        self.intel_utility.refresh_data()
        
        self._stop_event = threading.Event()
        
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        
        with open(self.log_path, "w") as f:
            f.write("--- Network Traffic Log ---\n")

    def start_monitoring(self, runtime_sec):
        print(f"[*] Sniffing for SYN packets for {runtime_sec}s...")
        sniff(filter="tcp[tcpflags] & (tcp-syn) != 0", 
              prn=self._process_packet, 
              timeout=runtime_sec, 
              store=0)

    def _process_packet(self, packet):
        if not packet.haslayer(IP): return
        
        dest_ip = packet[IP].dst
        src_ip = packet[IP].src
        
        log_entry = f"[SYN] {src_ip} -> {dest_ip}"
        
        if dest_ip in self.allowed_ips:
            status = "ALLOWED (Whitelist)"
        elif self.intel_utility.is_malicious(dest_ip):  # הבדיקה מול ThreatFox
            self._block_ip(dest_ip)
            status = "BLOCKED (ThreatFox Intelligence)"
        else:
            status = "UNAUTHORIZED (Not in Allowed List)"
            self._block_ip(dest_ip) 

        with open(self.log_path, "a") as f:
            f.write(f"{log_entry} | Status: {status}\n")
        print(f"[*] Connection attempt to {dest_ip}: {status}")

    def _block_ip(self, ip):
        os.system(f"iptables -A OUTPUT -d {ip} -j DROP")

    def cleanup_firewall(self):
        print("[*] Cleaning up iptables rules...")
        os.system("iptables -F")