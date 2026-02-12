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

        if src_ip == "192.168.1.132": 
            return
        
        log_entry = f"[SYN] {src_ip} -> {dest_ip}"
        
        if dest_ip in self.allowed_ips:
            status = "ALLOWED (Whitelist)"
        elif self.intel_utility.is_malicious(dest_ip):  # הבדיקה מול ThreatFox
            self._block_ip(dest_ip)
            status = "BLOCKED (ThreatFox Intelligence)"
        else:
            status = "UNAUTHORIZED (Not in lists)"

        log_entry = f"[SYN] {src_ip} -> {dest_ip} | Status: {status}"
        with open(self.log_path, "a") as f:
            f.write(f"{log_entry}\n")
        print(f"[*] Connection attempt to {dest_ip}: {status}")

    def _block_ip(self, ip_address):
        result = self.container.exec_run(f"iptables -A OUTPUT -d {ip_address} -j DROP")
        print(f"[*] Sample Output: {result.output.decode()}")
        if result.exit_code == 0:
            print(f"[!] Successfully blocked {ip_address} INSIDE the container.")
        else:
            print(f"[!] Failed to block {ip_address}. Error: {result.output.decode()}")

    def cleanup_firewall(self):
        if self.container:
            try:
                self.container.exec_run("iptables -F")
                print("[*] Iptables rules cleared inside container.")
            except:
                pass