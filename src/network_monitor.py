import os
import threading
from scapy.all import sniff, TCP, IP

class NetworkMonitor:
    def __init__(self, log_path="shared/reports/traffic_log.txt"):
        self.log_path = log_path
        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]  
        self.suspect_ips = ["1.1.1.1", "192.168.1.50"] 
        self._stop_event = threading.Event()
        
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
        elif dest_ip in self.suspect_ips:
            self._block_ip(dest_ip)
            status = "BLOCKED (Suspect List)"
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