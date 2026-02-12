import os
from scapy.all import sniff, IP
from src.security_utils import ThreatIntelUtility  
from datetime import datetime
from colorama import Fore, Style, init

# אתחול צבעים לטרמינל
init(autoreset=True)

class NetworkMonitor:
    def __init__(self, container=None):
        local_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        self.log_path = f"/sandbox/shared/reports/traffic_log_{local_time}.txt"
        self.allowed_ips = ["127.0.0.1", "8.8.8.8"]
        self.intel_utility = ThreatIntelUtility()
        self.intel_utility.refresh_data()
        self.container = container
        
        # מונים לסיכום סופי
        self.blocked_count = 0
        self.total_packets = 0
        self.unique_blocked_ips = set()
        
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"--- Sandbox Network Analysis: {local_time} ---\n\n")

    def start_monitoring(self, runtime_sec):
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"{Fore.CYAN}  LIVE NETWORK MONITORING  (Duration: {runtime_sec}s)")
        print(f"{Fore.CYAN}{'='*65}")
        header = f"{'TIME':<10} | {'SOURCE':<15} | {'DESTINATION':<15} | {'STATUS'}"
        print(Fore.WHITE + Style.BRIGHT + header)
        print("-" * 65)
        
        sniff(iface="eth0", filter="ip", prn=self._process_packet, timeout=runtime_sec, store=0)

    def _process_packet(self, packet):
        if not packet.haslayer(IP): return
        self.total_packets += 1

        dest_ip = packet[IP].dst
        src_ip = packet[IP].src
        
        # סינון רעשים של דוקר
        if dest_ip.startswith("172.") and src_ip.startswith("172."): return

        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if dest_ip in self.allowed_ips:
            status = "ALLOWED"
            color = Fore.GREEN
        elif self.intel_utility.is_malicious(dest_ip) or self.intel_utility.is_malicious(src_ip):
            malicious_ip = dest_ip if self.intel_utility.is_malicious(dest_ip) else src_ip
            self._block_ip(malicious_ip)
            status = "BLOCKED (MALICIOUS)"
            color = Fore.RED
            
            if malicious_ip not in self.unique_blocked_ips:
                self.unique_blocked_ips.add(malicious_ip)
                self.blocked_count += 1
        else:
            status = "UNAUTHORIZED"
            color = Fore.YELLOW

        # הדפסה למסך
        print(f"{color}{timestamp:<10} | {src_ip:<15} | {dest_ip:<15} | {status}")

        # כתיבה ללוג
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip} -> {dest_ip} | {status}\n")
            f.flush()

    def _block_ip(self, ip_address):
        """חסימה דו-כיוונית הרמטית"""
        if self.container and ip_address not in self.allowed_ips:
            self.container.exec_run(f"iptables -A OUTPUT -d {ip_address} -j DROP")
            self.container.exec_run(f"iptables -A INPUT -s {ip_address} -j DROP")

    def get_analysis_summary(self):
        """מחשב את הדירוג הסופי על סמך הממצאים"""
        verdict = "CLEAN"
        color = Fore.GREEN
        recommendation = "File appears safe for execution."
        
        if self.blocked_count > 0:
            verdict = "MALICIOUS"
            color = Fore.RED
            recommendation = "DANGER: This file attempted to contact known malicious servers. DO NOT RUN."
        elif self.total_packets > 100:
            verdict = "SUSPICIOUS"
            color = Fore.YELLOW
            recommendation = "Warning: Unusual amount of network activity detected."
            
        return {
            "verdict": verdict,
            "color": color,
            "blocked_count": self.blocked_count,
            "unique_ips": list(self.unique_blocked_ips),
            "total_packets": self.total_packets,
            "recommendation": recommendation
        }