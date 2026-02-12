import threading
import time
from pathlib import Path
from colorama import Fore, Style
from src.container_manager import ContainerManager
from src.network_monitor import NetworkMonitor

class ExecutionEngine:
    def __init__(self, sample_path):
            self.sample_path = Path(sample_path)
            self.container_mgr = ContainerManager()
            self.container = None
            self.monitor = None

    def __enter__(self):
        print("[*] Setting up isolated environment...")
        self.container = self.container_mgr.create_container()
        self.container.start()
        self.monitor = NetworkMonitor(container=self.container)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.container:
            print(f"\n[*] Cleaning up: Stopping and removing container...")
            print("-" * 100)
            try:
                self.container.stop(timeout=2)
                self.container.remove()
            except: pass

    def run_analysis(self, runtime_sec):
        print(f"[*] Starting monitoring thread for {runtime_sec}s...")
        
        monitor_thread = threading.Thread(target=self.monitor.start_monitoring, args=(runtime_sec,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # זמן קצר להתארגנות המוניטור לפני הרצת ה"וירוס"
        time.sleep(2) 

        print(f"[*] Executing sample: {self.sample_path.name}")
        try:
            result = self.container_mgr.exec_sample(self.container, self.sample_path.name)
            print("-" * 30)
            print("[*] Sample Console Output:")
            print(result.output.decode().strip() or "[No Output]")
            print("-" * 30)
        except Exception as e:
            print(f"[!] Execution error: {e}")

        # מחכים לסיום המוניטור
        monitor_thread.join(timeout=runtime_sec)
        
        # הפקת והדפסת הסיכום הסופי
        self._display_final_report()

    def _display_final_report(self):
        summary = self.monitor.get_analysis_summary()
        c = summary['color']
        
        print(f"\n{c}{Style.BRIGHT}{'='*65}")
        print(f"{c}{Style.BRIGHT}  FINAL SECURITY VERDICT: [ {summary['verdict']} ]")
        print(f"{c}{Style.BRIGHT}{'='*65}")
        print(f"{Fore.WHITE}  - Analyzed Packets: {summary['total_packets']}")
        print(f"{Fore.WHITE}  - Malicious Blocks: {summary['blocked_count']}")
        
        if summary['unique_ips']:
            print(f"{Fore.WHITE}  - Blocked IPs: {', '.join(summary['unique_ips'])}")
            
        print(f"\n{c}{Style.BRIGHT}  RECOMMENDATION: {summary['recommendation']}")
        print(f"{c}{'='*65}\n")