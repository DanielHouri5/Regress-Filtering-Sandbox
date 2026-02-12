import threading, time
from pathlib import Path
from container_manager import ContainerManager
from network_monitor import NetworkMonitor

class ExecutionEngine:
    def __init__(self, sample_path):
        self.sample_path = Path(sample_path)
        self.container_mgr = ContainerManager()
        self.monitor = None
        self.container = None

    def __enter__(self):
        print("[*] Setting up isolated environment...")
        self.container = self.container_mgr.create_container()
        self.container.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.container:
            print("[*] Cleaning up: Stopping and removing container...")
            print("-"*100)
            try:
                self.container.stop(timeout=2)
                self.container.remove()
            except Exception as e:
                print(f"[!] Cleanup warning: {e}")
        self.monitor.cleanup_firewall()

    def run_analysis(self, runtime_sec):
        print(f"[*] Starting monitoring thread for {runtime_sec}s...")

        self.monitor = NetworkMonitor(container=self.container)
        monitor_thread = threading.Thread(target=self.monitor.start_monitoring, args=(runtime_sec,))
        monitor_thread.start()
        
        time.sleep(2)  

        self.container_mgr.exec_sample(self.container, self.sample_path.name)

        monitor_thread.join()        
