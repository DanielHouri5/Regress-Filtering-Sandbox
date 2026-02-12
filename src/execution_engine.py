import threading, time
from pathlib import Path
from container_manager import ContainerManager
from network_monitor import NetworkMonitor

class ExecutionEngine:
    """
    The core engine responsible for the end-to-end execution and analysis of a sample.
    
    It manages the high-level lifecycle: environment setup, concurrent monitoring,
    malware execution, risk evaluation, and final report generation.
    """
    def __init__(self, sample_path):
        """
        Initializes the engine with necessary components.
        
        Args:
            sample_path (str/Path): The path to the file to be analyzed.
        """
        self.sample_path = Path(sample_path)
        self.container_mgr = ContainerManager()
        self.monitor = NetworkMonitor()
        self.container = None

    def __enter__(self):
        """
        Context Manager entry point. 
        Sets up and starts the isolated Docker environment before analysis begins.
        """
        print("[*] Setting up isolated environment...")
        self.container = self.container_mgr.create_container()
        self.container.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context Manager exit point.
        Ensures the Docker container is stopped and removed, preventing resource leaks.
        """
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
        """
        Orchestrates the dynamic analysis process.
        
        This method launches a background monitoring thread while executing 
        the sample in the foreground, then aggregates and reports the findings.
        
        Args:
            runtime_sec (int): Duration in seconds to monitor the sample.
        """
        print(f"[*] Starting monitoring thread for {runtime_sec}s...")

        monitor_thread = threading.Thread(target=self.monitor.start_monitoring, args=(runtime_sec,))
        monitor_thread.start()
        
        # Brief pause to ensure the monitor is fully initialized before execution
        time.sleep(2)  

        print(f"[*] Executing sample: {self.sample_path.name}")
        # Execute the sample inside the container using strace
        self.container_mgr.exec_sample(self.container, self.sample_path.name)

        # Wait for the monitoring thread to complete its duration
        monitor_thread.join()        

