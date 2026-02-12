import threading, time, re
from pathlib import Path

class Monitor:
    """
    The behavioral analysis engine of the sandbox.
    
    It performs dual-track monitoring:
    1. Resource Tracking: Real-time polling of CPU, RAM, and Thread usage.
    2. Syscall Analysis: Parsing strace logs using Regex to detect malicious patterns.
    """
    def __init__(self, container):
        """
        Initializes the monitor with detection rules and internal state.
        
        Args:
            container: The Docker container instance to be monitored.
        """
        self.container = container
        self._stop_event = threading.Event()
        self.trace_log_path = Path("shared/reports/trace.log")

        # Ensure the report directory exists and clear previous logs
        try:
            self.trace_log_path.parent.mkdir(parents=True, exist_ok=True) 
            with open(self.trace_log_path, 'w') as f:
                f.truncate(0)
        except Exception as e:
            print(f"[!] Warning: Could not clear log file: {e}")

        # Dictionary to store all collected data points
        self.stats = {
            "cpu_history": [], 
            "memory_history": [],
            "processes": {"total_spawned": 0, "seen": set()},
            "threads": {"max": 0}, 
            "behavior_alerts": []
        }
        
        # Security Detection Rules: Map System Call Regex patterns to human-readable alerts
        self.DETECTION_RULES = {
            r"execve\(.*python": None, 
            r"socket\(AF_INET": "Network socket creation",
            r"connect\(.*sin_addr=inet_addr\(\"(?!127\.0\.0\.1|172\.|0\.0\.0\.0)[^\"]+\"\)": "Outbound network connection attempt (external)",
            r'openat\(.*(?=.*O_CREAT)(?=.*(O_WRONLY|O_RDWR|O_APPEND))': "File creation and write activity",
            r"creat\(|open.*O_CREAT": "File creation detected",
            r"write\((?!1|2|3|4|5|6)[0-9]+,": "File write activity",
            r"unlink\(.*/tmp/": "File deletion in temp directory",
            r"unlink\(": "File deletion outside temp (Ransomware pattern)",
            r"chmod\(|fchmod\(": "File permission modification",
            r"/etc/(shadow|passwd)": "Sensitive system file access attempt",
            r"mmap.*PROT_WRITE.*PROT_EXEC": "Executable memory mapping (Potential code injection)",            
            r"mprotect.*PROT_EXEC": "Memory protection change to executable",
            r"execve\(": "Suspicious process execution"
        }

    def start_monitoring(self, runtime_sec):
        """
        The main loop for resource monitoring. Runs in a separate thread.
        
        Args:
            runtime_sec (int): How long to poll for resource usage.
        """
        start_t = time.time()
        self.stats["processes"]["seen"].update(self._get_pids())

        # Continuous polling loop
        while (time.time() - start_t) < runtime_sec and not self._stop_event.is_set():
            try:
                # Fetch Docker stats (CPU/Memory)
                s = self.container.stats(stream=False)

                # Calculate CPU percentage based on delta usage
                cpu_delta = s["cpu_stats"]["cpu_usage"]["total_usage"] - s["precpu_stats"]["cpu_usage"]["total_usage"]
                sys_delta = s["cpu_stats"]["system_cpu_usage"] - s["precpu_stats"]["system_cpu_usage"]
                if sys_delta > 0:
                    self.stats["cpu_history"].append((cpu_delta / sys_delta) * 100)
                
                # Memory usage in MB
                mem_mb = s["memory_stats"]["usage"] / (1024**2)
                self.stats["memory_history"].append(mem_mb)

                # Thread tracking via /proc inside the container
                curr_pids = self._get_pids()     
                self._update_threads(curr_pids)

            except Exception: pass
            time.sleep(0.5) # Poll twice per second

        # Once the execution time is up, parse the strace log for behavioral patterns
        self.analyze_behavior()

    def analyze_behavior(self):
        """
        Parses the strace log file to find malicious system call patterns.
        Implements a state-machine to focus only on code between START/STOP signals.
        """
        if not self.trace_log_path.exists(): return

        lines = self.trace_log_path.read_text(errors="ignore").splitlines()

        # Tracking sets for correlation (e.g., did they delete what they just wrote?)
        files_created, files_written, files_deleted = set(), set(), set()
        external_conn = False
        is_inside_payload = False

        for line in lines:
            # Marker Logic: Skip boilerplate Python startup noise
            if ("START_MONITORING" in line) and ("open" in line or "access" in line):
                is_inside_payload = True
                continue
            
            if ("STOP_MONITORING" in line) and ("open" in line or "access" in line):
                is_inside_payload = False
                break
            
            if "START_MONITORING" in line or "STOP_MONITORING" in line or not is_inside_payload:
                continue

            if self._is_noise(line): continue

            if "execve(" in line:
                if "ENOENT" in line:
                    continue

                match = re.search(r'execve\("([^"]+)"', line)
                if match:
                    cmd_name = match.group(1).split("/")[-1]
                    benign_cmds = ["sh", "python", "python3"] 
                    
                    if cmd_name not in benign_cmds:
                        alert = f"Suspicious process execution ({cmd_name})"
                        self.stats["behavior_alerts"].append(alert)
                continue
            
            # Regex Rule Matching
            for pattern, alert in self.DETECTION_RULES.items():
                if re.search(pattern, line):
                    if alert: 
                        print("Alert detected:", alert, "in line:", line.strip())
                        self.stats["behavior_alerts"].append(alert)

                        # Extract filenames for correlation
                        path_match = re.search(r'["\'](/[^"\']+)["\']', line)
                        file_path = path_match.group(1) if path_match else None

                        # Store file interaction state
                        if "creation" in alert: files_created.add(file_path)
                        if "write" in alert: files_written.add(file_path)
                        if "deletion" in alert: files_deleted.add(file_path)
                        if "external" in alert: external_conn = True
                    break

        # Final step: Check if multiple events combined represent a higher threat
        self._apply_correlation_rules(files_created, files_written, files_deleted, external_conn, lines)

    def _apply_correlation_rules(self, files_created, files_written, files_deleted, external_conn, lines):
        """
        Heuristic Analysis: Connects isolated dots into a behavioral story.
        
        This method identifies complex attack patterns by correlating multiple 
        low-level events that, when combined, indicate high-risk intent.
        
        Args:
            files_created (set): Set of paths where a creation event was detected.
            files_written (set): Set of paths where a write event was detected.
            files_deleted (set): Set of paths where a deletion event was detected.
            external_conn (bool): True if an outbound network connection occurred.
            lines (list): The raw strace log lines for process counting.
        """
        alerts = self.stats["behavior_alerts"]

        # Process Counting: Count fork/clone calls to determine how many child 
        # processes the malware tried to spawn.
        all_content = "".join(lines)
        fork_calls = re.findall(r"\b(clone|fork|vfork)\b", all_content)
        self.stats["processes"]["total_spawned"] = len(fork_calls) + 1

        # Pattern 1: File Lifecycle (Anti-Forensics)
        # Intersection logic: Did the same file get created, used, and then wiped?
        full_lifecycle = files_created.intersection(files_written).intersection(files_deleted)
        if full_lifecycle:
            self.stats["behavior_alerts"].append("Suspicious file lifecycle pattern (create → write → delete)")

        # Pattern 2: Data Exfiltration & Cleanup
        # If files were deleted and network activity occurred, it suggests 'Stage & Purge' behavior.
        if files_deleted and external_conn:
            alerts.append("Data destruction followed by external communication")

    def _is_noise(self, line):
        """
        Context-Aware Filter: Strips away benign OS and Interpreter activity.
        
        Malware analysis is often "finding a needle in a haystack." This filter 
        removes the haystack (Python's internal memory management and library loading).
        
        Returns:
            bool: True if the line is irrelevant background noise, False if it's suspicious.
        """
        # 1. Ignore low-level memory/thread primitives
        pure_noise = ["brk", "futex", "getrandom", "clock_gettime", "rt_sigprocmask"]
        if any(term in line for term in pure_noise):
            return True
        # 2. Distinguish between 'Loading a Library' and 'Code Injection'
        # mmap of a .so file is normal; mmap with PROT_EXEC on anonymous memory is not.
        if "mmap" in line or "mprotect" in line:
            if ".so" in line or "ld.so.cache" in line:
                return True
            if "PROT_EXEC" in line:
                return False

        # 3. Filter access to standard system libraries
        system_paths = ["/usr/lib", "/lib/", "/etc/ld.so.cache"]
        if any(path in line for path in system_paths):
            if "access" in line or "O_RDONLY" in line:
                return True

        return False

    def _get_pids(self):
        """
        Proc-FS Scraper: Inspects the container's /proc filesystem.
        
        Directly queries the kernel state inside the container to find active 
        Process IDs (PIDs), while filtering out the sandbox's own management tools.
        
        Returns:
            set: A set of active PIDs belonging to the analyzed sample.
        """
        # List directories in /proc to find active PID numbers
        res = self.container.exec_run("ls /proc")
        pids = [p for p in res.output.decode().split() if p.isdigit()]
        
        filtered_pids = set()
        for pid in pids:
            # Check the process name (comm) to avoid counting 'ls', 'sh', etc.
            name_res = self.container.exec_run(f"cat /proc/{pid}/comm")
            proc_name = name_res.output.decode().strip()
            
            if proc_name not in ["sh", "ls", "cat", "sleep", "grep"]:
                filtered_pids.add(pid)
                
        return filtered_pids

    def _update_threads(self, pids):
        """
        Thread Intensity Monitor: Tracks multi-threading behavior.
        
        Malware often uses multiple threads for parallelized tasks (like 
        brute-forcing or simultaneous file encryption).
        
        Args:
            pids (set): Current active PIDs to inspect.
        """
        total = 0
        for pid in pids:
            try:
                # Read the 'Threads' field from /proc/[pid]/status
                out = self.container.exec_run(f"grep Threads /proc/{pid}/status").output.decode()
                total += int(out.split()[1])
            except: continue
        # Record the historical peak for the final report
        self.stats["threads"]["max"] = max(self.stats["threads"]["max"], total)

    def stop(self): 
        """Signals the monitoring thread to terminate gracefully."""
        self._stop_event.set()
