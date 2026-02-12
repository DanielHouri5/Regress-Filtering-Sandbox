# 🛡️ Regress-Filtering-Sandbox

A high-performance, Docker-based **Malware Analysis Sandbox** designed for dynamic file execution in an isolated environment. The system features real-time network sniffing, automated threat intelligence correlation, and active bidirectional traffic interception.

---

## 📋 System Overview

The Regress-Filtering-Sandbox provides a secure environment to execute and monitor suspicious Python scripts. By leveraging **Docker-out-of-Docker (DooD)** technology, it spawns isolated runtime containers, monitors their network stack, and cross-references all traffic with live **Threat Intelligence** feeds.

If a connection to a known malicious Command & Control (C2) server is detected, the system immediately drops the connection at the kernel level using `iptables`.

## 🔄 Data Flow & Architecture

1.  **Initialization:** The Controller pulls the latest malicious IP indicators (IOCs) from the **ThreatFox API**.
2.  **Environment Isolation:** A dedicated "Target Container" is created with a shared network namespace to the monitor.
3.  **Active Monitoring:** The Network Monitor utilizes **Scapy** for real-time packet inspection on the `eth0` interface.
4.  **Detection & Response:**
    -   Outgoing packets are inspected for malicious destination IPs.
    -   **Automated Mitigation:** Upon detection, the system injects `iptables` rules into the Target Container to block both `INPUT` and `OUTPUT` traffic for that IP.
5.  **Final Verdict:** After execution, the engine analyzes total packet count, block frequency, and threat severity to provide a final security **Verdict** (CLEAN, SUSPICIOUS, or MALICIOUS).

---

## 🛠️ System Requirements

-   **Docker Desktop:** Installed and running.
-   **Linux-based Shell:** Git Bash (Windows), WSL2, or native Linux.
-   **Internet Access:** Required for real-time Threat Intelligence updates.

---

## 🚀 Getting Started

### 1. Build the Images

Run the following commands from the project root:

```bash
# Build the Management Controllerdocker build -t sandbox-controller .# Build the Isolated Runtime Environmentdocker build -f Dockerfile.runtime -t sandbox-runtime .
```