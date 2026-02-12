---
# 🛡️ Malware Analysis Sandbox

A secure, automated environment for analyzing suspicious Python scripts. The sandbox leverages **Docker isolation** and **System Call Tracing (strace)** to monitor behavior, enforce security policies, and generate detailed risk reports.
---

## 📁 Project Structure

- **`cli/`**: Entry point for the Command Line Interface.
- **`configs/`**: Configuration files for sandbox limits and image tags.
- **`controller/`**: Orchestrates the analysis flow.
- **`orchestrator/`**: Handles Docker container lifecycle and automated image building.
- **`sandbox/`**: The core engine (Monitoring, System Call Analysis, and Risk Policy).
- **`shared/samples/`**: **Target directory.** Place your `.py` files here for analysis.
- **`shared/reports/`**: Destination for generated JSON analysis reports.
- **`tests/`**: Unit tests for critical components.

---

## 🛠️ Installation & Setup

### 1. Prerequisites

- Python ≥ 3.12
- Docker Desktop (running)

### 2. Install Dependencies

Create a virtual environment (optional) and install the requirements:

```bash
pip install -r requirements.txt

```

### 3. Automated Environment Setup

_Note: You **do not** need to build the Docker image manually. The system will automatically detect and build the required environment upon the first execution._

---

## ▶️ Running Analysis

### Important: Adding Samples

Before running, you must place the Python scripts you wish to analyze inside the `shared/samples/` directory.

### To analyze a single file:

```bash
python -m cli.main --sample shared/samples/your_script.py

```

### To analyze ALL files in the samples directory (Batch Run):

Run this command in your terminal to iterate through all Python files:

```bash
for file in shared/samples/*.py; do python -m cli.main --sample "$file"; done

```

---

## 🧪 Running Unit Tests

The sandbox includes a suite of tests to ensure the monitoring and policy engines are accurate. These tests use **Mocks** to simulate Docker activity, so they are fast and safe to run.

### To run ALL tests:

```bash
python -m pytest tests/ -v

```

### To run a specific test file:

```bash
# Example: Testing only the Risk Policy engine
python -m pytest tests/test_policy.py -v

# Example: Testing only the Monitor engine
python -m pytest tests/test_monitoring.py -v

```

---

## 📦 Requirements (`requirements.txt`)

Ensure you have a `requirements.txt` file in the root directory with:

```text
docker>=7.1.0
pyyaml>=6.0.1
pytest>=8.0.0

```

---

## 📊 Reports & Verdicts

After execution, a JSON report is generated in `shared/reports/` for each sample. The report includes:

- **Resource Usage:** Peak CPU, RAM, and Thread count.
- **Behavioral Alerts:** Detected suspicious system calls.
- **Risk Score:** A weighted score calculated by the `SandboxPolicy`.
- **Final Verdict:** `CLEAN`, `SUSPICIOUS`, or `MALICIOUS`.

---

## ⚡ Quick Troubleshooting

- **Docker Error:** Ensure Docker Desktop is open and running.
- **ImportError:** Always run commands using `python -m` from the project's root directory.
- **Log Clearing:** The monitor automatically clears `trace.log` before each run to avoid data contamination.

---
