# Use a lightweight Python base image to minimize attack surface and image size
FROM python:3.12-slim

# Install essential system-level monitoring and networking tools
# strace: Used for intercepting system calls (the core of our behavioral analysis)
# net-tools: Provides utilities like netstat for network state inspection
# Clear the apt cache in the same layer to keep the image footprint small
RUN apt-get update && apt-get install -y strace net-tools && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /sandbox

# Install psutil for internal resource monitoring (CPU/Memory tracking from within)
RUN pip install --no-cache-dir psutil

# Create a non-privileged user to execute the untrusted malware samples
# This is a critical security measure to prevent 'Container Escape' vulnerabilities
RUN useradd -m sandboxuser

# Prepare the reporting directory and ensure the restricted user has write permissions
RUN mkdir -p /reports && chown sandboxuser:sandboxuser /reports

# Switch from 'root' to the restricted user for all subsequent operations
USER sandboxuser

# Default command starts the Python interpreter
CMD ["python3"]
