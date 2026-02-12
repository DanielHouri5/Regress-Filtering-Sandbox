# Use a lightweight Python base image to minimize attack surface and image size
FROM python:3.12-slim


RUN apt-get update && apt-get install -y \
    iptables \
    tcpdump \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /sandbox

RUN pip install --no-cache-dir scapy

# Default command starts the Python interpreter
CMD ["python3"]
