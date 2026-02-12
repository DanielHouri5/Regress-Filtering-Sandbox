# Dockerfile מעודכן
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    docker.io \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

# הגדרת PYTHONPATH כך שפייתון תכיר בתיקיית src כחבילה
ENV PYTHONPATH=/sandbox

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# הרצה של main דרך מודול (שימוש ב-m) שומר על הקשר ה-Packages
ENTRYPOINT ["python3", "-m", "src.main"]