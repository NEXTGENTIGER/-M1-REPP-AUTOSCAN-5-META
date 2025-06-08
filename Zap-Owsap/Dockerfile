FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir python-owasp-zap-v2.4

COPY zapscan.py /app/zapscan.py
WORKDIR /app

ENTRYPOINT ["python3", "zapscan.py"]
