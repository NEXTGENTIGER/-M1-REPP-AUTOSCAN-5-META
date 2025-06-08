FROM python:3.11-slim

RUN apt-get update && apt-get install -y nmap && pip install python-nmap

WORKDIR /app

COPY nmapscan.py .

CMD ["python3", "/app/nmapscan.py"]
