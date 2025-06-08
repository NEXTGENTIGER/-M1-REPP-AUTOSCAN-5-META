FROM python:3.11-slim

# Installer tshark (et ses dépendances nécessaires)
RUN apt-get update && \
    apt-get install -y tshark libcap2-bin && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ajouter le script
COPY capture_tshark.py /app/capture_tshark.py
WORKDIR /app

# Autoriser dumpcap sans sudo
RUN setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)

ENTRYPOINT ["python3", "capture_tshark.py"]
