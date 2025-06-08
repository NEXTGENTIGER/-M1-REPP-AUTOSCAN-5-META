FROM metasploitframework/metasploit-framework:latest

USER root

# Installe Python et pip
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    bash

# Installe dépendances Python
RUN pip3 install --no-cache-dir xmltodict

WORKDIR /app

# Copier le script Python et le template RC
COPY metasploit_scan.py /app/metasploit_scan.py
COPY scan_template.rc /app/scan_template.rc

# Créer le dossier results
RUN mkdir -p /app/results

# Point d’entrée : lance le script
ENTRYPOINT ["python3", "/app/metasploit_scan.py"]
