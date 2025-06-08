FROM metasploitframework/metasploit-framework:latest

USER root

# Installer Python3, pip et bash via apk
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# Installer dépendance Python
RUN pip3 install --no-cache-dir xmltodict

# Travailler dans /app (comme dans docker-compose.yml)
WORKDIR /app

# Copier le script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier résultats (sera monté en volume)
RUN mkdir -p /app/results

# Entrypoint : exécuter ton script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
