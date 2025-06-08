# Metasploit/Dockerfile
FROM metasploitframework/metasploit-framework:latest

USER root

# Installer Python, pip et bash
RUN apt-get update && \
    apt-get install -y python3 python3-pip bash && \
    rm -rf /var/lib/apt/lists/*

# Installer dépendance Python (xmltodict ou autre si besoin)
RUN pip3 install --no-cache-dir xmltodict

# Définir le dossier de travail
WORKDIR /msf

# Copier le script et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier de résultats
RUN mkdir -p /msf/results

# Entrypoint : lance le script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
