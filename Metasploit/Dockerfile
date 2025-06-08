# Metasploit/Dockerfile
FROM rapid7/metasploit-framework:latest

USER root

# Installer Python, pip et bash
RUN apt-get update && \
    apt-get install -y python3 python3-pip bash && \
    rm -rf /var/lib/apt/lists/*

# Installer dépendance Python (si besoin)
RUN pip3 install --no-cache-dir xmltodict

# Définir le dossier de travail
WORKDIR /msf

# Copier ton script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier pour les résultats
RUN mkdir -p /msf/results

# Lancer ton script Python par défaut
ENTRYPOINT ["python3", "metasploit_scan.py"]
