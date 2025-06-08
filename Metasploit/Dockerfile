FROM metasploitframework/metasploit-framework:latest

USER root

# Installer Python, pip et bash
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# Installer dépendance Python pour parsing si nécessaire
RUN pip3 install --no-cache-dir xmltodict

# Définir le répertoire de travail
WORKDIR /msf

# Copier le script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier pour les résultats
RUN mkdir -p /msf/results

# Par défaut, lancer le script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
