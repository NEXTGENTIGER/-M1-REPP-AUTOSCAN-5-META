# Metasploit/Dockerfile
FROM metasploitframework/metasploit-framework:latest

USER root

# Installer Python 3, pip et bash
RUN apk update && \
    apk add --no-cache python3 py3-pip bash

# Installer dépendance Python (xmltodict)
RUN pip3 install --no-cache-dir xmltodict

# Définir le répertoire de travail
WORKDIR /msf

# Copier le script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier de résultats (sera monté sur le host)
RUN mkdir -p /msf/results

# Lancer ton script Python à l'entrée du conteneur
ENTRYPOINT ["python3", "metasploit_scan.py"]
