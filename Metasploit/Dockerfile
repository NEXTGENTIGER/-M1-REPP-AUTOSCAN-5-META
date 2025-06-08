FROM metasploitframework/metasploit-framework:latest

USER root

# Installer Python et pip
RUN apk update && apk add --no-cache python3 py3-pip bash

# Installer dépendances Python
RUN pip3 install --no-cache-dir xmltodict

# Définir un seul WORKDIR
WORKDIR /msf

# Copier le script et le template RC à cet endroit
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier results
RUN mkdir -p /msf/results

# Point d’entrée
ENTRYPOINT ["python3", "metasploit_scan.py"]
