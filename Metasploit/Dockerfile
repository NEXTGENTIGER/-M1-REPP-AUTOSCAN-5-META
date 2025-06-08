FROM metasploitframework/metasploit-framework:debian

USER root

# Installer Python, pip et bash
RUN apt-get update && \
    apt-get install -y python3 python3-pip bash && \
    rm -rf /var/lib/apt/lists/*

# Installer la dépendance Python pour XML parsing (si besoin dans ton script)
RUN pip3 install --no-cache-dir xmltodict

# Déclarer le répertoire de travail
WORKDIR /msf

# Copier le script de scan et le template RC dans le conteneur
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier où seront écrits les résultats JSON
RUN mkdir -p /msf/results

# Par défaut, exécuter le script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
