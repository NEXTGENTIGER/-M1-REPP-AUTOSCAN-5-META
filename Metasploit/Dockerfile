# Utilise Ubuntu 20.04 LTS (métasploit et msfconsole disponibles)
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Installer Metasploit Framework et Python
RUN apt-get update && \
    apt-get install -y metasploit-framework python3 python3-pip bash && \
    rm -rf /var/lib/apt/lists/*

# Installer dépendances Python
RUN pip3 install --no-cache-dir xmltodict

# Définir le dossier de travail
WORKDIR /msf

# Copier le script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier pour les résultats
RUN mkdir -p /msf/results

# Point d'entrée : lance ton script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
