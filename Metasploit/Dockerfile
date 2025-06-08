# Utiliser Kali Linux (rolling) pour avoir metasploit-framework
FROM kalilinux/kali-rolling

USER root
ENV DEBIAN_FRONTEND=noninteractive

# Mettre à jour et installer Metasploit + Python
RUN apt-get update && \
    apt-get install -y metasploit-framework python3 python3-pip bash && \
    rm -rf /var/lib/apt/lists/*

# Installer dépendances Python supplémentaires
RUN pip3 install --no-cache-dir xmltodict

# Définir le dossier de travail
WORKDIR /msf

# Copier le script Python et le template RC
COPY metasploit_scan.py scan_template.rc ./

# Créer le dossier pour les résultats
RUN mkdir -p /msf/results

# Entrypoint : lancer ton script Python
ENTRYPOINT ["python3", "metasploit_scan.py"]
