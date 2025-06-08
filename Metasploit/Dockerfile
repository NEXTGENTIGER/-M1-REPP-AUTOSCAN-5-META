FROM metasploitframework/metasploit-framework:latest

USER root

# Met à jour les dépôts apk et installe python3, pip, bash et postgresql-client
RUN sed -i 's|dl-cdn.alpinelinux.org|dl-4.alpinelinux.org|g' /etc/apk/repositories && \
    apk update && apk add --no-cache \
    python3 \
    py3-pip \
    postgresql-client \
    bash

# Installe les dépendances Python
RUN pip3 install --no-cache-dir xmltodict

WORKDIR /app

# Copier le script Python et le template RC dans le conteneur
COPY msf_auto_scan.py /app/msf_auto_scan.py
COPY metasploit/scan_template.rc /app/metasploit/scan_template.rc

# Expose éventuellement le port RPC si tu l’utilises (optionnel)
# EXPOSE 55553

# Lancement par défaut : exécute ton script Python qui gère le scan avec Metasploit
CMD ["python3", "/app/msf_auto_scan.py"]
