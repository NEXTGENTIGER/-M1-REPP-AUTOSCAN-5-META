# ./Metasploit/Dockerfile
FROM metasploitframework/metasploit-framework:latest

# Créer un dossier pour les résultats
RUN mkdir -p /msf/results

# Définir le répertoire de travail
WORKDIR /msf

# Copier le script d'exploitation dans l'image
COPY run_msf_json.py /msf/

# Commande par défaut (modifiable)
ENTRYPOINT ["ruby"]
