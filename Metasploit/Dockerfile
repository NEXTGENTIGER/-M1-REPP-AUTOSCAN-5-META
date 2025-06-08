FROM metasploitframework/metasploit-framework:latest

# Installer Python + pip + dépendances
RUN apk add --no-cache python3 py3-pip && \
    pip3 install pymetasploit3

# Dossier de scan + résultats
WORKDIR /msf
COPY . /msf
