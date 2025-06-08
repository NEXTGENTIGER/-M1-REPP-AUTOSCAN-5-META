FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Installer dépendances système + ruby
RUN apt-get update && \
    apt-get install -y \
    curl gnupg2 postgresql git-core ruby ruby-dev libpq-dev \
    build-essential libreadline-dev libssl-dev zlib1g-dev \
    libxml2-dev libxslt1-dev libyaml-dev libsqlite3-dev sqlite3 \
    libgmp-dev autoconf libtool libffi-dev python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Installer Metasploit Framework
RUN git clone https://github.com/rapid7/metasploit-framework /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler && \
    bundle install

ENV PATH="/opt/metasploit-framework:$PATH"

WORKDIR /msf

# Copier les scripts dans le conteneur
COPY metasploit_scan.py scan_template.rc ./
RUN mkdir -p /msf/results

ENTRYPOINT ["python3", "metasploit_scan.py"]
