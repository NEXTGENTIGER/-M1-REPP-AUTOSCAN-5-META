FROM metasploitframework/metasploit-framework:latest

USER root

RUN sed -i 's|dl-cdn.alpinelinux.org|dl-4.alpinelinux.org|g' /etc/apk/repositories && \
    apk update && apk add --no-cache \
    python3 \
    py3-pip \
    postgresql-client \
    bash

# Fix : rendre msfconsole globalement accessible
RUN ln -s /opt/metasploit-framework/msfconsole /usr/local/bin/msfconsole

RUN pip install xmltodict jinja2

WORKDIR /app

COPY metasploit_scan.py /app/metasploit_scan.py
COPY scan_template.rc /app/scan_template.rc

ENTRYPOINT ["python3", "metasploit_scan.py"]
