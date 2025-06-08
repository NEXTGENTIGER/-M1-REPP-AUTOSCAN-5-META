FROM metasploitframework/metasploit-framework:latest

USER root

RUN apk update && apk add --no-cache python3 py3-pip bash
RUN pip3 install --no-cache-dir xmltodict

WORKDIR /msf
COPY metasploit_scan.py scan_template.rc ./
RUN mkdir -p /msf/results

ENTRYPOINT ["python3", "metasploit_scan.py"]
