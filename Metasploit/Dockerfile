FROM metasploitframework/metasploit-framework:latest

WORKDIR /msf

RUN apt-get update && apt-get install -y python3 python3-pip

COPY metasploit_scan.py scan_template.rc ./
RUN mkdir -p /msf/results

ENTRYPOINT ["python3", "metasploit_scan.py"]
