FROM metasploitframework/metasploit-framework:latest

WORKDIR /msf

COPY metasploit_scan.py scan_template.rc ./
RUN mkdir -p /msf/results

ENTRYPOINT ["python3", "metasploit_scan.py"]
