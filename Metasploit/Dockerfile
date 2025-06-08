FROM metasploitframework/metasploit-framework:latest

RUN mkdir -p /msf/results

WORKDIR /msf

COPY run_msf_json.py /msf/

# Installer Python + dépendances
RUN apt-get update && apt-get install -y python3 python3-pip && \
    pip3 install pymetasploit3

ENTRYPOINT ["python3", "run_msf_json.py"]
