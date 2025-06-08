FROM metasploitframework/metasploit-framework:latest

RUN mkdir -p /msf/results

WORKDIR /msf

COPY run_msf_json.py /msf/

# Installer Python et pip via apk (Alpine Linux)
RUN apk update && apk add --no-cache python3 py3-pip && pip3 install pymetasploit3

ENTRYPOINT ["python3", "run_msf_json.py"]
