import os
import time
import json
import xmltodict
import subprocess
from jinja2 import Template

def generate_rc_file(target_ip, rc_path, template_path):
    with open(template_path) as f:
        template = Template(f.read())
    rendered = template.render(target_ip=target_ip)
    with open(rc_path, "w") as f:
        f.write(rendered)
    print(f"[+] scan_auto.rc généré pour {target_ip}")

def run_msfconsole(rc_path, spool_path):
    print("[*] Lancement de msfconsole...")
    cmd = ["msfconsole", "-q", "-r", rc_path]
    subprocess.run(cmd)

def parse_spool(spool_path):
    result = {
        "target": os.environ["TARGET_IP"],
        "scans": [],
        "exploits": []
    }
    try:
        with open(spool_path, "r") as f:
            lines = f.readlines()
        for line in lines:
            if "[+] " in line:
                result["scans"].append(line.strip())
            if "[*] " in line and "Exploit" in line:
                result["exploits"].append(line.strip())
    except FileNotFoundError:
        print("[!] spool.txt introuvable")
    return result

def main():
    target_ip = os.environ.get("TARGET_IP")
    if not target_ip:
        print("[!] TARGET_IP non défini")
        return

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    rc_path = "/app/scan_auto.rc"
    template_path = "/app/scan_template.rc"
    spool_path = "/app/results/spool.txt"
    json_path = f"/app/results/result-{target_ip.replace('.', '_')}-{timestamp}.json"

    generate_rc_file(target_ip, rc_path, template_path)
    run_msfconsole(rc_path, spool_path)
    print(f"[+] Spool enregistré : {spool_path}")

    result = parse_spool(spool_path)
    with open(json_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Rapport JSON écrit : {json_path}")

if __name__ == "__main__":
    main()
