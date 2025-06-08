#!/usr/bin/env python3
import os
import subprocess
import re
import json
import datetime
import socket

# Répertoires et chemins
BASE_DIR     = "/app"
TEMPLATE_RC  = os.path.join(BASE_DIR, "scan_template.rc")
AUTO_RC      = os.path.join(BASE_DIR, "scan_auto.rc")
RESULTS_DIR  = os.path.join(BASE_DIR, "results")

def get_local_ip():
    """Détecte automatiquement l’IP locale de la machine/containeur."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connexion à un IP externe pour déterminer l'interface utilisée
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def generate_rc(ip):
    """Génère scan_auto.rc à partir du template, remplace __TARGET_IP__ et __LHOST__."""
    with open(TEMPLATE_RC, 'r') as f:
        content = f.read()

    local_ip = os.environ.get("LHOST") or get_local_ip()

    content = content.replace("__TARGET_IP__", ip)
    content = content.replace("__LHOST__", local_ip)

    with open(AUTO_RC, 'w') as f:
        f.write(content)
    print(f"[+] scan_auto.rc généré pour {ip} avec LHOST={local_ip}")
    return AUTO_RC

def run_msfconsole(rc_path, timeout=None):
    """Lance msfconsole avec le .rc généré et enregistre le spool."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    spool_file = os.path.join(RESULTS_DIR, "spool.txt")
    print("[*] Lancement de msfconsole...")

    cmd = [
        "/usr/src/metasploit-framework/msfconsole",
        "-q",
        "-r", rc_path
    ]

    with open(spool_file, 'w') as out:
        try:
            if timeout:
                subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
            else:
                subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout: msfconsole arrêté après {timeout} secondes")
    print(f"[+] Spool enregistré : {spool_file}")
    return spool_file

def parse_spool_to_json(spool_path, ip):
    """Parse le spool.txt pour extraire scans et exploits, puis génère un JSON."""
    with open(spool_path, 'r') as f:
        lines = f.readlines()

    scans = []
    exploits = []
    for line in lines:
        h = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
        p = re.search(r'Port: (\d+)/tcp', line)
        s = re.search(r'State: (\w+)', line)
        m = re.search(r'\[\*\] Meterpreter session (\d+) opened.*?(\d+\.\d+\.\d+\.\d+)', line)

        if h and p and s:
            scans.append({
                "host": h.group(1),
                "port": int(p.group(1)),
                "state": s.group(1)
            })
        if m:
            exploits.append({
                "session_id": int(m.group(1)),
                "host": m.group(2)
            })

    report = {
        "target": ip,
        "scans": scans,
        "exploits": exploits
    }
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_json = os.path.join(RESULTS_DIR, f"result-{ip.replace('.', '_')}-{ts}.json")
    with open(out_json, 'w') as jf:
        json.dump(report, jf, indent=2)
    print(f"[+] Rapport JSON écrit : {out_json}")
    return out_json

def main():
    ip = os.environ.get("TARGET_IP")
    if not ip:
        print("❌ Variable TARGET_IP non définie. Abandon.")
        return

    rc = generate_rc(ip)
    # Timeout à 120 secondes (2 minutes), à ajuster ou None pour sans limite
    spool = run_msfconsole(rc, timeout=120)
    parse_spool_to_json(spool, ip)

if __name__ == "__main__":
    main()
