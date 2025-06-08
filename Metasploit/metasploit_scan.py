import os
import subprocess
import re
import json
import datetime

BASE = "/msf"
TEMPLATE_RC = os.path.join(BASE, "scan_template.rc")
AUTO_RC     = os.path.join(BASE, "scan_auto.rc")
RESULTS_DIR = os.path.join(BASE, "results")

def generate_rc(ip):
    with open(TEMPLATE_RC) as f:
        txt = f.read()
    txt = txt.replace("__TARGET_IP__", ip)
    with open(AUTO_RC, "w") as f:
        f.write(txt)
    print(f"[+] scan_auto.rc généré pour {ip}")
    return AUTO_RC

def run_msf(rc):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    spool = os.path.join(RESULTS_DIR, "spool.txt")
    print("[*] Lancement de msfconsole...")
    cmd = ["msfconsole", "-q", "-r", rc]
    with open(spool, "w") as out:
        subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT)
    print(f"[+] Spool écrit dans {spool}")
    return spool

def parse(spool, ip):
    with open(spool) as f:
        lines = f.readlines()
    scans, exploits = [], []
    for l in lines:
        h = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', l)
        p = re.search(r'Port: (\d+)/tcp', l)
        s = re.search(r'State: (\w+)', l)
        ex = re.search(r'\[\*\] Meterpreter session (\d+) opened.*?(\d+\.\d+\.\d+\.\d+)', l)
        if h and p and s:
            scans.append({
                "host": h.group(1),
                "port": int(p.group(1)),
                "state": s.group(1)
            })
        if ex:
            exploits.append({
                "session": int(ex.group(1)),
                "host": ex.group(2)
            })
    report = {
        "target": ip,
        "scan": scans,
        "exploits": exploits
    }
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outj = os.path.join(RESULTS_DIR, f"result-{ip.replace('.', '_')}-{ts}.json")
    with open(outj, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Rapport JSON dans {outj}")
    return outj

def main():
    ip = os.environ.get("TARGET_IP")
    if not ip:
        print("❌ Pas de TARGET_IP !"); return
    rc = generate_rc(ip)
    spool = run_msf(rc)
    parse(spool, ip)

if __name__=="__main__":
    main()
