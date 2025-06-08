import subprocess
import os
import re
import json

def generate_rc_file(ip, rc_template_path='scan_template.rc', rc_out_path='scan_auto.rc'):
    with open(rc_template_path, 'r') as f:
        content = f.read()
    content = content.replace('__TARGET_IP__', ip)
    with open(rc_out_path, 'w') as f:
        f.write(content)
    print(f"[+] Fichier RC généré avec IP: {ip}")
    return rc_out_path

def run_msfconsole(rc_path):
    print("[*] Lancement de Metasploit...")
    spool_path = 'results/spool.txt'
    os.makedirs('results', exist_ok=True)
    cmd = ['msfconsole', '-q', '-r', rc_path]
    with open(spool_path, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    print(f"[+] Metasploit terminé. Spool enregistré dans {spool_path}")
    return spool_path

def parse_spool_to_json(spool_path, json_out_path='results/msf_report.json'):
    with open(spool_path, 'r') as f:
        lines = f.readlines()

    results, exploits = [], []

    for line in lines:
        host = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
        port = re.search(r'Port: (\d+)/tcp', line)
        state = re.search(r'State: (\w+)', line)
        service = re.search(r'Service: (\w+)', line)
        exploit = re.search(r'\[\*\] Meterpreter session (\d+) opened.*?(\d+\.\d+\.\d+\.\d+)', line)
        user = re.search(r'Username\s+:\s+(\w+)', line)
        platform = re.search(r'Platform\s+:\s+(\w+)', line)

        if host and port and state:
            results.append({
                "host": host.group(1),
                "port": int(port.group(1)),
                "state": state.group(1),
                "service": service.group(1) if service else ""
            })

        if exploit:
            exploits.append({
                "exploit_module": "exploit/windows/smb/ms08_067_netapi",
                "payload": "windows/meterpreter/reverse_tcp",
                "status": "success",
                "session": {
                    "type": "meterpreter",
                    "session_id": int(exploit.group(1)),
                    "user": user.group(1) if user else "unknown",
                    "platform": platform.group(1) if platform else "unknown",
                    "host": exploit.group(2)
                }
            })

    final_output = {
        "scan_results": results,
        "exploit_results": exploits
    }

    with open(json_out_path, 'w') as f:
        json.dump(final_output, f, indent=2)

    print(f"[+] Rapport JSON généré : {json_out_path}")
    return final_output

def main():
    ip = os.environ.get("TARGET_IP") or input("Merci de saisir l'adresse IP cible pour le scan : ").strip()
    if not ip:
        print("❌ Adresse IP manquante. Abandon.")
        return

    rc_path = generate_rc_file(ip)
    spool_path = run_msfconsole(rc_path)
    parse_spool_to_json(spool_path)

if __name__ == "__main__":
    main()
