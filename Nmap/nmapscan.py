import nmap
import json
import sys
import os
import datetime

def main():
    if len(sys.argv) < 2:
        print("Usage : python nmapscan.py <ip_ou_nom_domaine>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = nmap.PortScanner()

    # Options complètes avec TCP connect pour compatibilité Docker
    options = "-sT -sV -O -A -p 1-1000"

    print(f"🔍 Scan en cours sur {target} avec options : {options}...")

    try:
        scanner.scan(target, arguments=options)
    except Exception as e:
        print(f"❌ Erreur pendant le scan : {e}")
        sys.exit(1)

    if not scanner.all_hosts():
        print(f"⚠️ Aucun résultat pour {target}. Cible injoignable ou tous ports filtrés.")
        sys.exit(1)

    results = {}
    for host in scanner.all_hosts():
        host_info = {
            "state": scanner[host].state(),
            "hostname": scanner[host].hostname(),
            "protocols": {},
            "osmatch": scanner[host].get('osmatch', [])
        }

        for proto in scanner[host].all_protocols():
            ports_info = {}
            for port in scanner[host][proto]:
                ports_info[port] = {
                    "state": scanner[host][proto][port]['state'],
                    "name": scanner[host][proto][port].get('name', ''),
                    "product": scanner[host][proto][port].get('product', ''),
                    "version": scanner[host][proto][port].get('version', ''),
                    "extrainfo": scanner[host][proto][port].get('extrainfo', ''),
                    "reason": scanner[host][proto][port].get('reason', ''),
                    "conf": scanner[host][proto][port].get('conf', '')
                }
            host_info["protocols"][proto] = ports_info

        results[host] = host_info

    # Affichage direct dans la console (formaté)
    print("\n✅ Résultat JSON formaté :\n")
    print(json.dumps(results, indent=2))

    # Sauvegarde dans un fichier
    os.makedirs("/app/results", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = f"/app/results/result-{target.replace('.', '_')}-{timestamp}.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Résultat sauvegardé dans : {output_file}")

if __name__ == "__main__":
    main()
