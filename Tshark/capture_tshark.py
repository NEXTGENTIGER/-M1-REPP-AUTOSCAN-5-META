import subprocess
import json
import sys
import os
import datetime

def main():
    # Vérifie argument interface (ex : eth0)
    if len(sys.argv) < 2:
        print("Usage: python capture_tshark.py <interface> [nombre_paquets]")
        sys.exit(1)

    interface = sys.argv[1]
    packet_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10  # par défaut 10 paquets

    output_file = f"results/tshark_capture_{interface}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    os.makedirs("results", exist_ok=True)

    # Commande tshark pour capturer et exporter en JSON
    cmd = [
        "tshark",
        "-i", interface,
        "-c", str(packet_count),       # nombre de paquets à capturer
        "-T", "json",                  # output format JSON
    ]

    print(f"Capture de {packet_count} paquets sur {interface}...")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets_json = json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Erreur tshark : {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Erreur décodage JSON : {e}")
        sys.exit(1)

    # Sauvegarde dans un fichier
    with open(output_file, "w") as f:
        json.dump(packets_json, f, indent=2)

    print(f"Capture terminée. Résultats sauvegardés dans : {output_file}")

    # Affiche un résumé simple (nombre de paquets capturés)
    print(f"Nombre de paquets capturés : {len(packets_json)}")

if __name__ == "__main__":
    main()
