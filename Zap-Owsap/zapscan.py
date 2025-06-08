import os
import sys
import time
from zapv2 import ZAPv2
import datetime
import json

def main():
    if len(sys.argv) < 2:
        print("❌ Usage : docker run ... <target_url>")
        sys.exit(1)

    target = sys.argv[1]

    zap_api_key = os.getenv("ZAP_API_KEY", "")
    zap_host = os.getenv("ZAP_HOST", "zap")  # host du service ZAP (nom docker ou localhost)
    zap_port = os.getenv("ZAP_PORT", "8080")

    zap = ZAPv2(apikey=zap_api_key,
                proxies={"http": f"http://{zap_host}:{zap_port}",
                         "https": f"http://{zap_host}:{zap_port}"})

    print(f"▶️ Début du scan OWASP ZAP sur la cible : {target}")

    zap.urlopen(target)
    print("⏳ Attente que la cible soit accessible...")
    time.sleep(5)

    print("🚀 Lancement du scan actif...")
    scan_id = zap.ascan.scan(target)

    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"🔄 Progression du scan : {progress}%")
        time.sleep(5)

    print("✅ Scan actif terminé. Récupération des résultats...")

    alerts = zap.core.alerts(baseurl=target)

    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"/app/results/zap-result-{safe_target}-{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"💾 Rapport sauvegardé dans : {filename}")

if __name__ == "__main__":
    main()
