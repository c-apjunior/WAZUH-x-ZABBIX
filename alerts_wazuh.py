#!/usr/bin/env python3

import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

# Suprimir warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurações
WAZUH_INDEXER_URL = "https://x.x.x.x.:9200/wazuh-alerts-4.x-*/_search"

## Credencial configurada no Wazuh 

USERNAME = ""
PASSWORD = ""

# Query para pegar alertas rule.level >= 9 nas últimas 1 hora
query = {
    "query": {
        "bool": {
            "must": [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"timestamp": {"gte": "now-1h"}}}
            ]
        }
    },
    "size": 50,
    "sort": [{"timestamp": {"order": "desc"}}]
}

def get_recent_alerts():
    try:
        response = requests.get(
            WAZUH_INDEXER_URL,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False  # continua desativando verificação SSL
        )

        if response.status_code == 200:
            results = response.json()
            hits = results.get("hits", {}).get("hits", [])

            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                rule = source.get("rule", {})
                agent = source.get("agent", {})
                alerts.append({
                    "description": rule.get("description", "Sem descrição"),
                    "id": hit.get("_id", ""),  # Adiciona o campo id do alerta
                    "rule_level": rule.get("level"),
                    "agent_name": agent.get("name", "Desconhecido"),
                    "timestamp": source.get("timestamp")
                })

            output = {
                "data": alerts
            }
            print(json.dumps(output, indent=2, ensure_ascii=False))
        else:
            print(json.dumps({
                "error": response.status_code,
                "message": response.text
            }, indent=2, ensure_ascii=False))

    except Exception as e:
        print(json.dumps({
            "error": "exception",
            "message": str(e)
        }, indent=2, ensure_ascii=False))

if __name__ == "__main__":

    get_recent_alerts()
