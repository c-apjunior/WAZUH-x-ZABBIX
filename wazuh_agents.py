#!/usr/bin/env python3
import requests
import json
import argparse

# Configurações
API_URL = "https://x.x.x.x:55000"

#Usuário e senha da API 

USERNAME = ""
PASSWORD = ""

# Desativa warnings de SSL
requests.packages.urllib3.disable_warnings()

def get_token():
    url = f"{API_URL}/security/user/authenticate"
    response = requests.get(url, auth=(USERNAME, PASSWORD), verify=False)
    return response.json()["data"]["token"]

def get_agents(token):
    url = f"{API_URL}/agents"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, verify=False)
    return response.json()["data"]["affected_items"]

def build_lld(agents):
    data = []
    for agent in agents:
        os_info = agent.get("os", {})
        os_name = f"{os_info.get('name', '')} {os_info.get('version', '')}".strip()
        item = {
            "agent_id": agent.get("id"),
            "name_agent": agent.get("name"),
            "ip_agent": agent.get("ip"),
            "os_agent": os_name,
            "status_agent": agent.get("status")
        }
        data.append(item)
    return json.dumps({"data": data}, indent=4)

def build_filtered_agent_info(agents, agent_name):
    filtered = []
    for agent in agents:
        if agent.get("name", "").lower() == agent_name.lower():
            os_info = agent.get("os", {})
            os_name = f"{os_info.get('name', '')} {os_info.get('version', '')}".strip()
            item = {
                "agent_id": agent.get("id"),
                "name_agent": agent.get("name"),
                "ip_agent": agent.get("ip"),
                "os_agent": os_name,
                "status_agent": agent.get("status")
            }
            filtered.append(item)
    return json.dumps({"data": filtered}, indent=4) if filtered else json.dumps({"error": f"Agente '{agent_name}' não encontrado."}, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de consulta à API do Wazuh")
    parser.add_argument("-a", "--agent", help="Nome do agente específico para buscar")
    args = parser.parse_args()

    token = get_token()
    agents = get_agents(token)

    if args.agent:
        print(build_filtered_agent_info(agents, args.agent))
    else:

        print(build_lld(agents))
