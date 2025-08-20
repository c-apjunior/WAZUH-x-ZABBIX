# WAZUH-x-ZABBIX
Integração Wazuh com Zabbix
📌 Visão Geral

Esta integração permite que o Zabbix consuma alertas do Wazuh (SIEM/IDS) via script externo.
O objetivo é centralizar os alertas de segurança no Zabbix para monitoramento, correlação e abertura de incidentes.

⚙️ Arquitetura

O Wazuh gera alertas e os disponibiliza via API REST.

Um script Python (alerts_wazuh.py) coleta os dados da API e retorna em formato JSON.

O Zabbix Server executa o script em ExternalScripts e processa os resultados.

Os alertas são tratados por itens dependentes e LLD (Low-Level Discovery).


````

📂 Estrutura de Arquivos

/usr/lib/zabbix/externalscripts/
 └── alerts_wazuh.py

````

🔑 Pré-requisitos

Wazuh configurado e acessível via API.

Token de autenticação válido do Wazuh.

Zabbix Server instalado com suporte a scripts externos.

Python 3 disponível no servidor Zabbix.

🚀 Instalação

Copie o script para o diretório de ExternalScripts do Zabbix:

````
cp alerts_wazuh.py /usr/lib/zabbix/externalscripts/
chmod +x /usr/lib/zabbix/externalscripts/alerts_wazuh.py

````

Teste manualmente o script:

````
python3 /usr/lib/zabbix/externalscripts/alerts_wazuh.py

````

Configure no Zabbix Server o caminho para ExternalScripts no arquivo zabbix_server.conf (se necessário):
````
ExternalScripts=/usr/lib/zabbix/externalscripts

````

Reinicie o Zabbix Server:

systemctl restart zabbix-server

📊 Configuração no Zabbix

Crie um item mestre que execute o script:

Tipo: External check

Key: alerts_wazuh.py

Crie itens dependentes para extrair informações, por exemplo:

Último nível de alerta por agente:

````

$.data[?(@.agent_name=='{#AGENT_NAME}')].rule_level

````

Última descrição de alerta:

````
$.data[?(@.agent_name=='{#AGENT_NAME}')].description

````

Configure LLD (Low-Level Discovery) para criar dinamicamente os agentes a partir do campo agent_name.

Configure triggers para identificar eventos críticos, por exemplo:

Se rule_level >= 10 → gerar incidente de segurança.
````

🛡️ Exemplo de Saída JSON
{
  "data": [
    {
      "description": "Multiple System error events",
      "id": "IOE_x5gBUbzaJF2Dnx8-",
      "rule_level": 10,
      "agent_name": "CJ_NOTE",
      "timestamp": "2025-08-20T11:31:27.938+0000"
    },
    {
      "description": "Windows application error event.",
      "id": "FeE_x5gBUbzaJF2Dnx8-",
      "rule_level": 9,
      "agent_name": "CJ_NOTE",
      "timestamp": "2025-08-20T11:31:27.485+0000"
    }
  ]
}

````

✅ Benefícios

Correlação de eventos de segurança diretamente no Zabbix.

Redução de pontos cegos entre monitoramento e segurança.

Centralização de alertas de diferentes agentes em uma única plataforma.

