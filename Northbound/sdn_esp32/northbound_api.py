# --- Northbound API (O "Mensageiro" ou "Proxy") ---
#
# ARQUITETURA:
# Este script representa a API Northbound do sistema. Ele tem um papel crucial
# de atuar como um intermediário seguro e desacoplado entre o Plano de Aplicação
# (o ESP32) e o Plano de Controle (o Controlador Ryu).
#
# RESPONSABILIDADES:
# 1. RECEBER: Aceitar requisições HTTP do ESP32 contendo as decisões de segurança.
# 2. VALIDAR: Garantir que a requisição é legítima, verificando uma chave de API.
# 3. REENVIAR (PROXY): Repassar a ordem de forma imediata para a API interna do Ryu.
# 4. ABSTRAIR: O ESP32 só precisa conhecer o endereço deste "mensageiro", ele não
#    precisa saber onde o Ryu está. Isso torna o sistema mais flexível.

from flask import Flask, request, jsonify
import requests  # Biblioteca essencial para fazer a requisição HTTP para o Ryu.
import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente de um arquivo .env.
# Isso é uma boa prática para não deixar senhas e URLs fixas no código.
load_dotenv()
app = Flask(__name__)

# --- Configuração dos Endereços e Chaves ---

# O endereço da API interna do próprio Ryu.
# O script Flask vai enviar os dados para este endereço.
# Usar 'localhost' (ou 127.0.0.1) é ideal quando o Flask e o Ryu rodam na mesma máquina.
# Se estivessem em máquinas diferentes, aqui iria o IP da máquina do Ryu.
RYU_API_URL = os.environ.get('RYU_API_URL', 'http://localhost:8080/firewall/rules')

# Chave de API secreta para autenticar as requisições que vêm do ESP32.
# Isso impede que qualquer dispositivo na rede possa enviar regras para o seu firewall.
EXPECTED_API_KEY = os.environ.get('API_KEY')

# --- Rota Principal da API ---
@app.route('/firewall/rules', methods=['POST'])
def forward_firewall_rules():
    """
    Esta função é o coração da API. Ela é acionada toda vez que o ESP32 envia
    um POST para /firewall/rules.
    """
    
    # ETAPA 1: SEGURANÇA - Validar a requisição vinda do ESP32.
    # Verifica se o cabeçalho 'X-API-Key' enviado pelo ESP32 corresponde ao esperado.
    api_key = request.headers.get('X-API-Key')
    if api_key != EXPECTED_API_KEY:
        print(f"Tentativa de acesso com chave de API inválida: {api_key}")
        return jsonify({"error": "Não autorizado"}), 401 # 401 Unauthorized
    
    # ETAPA 2: VALIDAÇÃO DOS DADOS - Garantir que o JSON está no formato correto.
    data = request.get_json()
    if not data or 'rules' not in data:
        return jsonify({"error": "Formato inválido. Esperado: { 'rules': [...] }"}), 400 # 400 Bad Request

    print(f"Regras recebidas do ESP32: {data}")

    # ETAPA 3: AÇÃO PRINCIPAL (PROXY) - Reenviar as regras para a API do Ryu.
    try:
        print(f"Reenviando regras para o Ryu em {RYU_API_URL}...")
        
        # Faz a requisição POST para o Ryu, passando exatamente o mesmo JSON recebido.
        # O timeout é uma salvaguarda para não travar se o Ryu demorar muito para responder.
        response = requests.post(RYU_API_URL, json=data, timeout=5)

        # Esta linha é muito útil: ela gera um erro automaticamente se o Ryu responder
        # com um código de falha (como 4xx ou 5xx). O erro será capturado pelo 'except'.
        response.raise_for_status() 

        print("Ryu processou as regras com sucesso.")
        # Se tudo deu certo, retorna a mesma resposta do Ryu para o ESP32.
        return jsonify(response.json()), response.status_code

    # --- Tratamento de Erros de Conexão ---
    except requests.exceptions.RequestException as e:
        # Este bloco é executado se houver um problema de rede ao tentar falar com o Ryu
        # (ex: o Ryu não está rodando, o IP está errado, a rede caiu).
        print(f"ERRO: Não foi possível conectar ao controlador Ryu: {e}")
        return jsonify({"error": "Falha ao contatar o controlador Ryu"}), 503 # 503 Service Unavailable

    # --- Tratamento de Outros Erros ---
    except Exception as e:
        # Este bloco captura qualquer outro erro inesperado que possa acontecer.
        print(f"ERRO inesperado: {e}")
        return jsonify({"error": "Erro interno no servidor"}), 500 # 500 Internal Server Error

# --- Bloco de Execução Principal ---
if __name__ == '__main__':
    # Inicia o servidor Flask.
    # 'host="0.0.0.0"' é crucial: significa que o servidor irá aceitar conexões
    # de qualquer interface de rede, permitindo que o ESP32 (que está na rede Wi-Fi)
    # consiga se conectar. Se usássemos 'localhost', apenas conexões da própria
    # máquina seriam aceitas.
    app.run(host='0.0.0.0', port=5000)
