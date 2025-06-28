# --- Northbound API ---

from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv

load_dotenv()  # Carrega as variáveis do .env automaticamente
app = Flask(__name__)

# Definindo o endereço da API interna do Ryu
# Se o Flask e o Ryu rodam na mesma máquina podemos usar o localhost
RYU_API_URL = os.environ.get('RYU_API_URL', 'http://localhost:8080/firewall/rules')

# Chave de API para validar a requisição vinda do ESP32
# Deve ser a mesma que está no firmware
EXPECTED_API_KEY = os.environ.get('API_KEY')

@app.route('/firewall/rules', methods=['POST'])
def forward_firewall_rules():
    # 1. Validar a requisição vinda do ESP32
    api_key = request.headers.get('X-API-Key')
    if api_key != EXPECTED_API_KEY:
        print(f"Tentativa de acesso com chave de API inválida: {api_key}")
        return jsonify({"error": "Não autorizado"}), 401
    
    # 2. Obter o JSON enviado pelo ESP32
    data = request.get_json()
    if not data or 'rules' not in data:
        return jsonify({"error": "Formato inválido. Esperado: { 'rules': [...] }"}), 400

    print(f"Regras recebidas do ESP32: {data}")

    # 3. Reenviar as regras para a API do Ryu
    try:
        print(f"Reenviando regras para o Ryu em {RYU_API_URL}...")
        
        # O timeout é uma boa prática para não deixar a requisição presa indefinidamente
        response = requests.post(RYU_API_URL, json=data, timeout=5)

        # Verifica se o Ryu respondeu com sucesso (código 2xx)
        response.raise_for_status() 

        print("Ryu processou as regras com sucesso.")
        # Retorna a resposta do Ryu para o ESP32
        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        print(f"ERRO: Não foi possível conectar ao controlador Ryu: {e}")
        return jsonify({"error": "Falha ao contatar o controlador Ryu"}), 503 # Service Unavailable

    except Exception as e:
        print(f"ERRO inesperado: {e}")
        return jsonify({"error": "Erro interno no servidor"}), 500

if __name__ == '__main__':
    # Garanta que o Flask rode em um IP acessível na sua rede (0.0.0.0)
    app.run(host='0.0.0.0', port=5000)