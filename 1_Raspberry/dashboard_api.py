# =================================================================================
# ||   Orquestrador Central SDN v3.0                                            ||
# =================================================================================
import asyncio
import websockets
import threading
import json
import requests
import subprocess
import random
import time
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os

#  Configuração do Flask App
# Garante que o Flask encontre os arquivos 'templates' e 'static' corretamente.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)  # Permite que o painel web (outra origem) acesse esta API

# Configuração dos Endereços e Portas
# IP do ESP32 que atua como Controlador e armazena as regras
CONTROLLER_IP = "192.168.4.1"
CONTROLLER_API_URL = f"http://{CONTROLLER_IP}/firewall/rules"
WEBSOCKET_PORT = 81

# Estado Global e Gerenciamento de Threads
# Armazena os clientes WebSocket (dispositivos e painéis de controle)
connected_devices = set()
# Referência ao loop de eventos assíncronos para ser acessado por outras threads
main_event_loop = None
# Flags para controle do ataque
attacking = False
attack_process = None

# Lógica do Servidor WebSocket (Comunicação com o ESP32-Switch)

# Função para enviar mensagens para todos os Switches conectados
async def broadcast_to_devices(message):
    if connected_devices:
        # Envia a mensagem para cada switch na lista de conexões ativas
        await asyncio.wait([ws.send(message) for ws in connected_devices])


# Handler principal para novas conexões WebSocket
async def websocket_handler(websocket, path):
    print("[WSc] Novo cliente conectado...")
    connected_devices.add(websocket)
    try:
        # Mantém a conexão viva, escutando por mensagens (não esperamos nenhuma por enquanto)
        async for message in websocket:
            print(f"[WSc] Mensagem recebida do Switch: {message}")
    except websockets.exceptions.ConnectionClosed:
        print("[WSc] Cliente desconectado.")
    finally:
        # Remove o cliente da lista ao desconectar
        connected_devices.remove(websocket)


# Função para iniciar o servidor WebSocket em seu próprio loop de eventos
async def start_websocket_server():
    global main_event_loop
    main_event_loop = asyncio.get_running_loop()
    async with websockets.serve(websocket_handler, "0.0.0.0", WEBSOCKET_PORT):
        print(f"[+] Servidor WebSocket iniciado na porta {WEBSOCKET_PORT}")
        await asyncio.Future()  # Mantém o servidor rodando para sempre


# Lógica do Servidor HTTP Flask (API para o Painel Web)

@app.route('/')
def dashboard():
    """ Rota principal que serve o painel de controle. """
    return render_template('index.html')


@app.route('/ui/get_rules', methods=['GET'])
def get_rules_proxy():
    print("[API] Recebida solicitação para listar regras. Contatando o Controlador...")
    try:
        # O Raspberry Pi faz a requisição GET para o ESP32-Controlador
        response = requests.get(CONTROLLER_API_URL, timeout=5)
        response.raise_for_status()  # Lança um erro se a resposta for 4xx ou 5xx

        print(f"[API] Resposta do Controlador recebida: {response.status_code}")
        # Repassa a resposta do Controlador de volta para o Painel Web
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERRO] Falha ao contatar o ESP32-Controlador: {e}")
        return jsonify({"error": "Não foi possível conectar ao controlador", "rules": []}), 500


@app.route('/ui/add_rule', methods=['POST'])
def add_rule_proxy():
    try:
        rule_data = request.get_json()
        print(f"[API] Recebida solicitação para adicionar regra: {rule_data}")

        # 1. Envia a regra para o ESP32-Controlador para ser salva
        try:
            response_controller = requests.post(CONTROLLER_API_URL, json=rule_data, timeout=5)
            response_controller.raise_for_status()
            print("[API] Regra enviada com sucesso para o Controlador (via HTTP).")
        except requests.exceptions.RequestException as e:
            print(f"[ERRO] Falha ao enviar regra para o Controlador: {e}")
            # Mesmo com falha, continua para tentar avisar o Switch

        # 2. Envia a regra para o(s) ESP32-Switch(es) via WebSocket
        if connected_devices:
            # Usa uma forma segura para agendar a tarefa assíncrona a partir de uma thread síncrona
            asyncio.run_coroutine_threadsafe(broadcast_to_devices(json.dumps(rule_data)), main_event_loop)
            print("[API] Comando de regra transmitido para os Switches (via WebSocket).")
        else:
            print("[API] Nenhum Switch conectado ao WebSocket para receber a regra.")

        return jsonify({"status": "Regra processada"}), 200

    except Exception as e:
        print(f"[ERRO] Erro inesperado ao adicionar regra: {e}")
        return jsonify({"error": str(e)}), 500


# Rotas de Ataque
def ping_flood_worker(target_ip):
    global attacking, attack_process
    print(f"[ATAQUE] Iniciando Ping Flood em {target_ip}")
    # Usamos '-i 0.01' para um flood rápido e '-w' para um timeout, se o alvo parar de responder
    command = ["sudo", "ping", "-i", "0.01", "-w", "300", target_ip]
    attack_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    while attacking:
        if attack_process.poll() is not None:
            break
        time.sleep(0.5)

    if attack_process.poll() is None:
        attack_process.terminate()

    attacking = False
    print("[ATAQUE] Ping Flood finalizado.")


@app.route('/attack/ping_flood', methods=['POST'])
def start_ping_flood():
    global attacking, attack_thread
    if attacking:
        return jsonify({"status": "Ataque já em andamento"}), 409

    target_ip = request.json.get('target_ip')
    if not target_ip:
        return jsonify({"error": "IP alvo ausente"}), 400

    attacking = True
    attack_thread = threading.Thread(target=ping_flood_worker, args=(target_ip,), daemon=True)
    attack_thread.start()

    return jsonify({"status": f"Ataque iniciado em {target_ip}"}), 200


@app.route('/attack/stop', methods=['POST'])
def stop_attack():
    global attacking, attack_process
    if attacking:
        attacking = False
        if attack_process:
            attack_process.terminate()  # Força o término do processo de ping
        print("[API] Comando para parar ataque recebido.")
        return jsonify({"status": "Ataque parado com sucesso"})
    return jsonify({"status": "Nenhum ataque em andamento"})


@app.route('/attack/spoof_mac', methods=['POST'])
def spoof_mac():
    iface = request.json.get('iface', 'wlan0')
    new_mac = (f"02:00:00:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:"
               f"{random.randint(0, 255):02x}")
    try:
        print(f"[ATAQUE] Trocando MAC da interface {iface} para {new_mac}")
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True, timeout=10)
        subprocess.run(["sudo", "ifconfig", iface, "hw", "ether", new_mac], check=True, timeout=10)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True, timeout=10)
        return jsonify({"status": "MAC spoofado com sucesso", "new_mac": new_mac})
    except Exception as e:
        print(f"[ERRO] Falha no MAC Spoofing: {e}")
        return jsonify({"error": str(e)}), 500

# Inicialização dos Servidores

def run_flask_app():
    # Roda o Flask em modo de produção para melhor desempenho e estabilidade
    print("[+] Iniciando servidor Flask...")
    app.run(host='0.0.0.0', port=5000)


if __name__ == '__main__':
    print("=== ORQUESTRADOR CENTRAL SDN v3.0 ===")

    # Inicia o Flask em uma thread separada para não bloquear o WebSocket
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()

    # Inicia o servidor WebSocket no processo principal
    try:
        asyncio.run(start_websocket_server())
    except KeyboardInterrupt:
        print("\n[+] Encerrando servidores...")
    except OSError as e:
        print(
            f"\n[ERRO] Falha ao iniciar servidor WebSocket na porta {WEBSOCKET_PORT}"
            f"A porta já está em uso? Detalhes: {e}")