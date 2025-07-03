# --- API de ataques para o Raspberry Pi 3 ---
#
# ARQUITETURA:
# Este script transforma o Raspberry Pi em uma ferramenta de teste de segurança (pentest).
# Ele cria uma API web simples que permite, com um clique, lançar diferentes tipos de
# ataques simulados contra a sua rede.
#
# RESPONSABILIDADES:
# 1. SERVIR UMA INTERFACE WEB: Fornecer uma página HTML simples com botões para
#    iniciar e parar os ataques.
# 2. EXECUTAR ATAQUES: Lançar ataques de rede, como Ping Flood (um tipo de DoS)
#    e MAC Spoofing, quando solicitado pela interface web.
# 3. VALIDAR O FIREWALL: O objetivo principal deste script é testar se o seu
#    firewall inteligente (o ESP32) consegue DETECTAR esses ataques e se o
#    controlador Ryu consegue BLOQUEAR o tráfego do Raspberry Pi como resultado.

from flask import Flask, request, jsonify, render_template  # Adiciona render_template para servir a página HTML.
import threading
import time
import os
import random
import subprocess # Módulo para executar comandos do sistema de forma segura.

attack_app = Flask(__name__)

# --- Variáveis de Estado Global ---
# Controlam se um ataque está em andamento e qual thread o está executando.
attacking = False
attack_thread = None

# --- Rota para a Interface Web ---
@attack_app.route('/')
def index():
    """Serve a página principal com os botões de controle."""
    # Esta função procura por um arquivo chamado 'index.html' em uma pasta 'templates'.
    # Você precisará criar este arquivo HTML.
    return render_template('index.html')

# --- Lógica do Ataque: Flood por Ping ---
def ping_flood(target_ip):
    """
    Esta função executa o ataque de Ping Flood em um loop.
    Ela será executada em uma thread separada para não travar a API.
    """
    # O comando `ping -f` (flood) envia pings o mais rápido possível.
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

@attack_app.route('/attack/ping_flood', methods=['POST'])
def start_ping_flood():
    """
    Rota da API para INICIAR o ataque de Ping Flood.
    É chamada pelo botão "Iniciar Ataque" na interface web.
    """
    global attacking, attack_thread
    data = request.get_json()
    if not data or 'target_ip' not in data:
        return jsonify({"error": "target_ip ausente"}), 400
    
    target_ip = data['target_ip']

    # Impede que múltiplos ataques sejam iniciados ao mesmo tempo.
    if attacking:
        return jsonify({"status": "Um ataque já está em andamento"}), 409 # 409 Conflict

    print(f"Iniciando ataque de Ping Flood contra {target_ip}...")
    attacking = True
    # Cria e inicia uma nova thread para executar a função `ping_flood`.
    # 'daemon=True' garante que a thread será encerrada se o programa principal fechar.
    attack_thread = threading.Thread(target=ping_flood, args=(target_ip,), daemon=True)
    attack_thread.start()
    return jsonify({"status": f"Ataque de Ping Flood iniciado contra {target_ip}"})

@attack_app.route('/attack/stop', methods=['POST'])
def stop_attack():
    """
    Rota da API para PARAR qualquer ataque em andamento.
    """
    global attacking, attack_thread
    if not attacking:
        return jsonify({"status": "Nenhum ataque em andamento."})
    
    print("Parando o ataque...")
    # Altera a variável global, o que fará com que o loop na função do ataque termine.
    attacking = False
    if attack_thread and attack_thread.is_alive():
        # Espera um pouco para a thread terminar de forma limpa.
        attack_thread.join(timeout=1.0) 
    
    attack_thread = None
    return jsonify({"status": "Ataque interrompido com sucesso"})

@attack_app.route('/attack/spoof_mac', methods=['POST'])
def spoof_mac():
    """
    Rota da API para trocar o endereço MAC da interface de rede do Raspberry Pi.
    Isso é útil para testar se o controlador consegue lidar com mudanças de MAC
    ou para tentar evadir um bloqueio baseado em MAC.
    """
    data = request.get_json()
    # Permite especificar a interface (ex: 'eth0' ou 'wlan0'). Padrão é 'wlan0'.
    iface = data.get('iface', 'wlan0')
    
    # Gera um novo endereço MAC aleatório. O '02' no início indica que é um
    # endereço localmente administrado, o que é uma boa prática.
    new_mac = f"02:00:00:{random.randint(0x00, 0xFF):02x}:{random.randint(0x00, 0xFF):02x}:{random.randint(0x00, 0xFF):02x}"
    
    print(f"Tentando alterar o MAC da interface {iface} para {new_mac}...")
    try:
        # Os comandos para alterar o MAC requerem privilégios de root (sudo).
        # É necessário desativar a interface, alterar o MAC e reativá-la.
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "hw", "ether", new_mac], check=True)
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        return jsonify({"status": "MAC alterado com sucesso", "new_mac": new_mac})
    except subprocess.CalledProcessError as e:
        # Captura erros se os comandos falharem.
        return jsonify({"error": f"Falha ao executar comando: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Inicia o servidor Flask da API de ataques.
    # 'host="0.0.0.0"' permite que a API seja acessível de outros dispositivos na rede.
    # 'debug=True' é útil para desenvolvimento, pois recarrega o servidor a cada alteração.
    attack_app.run(host='0.0.0.0', port=7000, debug=True)
