# 🔥 Firewall Inteligente para IoT com Arquitetura Inspirada em SDN

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![PlatformIO](https://img.shields.io/badge/PlatformIO-Build%20%26%20Flash-orange)
![Python](https://img.shields.io/badge/Python-3.9.13-blue.svg)
![Framework: Flask](https://img.shields.io/badge/Framework-Flask-green.svg)
![Framework: C++](https://img.shields.io/badge/Linguagem-C++-purple.svg)

**Autores:** July Chassot e Débora Castro  
**Disciplina:** Redes Sem Fio - Engenharia da Computação (UFSC)

---

## 🚀 Sobre o Projeto

Este projeto é uma solução completa e de baixo custo para **segurança em redes de Internet das Coisas (IoT)**. Ele implementa um firewall dinâmico utilizando conceitos de **Redes Definidas por Software (SDN)** para detectar, visualizar e mitigar ameaças em tempo real.

O sistema é composto por microcontroladores ESP32 e um Raspberry Pi, que atuam de forma orquestrada para separar as funções de monitoramento (Plano de Dados) e tomada de decisão (Plano de Controle), culminando em um painel de controle web interativo para gerenciamento e simulação de ataques.

### 🎥 Demonstração Visual

[![Demonstração do Projeto](http://img.youtube.com/vi/dQw4w9WgXcQ/0.jpg)](https://www.youtube.com/watch?v=dQw4w9WgXcQ "Link para demonstração em vídeo")

## 🧠 Conceitos e Arquitetura

Inspirado nos princípios de SDN, o projeto desacopla a inteligência da rede dos dispositivos que apenas encaminham dados. Enquanto arquiteturas SDN tradicionais utilizam controladores como o **Ryu** e protocolos como o **OpenFlow**, esta solução adota uma abordagem mais leve e customizada para o ambiente de IoT, utilizando **WebSockets** para a comunicação entre o plano de controle e o de dados.

A arquitetura é dividida em três componentes principais:

1.  **Orquestrador Central (Raspberry Pi)**: O cérebro do sistema. Ele hospeda:
    * Um **Painel de Controle Web** (frontend) para interação do usuário.
    * Uma **API Northbound** (backend Flask em Python) que recebe comandos do painel e do sensor/firewall.
    * Um **Servidor WebSocket** para enviar regras em tempo real para o Switch.
    * Módulos para **simulação de ataques** (Ping Flood, MAC Spoofing) para testar a reatividade do sistema.

2.  **Firewall/Sensor (ESP32)**: O "Northbound Client" da rede.
    * Opera em **modo promíscuo**, capturando e analisando todo o tráfego da rede Wi-Fi.
    * Possui uma **lógica de detecção de anomalias** embarcada.
    * Ao detectar uma ameaça, reporta ao Orquestrador via `HTTP POST` e pode agir localmente para **desautenticar** clientes maliciosos. Periodicamente, pode enviar atualizações de regras com base no que detecta.

3.  **Switch SDN (ESP32)**: O músculo da rede (Plano de Dados).
    * Atua como um **filtro/ponte transparente** na rede.
    * Recebe regras de bloqueio (ACL - Access Control List) do Orquestrador via WebSocket.
    * Seu único trabalho é **encaminhar pacotes permitidos** e **descartar pacotes bloqueados**, sem tomar decisões complexas.
    * Opera em modo **Fail-Secure**: se perder a conexão com o controle, bloqueia todo o tráfego por padrão.

## ✨ Funcionalidades (Features)

* **Painel de Controle Web**: Interface gráfica para gerenciar o firewall e lançar testes de segurança.
* **Gerenciamento de Regras em Tempo Real**: Adicione regras de bloqueio de MAC Address que são aplicadas instantaneamente na rede.
* **Firewall Ativo e Reativo**: O sistema não só filtra o tráfego com base em regras, mas também detecta ativamente anomalias e reage a elas.
* **Simulador de Ataques**:
    * **Ping Flood**: Gere tráfego intenso para testar a capacidade de detecção e bloqueio.
    * **MAC Spoofing**: Altere o MAC de uma interface de rede para testar a segurança da camada de enlace.
* **Arquitetura Segura**: Comunicação entre o sensor e o controlador validada por chave de API e modo *Fail-Secure* no switch.
* **Baixo Custo**: Implementado com componentes de hardware acessíveis e software open-source.

---

## 🛠️ Hardware e Software Necessários

### Hardware
* 1x Raspberry Pi 3 (ou superior) com Raspberry Pi OS.
* 2x Microcontroladores ESP32 (placa de desenvolvimento, ex: ESP32 DevKitC).
* Cabos Micro-USB para alimentação e programação.
* Um roteador Wi-Fi para criar a rede de teste.
* Computador para desenvolvimento (testado com Windows 11).

### Software
* **IDE**: [VS Code](https://code.visualstudio.com/) com a extensão [PlatformIO IDE](https://platformio.org/platformio-ide).
* **Driver USB**: [CP2102 USB to UART Bridge Controller Driver](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers) (necessário para a maioria das placas ESP32).
* **Python**: Versão `3.9.13` ou superior.
* **Bibliotecas Python**:
    ```sh
    pip install Flask Flask-Cors websockets scapy
    ```
    > **Observação:** Em algumas instalações, pode ocorrer um erro de dependência com o `eventlet`. Se você encontrar `ImportError: cannot import name 'ALREADY_HANDLED'`, resolva com:
    > `pip install eventlet==0.30.2`
* **Ferramentas de linha de comando**: `git`.

---

## 🔧 Instalação e Configuração

Siga os passos abaixo para replicar o ambiente.

### Passo 1: Preparar o Ambiente de Desenvolvimento

1.  Instale o VS Code, Python 3.9+, Git e os drivers CP2102 no seu computador.
2.  Dentro do VS Code, instale a extensão **PlatformIO IDE** a partir do marketplace.

### Passo 2: Configurar o Raspberry Pi (Orquestrador)

1.  **Preparar o SO**: Use o `Raspberry Pi Imager` para instalar o "Raspberry Pi OS (32-bit)" em um cartão MicroSD.
2.  **Acesso Remoto**: Após a inicialização, acesse o terminal do Pi (diretamente ou via SSH).
3.  **Clonar o Repositório**:
    ```sh
    git clone [https://github.com/JulyChassot/seu-repositorio.git](https://github.com/JulyChassot/seu-repositorio.git)
    cd seu-repositorio/1_Raspberry
    ```
4.  **Configurar Variáveis de Ambiente**: Crie um arquivo `.env` na raiz da pasta `1_Raspberry` para armazenar as chaves de API. Este arquivo não deve ser enviado para o Git.
    ```ini
    # .env
    API_KEY="SUA_CHAVE_SECRETA_COMPARTILHADA"
    ```
5.  **Configurar o Ambiente Python**:
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt # Ou use o comando pip install do tópico de software
    ```
6.  **Iniciar o Servidor**:
    ```sh
    # No primeiro terminal
    python3 dashboard_api.py
    ```
    Anote o endereço IP do seu Raspberry Pi na rede. O servidor estará rodando na porta `5000`.

### Passo 3: Configurar os ESP32 (Switch e Firewall)

Para ambos os ESP32, o processo é semelhante.

1.  **Gerenciamento de Credenciais**: Em cada pasta de firmware (`2_ESP32_Controlador` e `3_ESP32_Switch`), crie um arquivo `configs.h` dentro da pasta `src/` para armazenar suas informações sensíveis. Utilize o `configs.h.example` como modelo. Este arquivo deve ser ignorado pelo Git.
    ```cpp
    // src/configs.h
    #define WIFI_SSID "NOME_DA_SUA_REDE"
    #define WIFI_PASS "SENHA_DA_SUA_REDE"
    #define CONTROLLER_URL "http://IP_DO_SEU_RASPBERRY_PI:5000"
    #define WEBSOCKET_HOST "IP_DO_SEU_RASPBERRY_PI"
    #define API_KEY "SUA_CHAVE_SECRETA_COMPARTILHADA" // Mesma chave do .env
    ```
2.  **Configurar o `platformio.ini`**: Certifique-se de que o arquivo `platformio.ini` em cada pasta de firmware está configurado corretamente:
    ```ini
    [env:esp32dev]
    platform = espressif32
    board = esp32dev
    framework = arduino
    monitor_speed = 115200
    lib_deps =
        bblanchon/ArduinoJson@^6.21.2
    ```
3.  **Compilar e Fazer Upload**:
    * Abra a pasta de um dos firmwares (ex: `2_ESP32_Controlador`) no VS Code com PlatformIO.
    * Preencha o arquivo `src/configs.h` com as informações da sua rede e do Raspberry Pi.
    * Conecte o ESP32 ao computador, compile e faça o upload do firmware usando os botões do PlatformIO na barra de status do VS Code.
    * Repita o processo para o outro ESP32 (`3_ESP32_Switch`).

---

## 🎮 Como Usar

1.  **Inicie os Servidores**:
    * No Raspberry Pi, execute a API: `python3 dashboard_api.py`.
    * Ligue os dois ESP32.

2.  **Monitore a Atividade**:
    * Abra o **Monitor Serial** do PlatformIO para o **ESP32-Firewall/Sensor** para observar os logs de detecção de tráfego e ataques. A velocidade deve ser `115200`.

3.  **Acesse o Painel**:
    * Conecte seu computador à mesma rede Wi-Fi do Raspberry Pi.
    * Abra o navegador e acesse `http://<IP_DO_RASPBERRY_PI>:5000`.
    * Você verá o **Painel de Controle SDN**.

4.  **Para Bloquear um Dispositivo Manualmente**:
    * Digite o endereço MAC do dispositivo que deseja bloquear no campo "ENDEREÇO MAC ALVO".
    * Clique em `> BLOQUEAR MAC`. A regra aparecerá na lista de "REGRAS ATIVAS" e será enviada em tempo real para o ESP32-Switch.

5.  **Para Simular um Ataque e ver a Reação**:
    * No painel, digite o endereço IP de um dispositivo na sua rede (pode ser o seu próprio PC) no campo "IP ALVO PARA FLOOD".
    * Clique em `> INICIAR PING FLOOD`.
    * Observe os logs no monitor serial do **ESP32-Firewall/Sensor**. Ele deve detectar o ataque, reportar ao Orquestrador, e o MAC do dispositivo atacante (o Raspberry Pi) aparecerá automaticamente na lista de bloqueio do painel.
    * Clique em `> TERMINAR ATAQUE` para parar a simulação.

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

---

## 🧑‍💻 Autores

* **July Chassot** - [GitHub](https://github.com/LastChassot)
* **Débora Castro** - [GitHub](https://github.com/cyberdebb) 

*Feito com ❤️ e ☕ e ☕ e mais ☕ para a disciplina de Redes Sem Fio.*
