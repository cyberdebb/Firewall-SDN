
// Estado global da aplicação
const appState = {
    isAttacking: false,
    activeRules: [],
    API_BASE_URL: 'http://localhost:5000',
    WS_URL: `ws://${window.location.hostname}:81`,
    webSocket: null,
};

// --- Funções do WebSocket ---

function connectWebSocket() {
    console.log(`Tentando conectar ao WebSocket em ${appState.WS_URL}`);
    appState.webSocket = new WebSocket(appState.WS_URL);

    appState.webSocket.onopen = () => {
        console.log("WebSocket Conectado!");
        updateWebsocketStatus(true);
        // Se identifica para o servidor como uma UI
        appState.webSocket.send(JSON.stringify({ type: "ui" }));
        addLog("Sistema", "Conectado ao Hub de Logs do Orquestrador.", "system");
    };

    appState.webSocket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === "log") {
                addLog(data.source, data.message);
            }
        } catch (e) {
            console.error("Erro ao processar mensagem do WebSocket:", e);
        }
    };

    appState.webSocket.onclose = () => {
        console.log("WebSocket Desconectado. Tentando reconectar em 3s...");
        updateWebsocketStatus(false);
        addLog("Sistema", "Desconectado do Hub de Logs. Tentando reconectar...", "error");
        setTimeout(connectWebSocket, 3000);
    };

    appState.webSocket.onerror = (error) => {
        console.error("Erro no WebSocket:", error);
        addLog("Sistema", "Erro na conexão WebSocket.", "error");
        appState.webSocket.close();
    };
}

function updateWebsocketStatus(isConnected) {
    const statusDiv = document.getElementById('websocketStatus');
    if (isConnected) {
        statusDiv.innerHTML = `
            <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span class="text-green-400 text-sm">WEBSOCKET CONECTADO</span>
        `;
    } else {
        statusDiv.innerHTML = `
            <div class="w-2 h-2 bg-red-400 rounded-full"></div>
            <span class="text-red-400 text-sm">WEBSOCKET DESCONECTADO</span>
        `;
    }
}

// --- Funções do Terminal de Log ---

function addLog(source, message, type = 'info') {
    const logContainer = document.getElementById('logContainer');
    const logEntry = document.createElement('div');

    let sourceColor = "text-yellow-400"; // Cor padrão para RaspberryPi
    if (source === "Switch") sourceColor = "text-cyan-400";
    if (source === "Controlador") sourceColor = "text-fuchsia-400";
    if (source === "Sistema") sourceColor = "text-green-400";

    let messageColor = "text-green-300";
    if (type === 'error') messageColor = "text-red-400";

    const timestamp = new Date().toLocaleTimeString();

    logEntry.className = `log-entry ${messageColor}`;
    logEntry.innerHTML = `<span class="text-green-600">[${timestamp}]</span> <span class="font-bold ${sourceColor}">[${source}]</span> <span>${message}</span>`;

    logContainer.appendChild(logEntry);
    // Auto-scroll para a última mensagem
    logContainer.scrollTop = logContainer.scrollHeight;

    // Remove logs antigos se houver muitos (mantém apenas os últimos 100)
    if (logContainer.children.length > 100) {
        logContainer.removeChild(logContainer.firstChild);
    }
}

// Função para mostrar toast notifications
function showToast(title, description, type = 'success') {
    const container = document.getElementById('toastContainer');

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    toast.innerHTML = `
        <div class="toast-title">${title}</div>
        <div class="toast-description">${description}</div>
    `;

    container.appendChild(toast);

    // Remove toast após 5 segundos
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 5000);
}

// Função para fazer requisições HTTP
async function sendRequest(url, method = 'POST', body = {}) {
    try {
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: method !== 'GET' ? JSON.stringify(body) : null
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Erro na API:', error);
        throw error;
    }
}

// Função para atualizar o status
function updateStatus(message, isAttacking = false) {
    const statusText = document.getElementById('statusText');
    const attackStatus = document.getElementById('attackStatus');
    const statusDisplay = document.getElementById('statusDisplay');

    if (statusText) statusText.textContent = message;
    appState.isAttacking = isAttacking;

    if (attackStatus) {
        if (isAttacking) {
            attackStatus.style.display = 'inline-flex';
        } else {
            attackStatus.style.display = 'none';
        }
    }

    if (statusDisplay) {
        if (isAttacking) {
            statusDisplay.className = statusDisplay.className.replace('border-green-500-30 bg-green-900-10', 'border-red-500-30 bg-red-900-10');
        } else {
            statusDisplay.className = statusDisplay.className.replace('border-red-500-30 bg-red-900-10', 'border-green-500-30 bg-green-900-10');
        }
    }

    // Adiciona também ao log
    addLog("Sistema", message, isAttacking ? "error" : "info");
}

// Função para validar MAC address
function isValidMac(mac) {
    return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac);
}

// Função para adicionar regra de bloqueio
async function addBlockRule() {
    const macInput = document.getElementById('macAddress');
    const macAddress = macInput.value.toUpperCase();

    if (!macAddress || !isValidMac(macAddress)) {
        showToast(
            '[ERRO] Endereço MAC Inválido',
            '> Formato esperado: AA:BB:CC:DD:EE:FF',
            'error'
        );
        addLog("Sistema", `Tentativa de bloqueio com MAC inválido: ${macAddress}`, "error");
        return;
    }

    const button = document.getElementById('addBlockRule');
    button.disabled = true;
    button.textContent = '> PROCESSANDO...';

    try {
        const rule = { match: { mac_address: macAddress }, action: "deny" };
        await sendRequest(`${appState.API_BASE_URL}/ui/add_rule`, 'POST', rule);

        showToast(
            '[SUCESSO] Regra Adicionada',
            `> MAC ${macAddress} foi bloqueado`
        );

        addLog("Firewall", `Regra de bloqueio adicionada para MAC: ${macAddress}`, "info");

        macInput.value = '';
        setTimeout(loadActiveRules, 1000);
    } catch (error) {
        showToast(
            '[ERRO] Falha na Operação',
            '> Não foi possível adicionar regra. Verifique o servidor Flask.',
            'error'
        );
        addLog("Sistema", `Erro ao adicionar regra: ${error.message}`, "error");
    } finally {
        button.disabled = false;
        button.textContent = '> BLOQUEAR MAC';
    }
}

// Função para carregar regras ativas
async function loadActiveRules() {
    try {
        const data = await sendRequest(`${appState.API_BASE_URL}/ui/get_rules`, 'GET');
        if (data && data.rules) {
            appState.activeRules = data.rules;
            renderActiveRules();
            addLog("Sistema", `Carregadas ${data.rules.length} regras ativas`, "info");
        }
    } catch (error) {
        showToast(
            '[ERRO] Conexão Falhou',
            '> Erro ao carregar regras do controlador',
            'error'
        );
        appState.activeRules = [];
        renderActiveRules();
        addLog("Sistema", `Erro ao carregar regras: ${error.message}`, "error");
    }
}

// Função para renderizar regras ativas
function renderActiveRules() {
    const container = document.getElementById('rulesContainer');
    const count = document.getElementById('rulesCount');

    if (count) count.textContent = `[${appState.activeRules.length}]`;

    if (!container) return;

    if (appState.activeRules.length > 0) {
        container.innerHTML = `
            <div class="space-y-2">
                ${appState.activeRules.map((rule, index) => `
                    <div class="flex items-center justify-between p-3 bg-green-900-10 border border-green-500-20 rounded-lg">
                        <div class="flex items-center gap-3">
                            <svg class="h-4 w-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                                <circle cx="12" cy="16" r="1"/>
                                <path d="m7 11V7a5 5 0 0 1 10 0v4"/>
                            </svg>
                            <span class="font-mono text-sm text-green-300">${rule.match.mac_address}</span>
                        </div>
                        <span class="badge bg-red-800-80 border-red-500-30 text-green-400 text-xs">
                            [${rule.action.toUpperCase()}]
                        </span>
                    </div>
                `).join('')}
            </div>
        `;
    } else {
        container.innerHTML = `
            <div class="flex flex-col items-center justify-center h-full text-green-600-70">
                <svg class="h-8 w-8 mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>
                </svg>
                <p class="text-sm font-mono">&gt;&gt; NENHUMA REGRA ATIVA</p>
            </div>
        `;
    }
}

// Função para iniciar ping flood
async function startPingFlood() {
    const targetIp = document.getElementById('targetIp').value;

    if (!targetIp) {
        showToast(
            '[ERRO] Alvo Obrigatório',
            '> Insira um IP alvo válido',
            'error'
        );
        addLog("Ataque", "Tentativa de ping flood sem IP alvo", "error");
        return;
    }

    updateStatus(`> Iniciando ataque ping flood em ${targetIp}...`, true);

    try {
        const response = await sendRequest(`${appState.API_BASE_URL}/attack/ping_flood`, 'POST', { target_ip: targetIp });

        let message = response.status || `> Erro: ${response.error || JSON.stringify(response)}`;
        updateStatus(`> ${message}`, true);

        showToast(
            '[ATAQUE] Ping Flood Iniciado',
            `> Atacando ${targetIp}`
        );

        addLog("Ataque", `Ping flood iniciado contra ${targetIp}`, "info");
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor', false);
        showToast(
            '[ERRO] Ataque Falhou',
            '> Não foi possível iniciar ataque. Verifique servidor Flask.',
            'error'
        );
        addLog("Ataque", `Erro ao iniciar ping flood: ${error.message}`, "error");
    }
}

// Função para parar ataque
async function stopAttack() {
    try {
        const response = await sendRequest(`${appState.API_BASE_URL}/attack/stop`, 'POST', {});

        let message = response.status || `> Erro: ${response.error || JSON.stringify(response)}`;
        updateStatus(`> ${message}`, false);

        showToast(
            '[SISTEMA] Ataque Terminado',
            '> Todos os ataques foram finalizados'
        );

        addLog("Ataque", "Todos os ataques foram finalizados", "info");
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor', false);
        showToast(
            '[ERRO] Falha ao Parar',
            '> Não foi possível parar o ataque',
            'error'
        );
        addLog("Ataque", `Erro ao parar ataques: ${error.message}`, "error");
    }
}

// Função para MAC spoofing
async function spoofMac() {
    const iface = document.getElementById('iface').value;

    if (!iface) {
        showToast(
            '[ERRO] Interface Obrigatória',
            '> Insira uma interface de rede válida',
            'error'
        );
        addLog("Ataque", "Tentativa de MAC spoof sem interface", "error");
        return;
    }

    try {
        const response = await sendRequest(`${appState.API_BASE_URL}/attack/spoof_mac`, 'POST', { iface: iface });

        let message = response.status || `> Erro: ${response.error || JSON.stringify(response)}`;
        if (response.new_mac) message += ` | Novo MAC: ${response.new_mac}`;

        updateStatus(`> ${message}`);

        showToast(
            '[EXPLOIT] MAC Spoofing Completo',
            `> Interface ${iface} MAC alterado`
        );

        addLog("Ataque", `MAC spoofing executado na interface ${iface}${response.new_mac ? ` - Novo MAC: ${response.new_mac}` : ''}`, "info");
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor');
        showToast(
            '[ERRO] Spoof Falhou',
            '> Não foi possível executar MAC spoofing. Verifique servidor Flask.',
            'error'
        );
        addLog("Ataque", `Erro no MAC spoofing: ${error.message}`, "error");
    }
}

// Função para limpar logs
function clearLogs() {
    const logContainer = document.getElementById('logContainer');
    if (logContainer) {
        logContainer.innerHTML = `
            <div class="log-entry text-green-500-50">
                <span class="font-bold text-green-400">[Sistema]</span>
                <span>Logs limpos - Aguardando novas mensagens...</span>
            </div>
        `;
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Firewall Panel
    const addBlockRuleBtn = document.getElementById('addBlockRule');
    if (addBlockRuleBtn) addBlockRuleBtn.addEventListener('click', addBlockRule);

    const refreshRulesBtn = document.getElementById('refreshRules');
    if (refreshRulesBtn) refreshRulesBtn.addEventListener('click', loadActiveRules);

    // Attack Panel
    const startPingFloodBtn = document.getElementById('startPingFlood');
    if (startPingFloodBtn) startPingFloodBtn.addEventListener('click', startPingFlood);

    const stopAttackBtn = document.getElementById('stopAttack');
    if (stopAttackBtn) stopAttackBtn.addEventListener('click', stopAttack);

    const spoofMacBtn = document.getElementById('spoofMac');
    if (spoofMacBtn) spoofMacBtn.addEventListener('click', spoofMac);

    // Clear logs button
    const clearLogsBtn = document.getElementById('clearLogs');
    if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);

    // Permitir envio com Enter no campo MAC
    const macAddressInput = document.getElementById('macAddress');
    if (macAddressInput) {
        macAddressInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                addBlockRule();
            }
        });
    }

    // Permitir envio com Enter no campo IP
    const targetIpInput = document.getElementById('targetIp');
    if (targetIpInput) {
        targetIpInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                startPingFlood();
            }
        });
    }

    // Carregar regras iniciais
    loadActiveRules();

    // Inicia a conexão WebSocket
    connectWebSocket();

    // Log inicial
    addLog("Sistema", "Painel de Controle SDN carregado com sucesso!", "info");

    console.log('Painel de Controle SDN carregado com sucesso!');
});
