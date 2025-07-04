// Estado global da aplicação
const appState = {
    isAttacking: false,
    activeRules: [],
    API_BASE_URL: 'http://localhost:5000'
};

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

    statusText.textContent = message;
    appState.isAttacking = isAttacking;

    if (isAttacking) {
        attackStatus.style.display = 'inline-flex';
        statusDisplay.className = statusDisplay.className.replace('border-green-500-30 bg-green-900-10', 'border-red-500-30 bg-red-900-10');
    } else {
        attackStatus.style.display = 'none';
        statusDisplay.className = statusDisplay.className.replace('border-red-500-30 bg-red-900-10', 'border-green-500-30 bg-green-900-10');
    }
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

        macInput.value = '';
        setTimeout(loadActiveRules, 1000);
    } catch (error) {
        showToast(
            '[ERRO] Falha na Operação',
            '> Não foi possível adicionar regra. Verifique o servidor Flask.',
            'error'
        );
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
        }
    } catch (error) {
        showToast(
            '[ERRO] Conexão Falhou',
            '> Erro ao carregar regras do controlador',
            'error'
        );
        appState.activeRules = [];
        renderActiveRules();
    }
}

// Função para renderizar regras ativas
function renderActiveRules() {
    const container = document.getElementById('rulesContainer');
    const count = document.getElementById('rulesCount');

    count.textContent = `[${appState.activeRules.length}]`;

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
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor', false);
        showToast(
            '[ERRO] Ataque Falhou',
            '> Não foi possível iniciar ataque. Verifique servidor Flask.',
            'error'
        );
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
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor', false);
        showToast(
            '[ERRO] Falha ao Parar',
            '> Não foi possível parar o ataque',
            'error'
        );
    }
}

// Função para MAC spoofing
async function spoofMac() {
    const iface = document.getElementById('iface').value;

    try {
        const response = await sendRequest(`${appState.API_BASE_URL}/attack/spoof_mac`, 'POST', { iface: iface });

        let message = response.status || `> Erro: ${response.error || JSON.stringify(response)}`;
        if (response.new_mac) message += ` | Novo MAC: ${response.new_mac}`;

        updateStatus(`> ${message}`);

        showToast(
            '[EXPLOIT] MAC Spoofing Completo',
            `> Interface ${iface} MAC alterado`
        );
    } catch (error) {
        updateStatus('> Erro na comunicação com o servidor');
        showToast(
            '[ERRO] Spoof Falhou',
            '> Não foi possível executar MAC spoofing. Verifique servidor Flask.',
            'error'
        );
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Firewall Panel
    document.getElementById('addBlockRule').addEventListener('click', addBlockRule);
    document.getElementById('refreshRules').addEventListener('click', loadActiveRules);

    // Attack Panel
    document.getElementById('startPingFlood').addEventListener('click', startPingFlood);
    document.getElementById('stopAttack').addEventListener('click', stopAttack);
    document.getElementById('spoofMac').addEventListener('click', spoofMac);

    // Permitir envio com Enter no campo MAC
    document.getElementById('macAddress').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            addBlockRule();
        }
    });

    // Permitir envio com Enter no campo IP
    document.getElementById('targetIp').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startPingFlood();
        }
    });

    // Carregar regras iniciais
    loadActiveRules();

    console.log('Painel de Controle SDN carregado com sucesso!');
});
