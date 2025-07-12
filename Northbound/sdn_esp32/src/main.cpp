/**
 * @file main.cpp
 * @brief Este firmware transforma um ESP32 em um sensor de rede inteligente (IDS/IPS).
 *
 * ARQUITETURA:
 * Este código representa o PLANO DE APLICAÇÃO de uma rede SDN.
 * - RESPONSABILIDADE: Detectar comportamentos de rede maliciosos e tomar decisões de segurança.
 * - COMO: Ele "ouve" o tráfego da rede, aplica uma lógica de detecção e, ao encontrar uma
 * ameaça, envia uma ordem de bloqueio para o Plano de Controle (Controlador Ryu)
 * através de uma API Northbound (seu script Flask).
 */

// --- Includes de bibliotecas e arquivos ---
#include <WiFi.h>              // Para conectividade Wi-Fi.
#include <HTTPClient.h>        // Para fazer requisições HTTP (enviar regras para o controlador).
#include <ArduinoJson.h>       // Para construir o payload JSON das regras.
#include <vector>              // Para listas dinâmicas (regras ativas, whitelist).
#include <map>                 // Para as estruturas de dados da detecção (ex: IP -> Portas).
#include <set>                 // Para armazenar as portas de forma única para cada IP.
#include "configs.h"           // Arquivo externo para guardar senhas e URLs (boa prática).

// --- Includes de baixo nível para o Sniffer ---
#include "esp_wifi.h"          // Funções da API do ESP-IDF para controlar o Wi-Fi.
#include "esp_wifi_types.h"    // Tipos de dados usados pela API Wi-Fi, como o do pacote capturado.

// --- Configurações de Rede e Segurança ---
const char* ssid = WIFI_SSID;
const char* password = WIFI_PASS;
const char* controllerAddress = CONTROLLER_URL; // URL do "mensageiro" (API Flask).
const char* apiKey = API_KEY;                   // Chave para autenticação básica.

// --- Constantes para a Lógica de Detecção ---
#define PORT_SCAN_THRESHOLD 20  // Limite para detecção: se um IP testar mais que X portas, é um scanner.
#define CHECK_INTERVAL_MS 10000 // Intervalo da análise: o cérebro do firewall vai "pensar" a cada 10s.

// --- Estruturas de Dados para Firewall e Detecção ---
// Representa uma regra de firewall simples.
struct FirewallRule {
    String mac_address;
    String action;
};

// Mapa para rastrear portas escaneadas por IP: A "memória de curto prazo" do módulo de detecção.
std::map<String, std::set<uint16_t>> ip_to_ports;
// Mapa para associar um IP ao seu MAC mais recente: Necessário para saber qual MAC bloquear.
std::map<String, String> ip_to_mac;
// Armazena as regras que este firewall já decidiu e enviou para o Ryu.
std::vector<FirewallRule> active_rules;

// --- Estruturas para Decodificar Pacotes ---
#pragma pack(push, 1) // Garante que o compilador não adicione preenchimento, para o molde ser exato.
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t saddr[4]; // Endereço IP de origem em bytes.
    uint8_t daddr[4]; // Endereço IP de destino em bytes.
} IPHeader;

typedef struct {
    uint16_t source_port;
    uint16_t dest_port;
} TCPHeader;
#pragma pack(pop) // Volta ao alinhamento padrão.


// --- Protótipos de Funções ---
void connectToWiFi();
void blockMacAddress(const String& mac);
void sendSingleRuleToController(const FirewallRule& rule);
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type);
unsigned long last_check_time = 0; // Para o controle de tempo não-bloqueante no loop.

// =================================================================
// --- SETUP ---
// =================================================================
void setup() {
    Serial.begin(115200);
    delay(1000);

    connectToWiFi();

    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nIniciando firewall em modo inteligente...");
        
        // Ativa o "Modo Promíscuo", que é a capacidade da placa de rede de
        // "ouvir" todos os pacotes que passam pelo ar, não apenas os endereçados a ela.
        esp_wifi_set_promiscuous(true);
        // Registra a função que será chamada para cada pacote capturado.
        esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
        
        Serial.println("Modo promiscuo ativado. Ouvindo o tráfego da rede...");
    } else {
        Serial.println("Falha ao conectar ao WiFi. O firewall inteligente não pode ser iniciado.");
    }
}

// =================================================================
// --- LOOP PRINCIPAL ---
// =================================================================
void loop() {
    // Esta estrutura com millis() cria uma tarefa periódica sem travar o processador com delays.
    // É o "coração pensante" do firewall, que analisa os dados coletados.
    if (millis() - last_check_time > CHECK_INTERVAL_MS) {
        Serial.printf("\n--- Verificando atividades suspeitas (últimos %d segundos) ---\n", CHECK_INTERVAL_MS / 1000);

        // Itera sobre o mapa de IPs que vimos no último intervalo.
        for (auto const& [ip, ports] : ip_to_ports) {
            // Se um único IP tentou se conectar a mais portas do que o nosso limite...
            if (ports.size() > PORT_SCAN_THRESHOLD) {
                String mac_to_block = ip_to_mac[ip]; // Busca o MAC associado a esse IP.
                Serial.printf("!!! DETECÇÃO DE PORT SCAN !!! IP: %s (MAC: %s) escaneou %d portas.\n",
                              ip.c_str(), mac_to_block.c_str(), ports.size());
                
                // Inicia o processo de bloqueio.
                blockMacAddress(mac_to_block);
            }
        }
        
        // Após a análise, a "memória de curto prazo" é limpa para o próximo ciclo.
        ip_to_ports.clear();
        ip_to_mac.clear();
        
        last_check_time = millis(); // Reseta o cronômetro para o próximo ciclo.
    }
}

// =================================================================
// --- FUNÇÃO SNIFFER ---
// =================================================================
/**
 * @brief Esta é a função mais crítica e de mais baixo nível.
 * Ela é executada centenas ou milhares de vezes por segundo, para cada pacote capturado.
 * Sua única responsabilidade deve ser extrair dados rapidamente e armazená-los.
 * A análise pesada fica para o loop().
 */
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    EthernetHeader *eth_hdr = (EthernetHeader*)pkt->payload;

    // Filtra para processar apenas pacotes IPv4. ntohs() corrige a ordem dos bytes.
    if (ntohs(eth_hdr->ethertype) == 0x0800) {
        // "Caminha" para o próximo cabeçalho, o de IP.
        IPHeader *ip_hdr = (IPHeader*)(eth_hdr + 1);
        
        // Filtra para processar apenas pacotes TCP, que são usados para scans de portas.
        if (ip_hdr->protocol == 6) {
            // Calcula o início do cabeçalho TCP (o cabeçalho IP tem tamanho variável).
            TCPHeader *tcp_hdr = (TCPHeader*)((uint8_t*)ip_hdr + (ip_hdr->version_ihl & 0x0F) * 4);

            // Converte os dados brutos (bytes) em formatos mais fáceis de usar (Strings).
            char src_mac_str[18], src_ip_str[16];
            sprintf(src_mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                    eth_hdr->src_mac[0], eth_hdr->src_mac[1], eth_hdr->src_mac[2],
                    eth_hdr->src_mac[3], eth_hdr->src_mac[4], eth_hdr->src_mac[5]);
            sprintf(src_ip_str, "%d.%d.%d.%d",
                    ip_hdr->saddr[0], ip_hdr->saddr[1], ip_hdr->saddr[2], ip_hdr->saddr[3]);

            uint16_t dest_port = ntohs(tcp_hdr->dest_port);

            // Armazena os dados coletados para a análise que acontecerá no loop().
            ip_to_ports[String(src_ip_str)].insert(dest_port);
            ip_to_mac[String(src_ip_str)] = String(src_mac_str);
        }
    }
}

// =================================================================
// --- FUNÇÕES AUXILIARES ---
// =================================================================
void connectToWiFi() {
    Serial.print("Conectando a ");
    Serial.println(ssid);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nWiFi conectado!");
        Serial.print("Endereço IP: ");
        Serial.println(WiFi.localIP());
    }
}

/**
 * @brief Gerencia a lógica de bloqueio: verifica se já não está bloqueado e inicia o envio.
 */
void blockMacAddress(const String& mac) {
    // Impede o envio de regras duplicadas para o mesmo MAC.
    for (const auto& rule : active_rules) {
        if (rule.mac_address == mac) {
            Serial.printf("MAC %s já está bloqueado.\n", mac.c_str());
            return;
        }
    }

    // Cria a regra e a envia para o controlador.
    FirewallRule new_rule = {mac, "block"};
    active_rules.push_back(new_rule); // Mantém um registro local das regras ativas.
    sendSingleRuleToController(new_rule);
}

/**
 * @brief Envia UMA ÚNICA regra para o controlador.
 * Esta função é a ponte entre a decisão tomada neste dispositivo (Plano de Aplicação)
 * e a execução que será feita pelo controlador (Plano de Controle).
 */
void sendSingleRuleToController(const FirewallRule& rule) {
    DynamicJsonDocument doc(256); // Documento JSON para a requisição.

    // Monta o payload no formato esperado pela API Northbound: {"rules": [{"mac": ..., "action": ...}]}
    JsonArray jsonRules = doc.createNestedArray("rules");
    JsonObject ruleObj = jsonRules.createNestedObject();
    ruleObj["mac"] = rule.mac_address;
    ruleObj["action"] = rule.action;

    String jsonPayload;
    serializeJson(doc, jsonPayload);

    Serial.println("\n--- ENVIANDO NOVA REGRA PARA O CONTROLADOR ---");
    serializeJsonPretty(doc, Serial);
    Serial.println();

    HTTPClient http;
    http.begin(controllerAddress);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", apiKey);

    // Envia a requisição POST para o "mensageiro" (API Flask).
    int httpResponseCode = http.POST(jsonPayload);

    // Processa a resposta para saber se o controlador aceitou a regra.
    if (httpResponseCode > 0) {
        Serial.printf("Código de resposta HTTP: %d\n", httpResponseCode);
        String responsePayload = http.getString();
        Serial.printf("Payload da resposta: %s\n", responsePayload.c_str());
    } else {
        Serial.printf("Falha na requisição HTTP. Erro: %s\n", http.errorToString(httpResponseCode).c_str());
    }

    http.end();
}