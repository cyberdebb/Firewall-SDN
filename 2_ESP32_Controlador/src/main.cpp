// ===================================================================
// ||   Firmware para o ESP32-Controlador (v6)                    ||
// ===================================================================

#include <WiFi.h>
#include <esp_wifi.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <WiFiUdp.h>
#include <WiFiServer.h> 
#include <WiFiClient.h>

// ESTRUTURAS
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6], addr2[6], addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

// CONFIGURAÇÕES
const char* main_ssid = "Wifi July";
const char* main_password = "jlichassot";
const char* raspberry_pi_ip = "192.168.161.102";
const int udp_log_port = 12345;
WiFiServer server(80); 
WiFiUDP udp;

JsonDocument firewallRules;
const char* rulesFilePath = "/firewall_rules.json";

bool udp_logging_enabled = false;

void log_message(const char* message) {
    Serial.println(message);
    if (udp_logging_enabled) {
        udp.beginPacket(raspberry_pi_ip, udp_log_port);
        String log_prefix = "[Controlador] ";
        udp.print(log_prefix + message);
        udp.endPacket();
    }
}
void saveFirewallRules() {
    File file = LittleFS.open(rulesFilePath, "w");
    if (!file) { log_message("Falha ao abrir arquivo para salvar regras."); return; }
    serializeJson(firewallRules, file);
    file.close();
    log_message("Regras salvas no LittleFS.");
}
void loadFirewallRules() {
    if (!LittleFS.begin()) { Serial.println("Falha ao montar LittleFS."); return; }
    File file = LittleFS.open(rulesFilePath, "r");
    if (!file) {
        log_message("Arquivo de regras não encontrado. Criando um novo.");
        firewallRules.to<JsonArray>();
        return;
    }
    if (deserializeJson(firewallRules, file) != DeserializationError::Ok) {
        log_message("Falha ao ler regras. Começando com lista vazia.");
        firewallRules.to<JsonArray>();
    } else {
        log_message("Regras de firewall carregadas do LittleFS.");
    }
    file.close();
}
String macToString(const uint8_t* mac) {
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_ieee80211_mac_hdr_t* hdr = (wifi_ieee80211_mac_hdr_t*)pkt->payload;
    String src_mac_str = macToString(hdr->addr2);
    JsonArray rules = firewallRules.as<JsonArray>();
    for (JsonObject rule : rules) {
        if (src_mac_str.equalsIgnoreCase(rule["match"]["mac_address"])) {
            if (String("deny").equalsIgnoreCase(rule["action"])) {
                char log_buffer[100];
                sprintf(log_buffer, "PACOTE ILEGAL! Origem: %s.", src_mac_str.c_str());
                log_message(log_buffer);
                return;
            }
        }
    }
}

// SETUP PRINCIPAL 
void setup() {
    Serial.begin(115200);
    Serial.println("\n\n--- Iniciando Firewall Controlador (v6 - Leve e Estável) ---");
    loadFirewallRules();

    WiFi.mode(WIFI_STA);
    WiFi.begin(main_ssid, main_password);
    Serial.print("Conectando à rede principal...");
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nCONEXÃO WI-FI ESTABELECIDA!");
    
    udp_logging_enabled = true;
    log_message((String("IP do Controlador: ") + WiFi.localIP().toString()).c_str());

    // Inicia o servidor web leve
    server.begin();
    log_message("API de gerenciamento de regras iniciada.");

    // Inicia o Modo Sniffer
    esp_wifi_set_channel(WiFi.channel(), WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    log_message("Modo Firewall (Sniffer) ativado.");

    log_message(">>> Controlador pronto e 100% operacional. <<<");
}

// O loop alida com as requisições HTTP 
void loop() {
    WiFiClient client = server.available(); 
    if (client) {
        log_message("Novo cliente conectado à API.");
        String currentLine = "";
        String requestBody = "";
        bool bodyStarted = false;

        while (client.connected()) {
            if (client.available()) {
                char c = client.read();
                if (c == '\n') {
                    if (currentLine.length() == 0) { 
                        bodyStarted = true;
                    }
                    currentLine = "";
                } else if (c != '\r') {
                    currentLine += c;
                }
                
                if (bodyStarted) {
                    requestBody += c;
                }
            }

            // Se o cliente desconectar, processa a requisição
            if (!client.connected()) break;
        }

        // Processamento da Requisição 
        if (currentLine.startsWith("GET /firewall/rules")) {
            log_message("Recebida requisição GET /firewall/rules");
            String responseBody;
            serializeJson(firewallRules, responseBody);
            client.println("HTTP/1.1 200 OK");
            client.println("Content-Type: application/json");
            client.println("Connection: close");
            client.println();
            client.println(responseBody);
        } else if (currentLine.startsWith("POST /firewall/rules")) {
            log_message("Recebida requisição POST /firewall/rules");
            JsonDocument newRule;
            if (deserializeJson(newRule, requestBody.substring(1)) == DeserializationError::Ok) {
                firewallRules.as<JsonArray>().add(newRule);
                saveFirewallRules();
                client.println("HTTP/1.1 200 OK");
                client.println("Content-Type: application/json");
                client.println("Connection: close");
                client.println();
                client.println("{\"status\":\"Regra recebida e salva\"}");
                log_message("Nova regra salva com sucesso.");
            } else {
                client.println("HTTP/1.1 400 Bad Request");
                client.println("Content-Type: application/json");
                client.println("Connection: close");
                client.println();
                client.println("{\"error\":\"JSON inválido\"}");
                log_message("ERRO: Recebido JSON inválido via API.");
            }
        }
        
        delay(1);
        client.stop();
        log_message("Cliente da API desconectado.");
    }
}