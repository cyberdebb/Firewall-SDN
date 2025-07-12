// ===================================================================
// ||   Firmware para o ESP32-Switch SDN (v4)                      ||
// ===================================================================

#include <esp_wifi.h>
#include <WiFi.h>
#include <vector>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <WiFiUdp.h>

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6], addr2[6], addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;
enum Policy { PERMIT, DENY };
struct FirewallRule {
    String mac;
    Policy policy;
};


// CONFIGURAÇÕES E VARIÁVEIS GLOBAIS
const char* main_ssid = "Wifi July";
const char* main_password = "jlichassot";
const char* raspberry_pi_ip = "192.168.0.236";
const int udp_log_port = 12345;
const uint16_t websocket_port = 81;

// O resto das variáveis globais...
std::vector<FirewallRule> acl;
volatile bool is_controller_connected = false;
WebSocketsClient webSocket;
WiFiUDP udp;
bool udp_logging_enabled = false;


// Mantenha as suas funções de log, macToString, promiscuous_callback e webSocketEvent
// Elas não serão alteradas nesta etapa.
void log_message(const char* message) {
    Serial.println(message);
    if (udp_logging_enabled) {
        udp.beginPacket(raspberry_pi_ip, udp_log_port);
        String log_prefix = "[Switch] ";
        udp.print(log_prefix + message);
        udp.endPacket();
    }
}
String macToString(const uint8_t* mac) {
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}
void promiscuous_rx_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!is_controller_connected || type != WIFI_PKT_DATA) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_ieee80211_mac_hdr_t* hdr = (wifi_ieee80211_mac_hdr_t*)pkt->payload;
    if (memcmp(hdr->addr2, WiFi.macAddress(nullptr), 6) == 0) return;
    String src_mac_str = macToString(hdr->addr2);
    Policy effective_policy = DENY;
    for (const auto& rule : acl) {
        if (rule.mac.equalsIgnoreCase(src_mac_str)) {
            effective_policy = rule.policy;
            break;
        }
    }
    if (effective_policy == PERMIT) {
        esp_wifi_80211_tx(WIFI_IF_STA, pkt->payload, pkt->rx_ctrl.sig_len, false);
    } else {
        char log_buffer[60];
        sprintf(log_buffer, "Pacote de %s BLOQUEADO pela ACL.", src_mac_str.c_str());
        log_message(log_buffer);
    }
}
void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
    char log_buffer[100];
    switch (type) {
        case WStype_DISCONNECTED:
            is_controller_connected = false;
            esp_wifi_set_promiscuous(false);
            log_message("Desconectado do Orquestrador! Modo Firewall Pausado.");
            break;
        case WStype_CONNECTED:
            is_controller_connected = true;
            esp_wifi_set_channel(WiFi.channel(), WIFI_SECOND_CHAN_NONE);
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_callback);
            log_message("Conectado ao Orquestrador! Modo Firewall ATIVADO.");
            webSocket.sendTXT("{\"type\": \"device\", \"id\": \"Switch\"}");
            break;
        case WStype_TEXT:
             {
                sprintf(log_buffer, "Regra recebida via WebSocket: %s", (char*)payload);
                log_message(log_buffer);
                JsonDocument doc;
                if (deserializeJson(doc, payload, length).code() == DeserializationError::Ok) {
                    String action = doc["action"];
                    String mac = doc["mac_address"];
                    if (mac.isEmpty()) return;
                    bool rule_updated = false;
                    for (auto& rule : acl) {
                        if (rule.mac.equalsIgnoreCase(mac)) {
                            rule.policy = (action.equalsIgnoreCase("allow")) ? PERMIT : DENY;
                            rule_updated = true;
                            sprintf(log_buffer, 
                              "ACL: Regra para %s ATUALIZADA para %s.", mac.c_str(), action.c_str());
                            log_message(log_buffer);
                            break;
                        }
                    }
                    if (!rule_updated) {
                        acl.push_back({mac, (action.equalsIgnoreCase("allow")) ? PERMIT : DENY});
                        sprintf(log_buffer, 
                          "ACL: Nova regra para %s ADICIONADA: %s.", mac.c_str(), action.c_str());
                        log_message(log_buffer);
                    }
                }
            }
            break;
        default: break;
    }
}

// <<< SETUP PRINCIPAL  >>>
void setup() {
    Serial.begin(115200);
    Serial.println("\n\n--- Iniciando Firmware do Switch SDN (v4) ---");
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(main_ssid, main_password);

    Serial.println("Tentando conectar à rede: " + String(main_ssid));

    // Loop de debug: vamos esperar 15 segundos, imprimindo o status
    int attempt = 0;
    while (WiFi.status() != WL_CONNECTED && attempt < 30) {
        Serial.print("Tentativa ");
        Serial.print(attempt + 1);
        Serial.print("... Status: ");
        Serial.print(WiFi.status()); 
        Serial.println();
        delay(500);
        attempt++;
    }

    // Verifica o resultado final após o loop
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nCONEXÃO WI-FI ESTABELECIDA!");
        udp_logging_enabled = true; // Ativa o log UDP

        log_message((String("IP do Switch: ") + WiFi.localIP().toString()).c_str());

        // Inicia o WebSocket APENAS se a conexão foi bem-sucedida
        webSocket.begin(raspberry_pi_ip, websocket_port, "/");
        webSocket.onEvent(webSocketEvent);
        webSocket.setReconnectInterval(5000);
        log_message("Aguardando conexão com o Orquestrador via WebSocket...");
    } else {
        Serial.println("\n!!! FALHA NA CONEXÃO WI-FI APÓS VÁRIAS TENTATIVAS !!!");
        Serial.println("Verifique o NOME DA REDE e a SENHA no código.");
        Serial.print("Último status recebido: ");
        Serial.println(WiFi.status());
    }
}

void loop() {
    if (WiFi.status() == WL_CONNECTED) {
        webSocket.loop();
    }
    delay(10);
}