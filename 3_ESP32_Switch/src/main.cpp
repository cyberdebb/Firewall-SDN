#include <WiFi.h>
#include <esp_wifi.h>
#include "esp_wifi_types.h"
#include "esp_wifi_internal.h" 
#include <vector>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>

// --- Configurações da Rede e Conexão ---
const char* controller_ssid = "SDN_Control_Net";
const char* controller_password = "securepassword";
const char* websocket_server_host = "192.168.4.1";
const uint16_t websocket_server_port = 80;

// --- Estruturas de Dados para o Firewall ---
enum Policy { PERMIT, DENY };
struct FirewallRule {
  String mac;
  Policy policy;
};

// --- Variáveis Globais ---
std::vector<FirewallRule> acl;
volatile bool is_controller_connected = false;
const bool FAIL_SECURE_MODE = true;

WebSocketsClient webSocket;

// --- Funções Auxiliares ---
String macToString(const uint8_t* mac) {
  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

// --- Lógica Principal do Firewall ---
void promiscuous_rx_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_ieee80211_mac_hdr_t *hdr = (wifi_ieee80211_mac_hdr_t *)pkt->payload;
  String src_mac_str = macToString(hdr->addr2);

  Policy effective_policy = DENY;

  if (!is_controller_connected && !FAIL_SECURE_MODE) {
      effective_policy = PERMIT;
  } else {
    for (const auto& rule : acl) {
      if (rule.mac.equalsIgnoreCase(src_mac_str)) {
        effective_policy = rule.policy;
        break;
      }
    }
  }

  if (effective_policy == PERMIT) {
    esp_wifi_80211_tx(WIFI_IF_STA, pkt->payload, pkt->rx_ctrl.sig_len, true);
  }
}

// --- Comunicação com o Controlador ---
void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      Serial.println("[WSc] Desconectado do controlador!");
      is_controller_connected = false;
      break;
    case WStype_CONNECTED:
      Serial.println("[WSc] Conectado ao controlador!");
      is_controller_connected = true;
      webSocket.sendTXT("Switch Conectado");
      break;
    case WStype_TEXT:
      {
        Serial.printf("[WSc] Regra recebida: %s\n", payload);
        JsonDocument doc;
        if (deserializeJson(doc, payload, length).code() != DeserializationError::Ok) {
          Serial.println("Falha ao analisar JSON da regra.");
          return;
        }

        String action = doc["action"];
        String mac = doc["client_mac"];

        bool rule_updated = false;
        for (auto& rule : acl) {
          if (rule.mac.equalsIgnoreCase(mac)) {
            rule.policy = (action.equalsIgnoreCase("allow")) ? PERMIT : DENY;
            rule_updated = true;
            Serial.println("Regra existente atualizada na ACL.");
            break;
          }
        }

        if (!rule_updated) {
          FirewallRule new_rule;
          new_rule.mac = mac;
          new_rule.policy = (action.equalsIgnoreCase("allow")) ? PERMIT : DENY;
          acl.push_back(new_rule);
          Serial.println("Nova regra adicionada à ACL.");
        }
      }
      break;
    case WStype_ERROR:
    case WStype_FRAGMENT_TEXT_START:
    case WStype_FRAGMENT_BIN_START:
    case WStype_FRAGMENT:
    case WStype_FRAGMENT_FIN:
      break;
  }
}

// --- Funções de Configuração e Loop ---
void setup() {
  Serial.begin(115200);
  Serial.println("\nIniciando Switch SDN v3...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(controller_ssid, controller_password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado à rede de controle.");
  Serial.print("IP do Switch: ");
  Serial.println(WiFi.localIP());

  wifi_config_t conf;
  esp_wifi_get_config(WIFI_IF_STA, &conf);
  esp_wifi_set_channel(conf.sta.channel, WIFI_SECOND_CHAN_NONE);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_callback);

  webSocket.begin(websocket_server_host, websocket_server_port, "/ws");
  webSocket.onEvent(webSocketEvent);
  webSocket.setReconnectInterval(5000);
}

void loop() {
  webSocket.loop();
}