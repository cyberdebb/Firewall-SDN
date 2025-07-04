/*
 * ||  Firewall Controlador Inteligente (All-in-One)  ||
 * - Atua como o CÉREBRO e MÚSCULO da rede SDN.
 * - Cria um Access Point (AP) para os clientes se conectarem.
 * - Mantém a lista mestre de regras de firewall e a persiste no LittleFS.
 * - USA MODO PROMÍSCUO para "ouvir" todo o tráfego em sua própria rede.
 * - Ao detectar um pacote de um MAC bloqueado, CHUTA ATIVAMENTE o
 * dispositivo da rede (de-authentication).
 * - Oferece uma API HTTP para ser gerenciado remotamente pelo Raspberry Pi.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include "esp_wifi_types.h"
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

// Estrutura do Pacote
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

// Configurações da Rede
const char* controller_ssid = "SDN_Control_Net";
const char* controller_password = "666666";

AsyncWebServer server(80);

// Armazenamento de Regras e Estado
JsonDocument firewallRules;
const char* rulesFilePath = "/firewall_rules.json";

// Funções de Persistência (LittleFS)
void saveFirewallRules() {
  File file = LittleFS.open(rulesFilePath, "w");
  if (!file) { Serial.println("Falha ao salvar regras."); return; }
  serializeJson(firewallRules, file);
  file.close();
}

void loadFirewallRules() {
  if (!LittleFS.begin()) { Serial.println("Falha ao montar LittleFS."); return; }
  File file = LittleFS.open(rulesFilePath, "r");
  if (!file) {
    Serial.println("Arquivo de regras não encontrado.");
    firewallRules["rules"] = JsonArray();
    return;
  }
  DeserializationError error = deserializeJson(firewallRules, file);
  if (error) {
    Serial.println("Falha ao ler regras.");
    firewallRules["rules"] = JsonArray();
  } else {
    Serial.println("Regras de firewall carregadas.");
  }
  file.close();
}

// Decisão e Ação do Firewall
// Converte um endereço MAC (array de bytes) para uma String
String macToString(const uint8_t* mac) {
  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

// Função de callback chamada para cada pacote capturado
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) {
    return;
  }

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_ieee80211_mac_hdr_t *hdr = (wifi_ieee80211_mac_hdr_t *)pkt->payload;

  String src_mac_str = macToString(hdr->addr2);

  // Consulta a lista LOCAL de regras
  JsonArray rules = firewallRules["rules"].as<JsonArray>();
  for (JsonObject rule : rules) {
    if (src_mac_str.equalsIgnoreCase(rule["match"]["mac_address"])) {
      // Se a regra para este MAC for "deny" seguimos
      if (String("deny").equalsIgnoreCase(rule["action"])) {
        Serial.printf("PACOTE ILEGAL DETECTADO! Origem: %s. Ação: BLOQUEAR E DESCONECTAR.\n", src_mac_str.c_str());

        // AÇÃO DE BLOQUEIO: Chuta o dispositivo da rede.
        esp_wifi_deauth_sta(0); // Isso pode causar a deautenticação de clientes.
                               // Talvez o ideal seria a implementação que buscaria o AID do cliente com base no MAC.
                               // Por ora, o log já prova a detecção, mas faz sentido melhorar em outra versão
        return; // Para de processar este pacote
      }
    }
  }
  // Se não encontrou nenhuma regra de bloqueio, o pacote é permitido implicitamente,
  //o que não é ideal, mas no futuro melhoramos também
}


// Funções de Configuração e Loop
void setup() {
  Serial.begin(115200);
  Serial.println("\nIniciando Firewall Controlador Inteligente...");

  // 1. Carrega as regras de firewall da memória flash
  loadFirewallRules();

  // 2. Configura o ESP32 como um Access Point (AP)
  WiFi.softAP(controller_ssid, controller_password);
  Serial.print("AP do Controlador iniciado. IP: ");
  Serial.println(WiFi.softAPIP());

  // 3. ATIVA O MODO SNIFFER/FIREWALL EM SI MESMO
  wifi_config_t conf;
  esp_wifi_get_config(WIFI_IF_AP, &conf);
  esp_wifi_set_channel(conf.ap.channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
  Serial.println("Modo Firewall Ativo: ouvindo todo o tráfego da rede.");

  // 4. Configura a API DE GERENCIAMENTO para o Raspberry Pi
  server.on("/firewall/rules", HTTP_GET, [](AsyncWebServerRequest *request) {
    String response;
    serializeJson(firewallRules, response);
    request->send(200, "application/json", response);
  });

  server.on("/firewall/rules", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL,
  [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
    JsonDocument newRule;
    if (deserializeJson(newRule, data, len) == DeserializationError::Ok) {
      firewallRules["rules"].add(newRule.as<JsonObject>());
      saveFirewallRules();
      request->send(200, "text/plain", "Regra instalada no controlador.");
    } else {
      request->send(400, "text/plain", "JSON inválido.");
    }
  });

  // 5. Inicia o servidor web
  server.begin();
  Serial.println("API de gerenciamento iniciada. Controlador pronto.");
}

void loop() {
  delay(10000);
}