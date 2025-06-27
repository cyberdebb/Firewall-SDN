/*
 * =========================================
 * ||        CÓDIGO: ESP32 - SWITCH        ||
 * =========================================
 * - Cria um Access Point para clientes se conectarem.
 * - Se conecta como Station ao Wi-Fi do Controlador.
 * - Reporta eventos (ex: novo cliente) para o Controlador.
 * - Recebe e armazena regras do Controlador.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// --- Configurações do Switch ---
const char* switch_ap_ssid = "Rede_do_Switch_01";
const char* switch_ap_password = "senha_do_switch";

// --- Configurações para conectar ao Controlador ---
const char* controller_ssid = "Controlador_SDN_WiFi";
const char* controller_password = "senha_segura";
const char* controller_ip = "192.168.4.1"; // IP padrão do Soft AP do ESP32

// Armazenamento local de regras
struct FlowRule {
  String client_mac;
  String action; // "allow" ou "deny"
};
FlowRule flow_table[10]; // Tabela de fluxo para até 10 regras
int rule_count = 0;

// Função para notificar o controlador sobre um novo cliente
void notifyControllerNewClient(String clientMac) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String serverPath = "http://" + String(controller_ip) + "/events/client_connected";
    http.begin(serverPath);
    http.addHeader("Content-Type", "application/json");

    JsonDocument doc;
    doc["switch_mac"] = WiFi.macAddress();
    doc["client_mac"] = clientMac;

    String requestBody;
    serializeJson(doc, requestBody);

    int httpResponseCode = http.POST(requestBody);

    if (httpResponseCode > 0) {
      Serial.printf("Controlador respondeu com código: %d\n", httpResponseCode);
      String payload = http.getString();
      Serial.println("Resposta (Regra recebida): " + payload);

      // Processar a regra recebida
      JsonDocument ruleDoc;
      deserializeJson(ruleDoc, payload);
      const char* action = ruleDoc["action"];
      const char* mac = ruleDoc["client_mac"];

      // Adicionar à tabela de fluxo
      if (rule_count < 10) {
        flow_table[rule_count].client_mac = String(mac);
        flow_table[rule_count].action = String(action);
        rule_count++;
        Serial.println("Nova regra adicionada à tabela de fluxo!");
      }
    } else {
      Serial.printf("Erro na requisição POST: %s\n", http.errorToString(httpResponseCode).c_str());
    }
    http.end();
  }
}

// Callback que é chamado quando um novo cliente se conecta ao AP do Switch
void onClientConnected(WiFiEvent_t event, WiFiEventInfo_t info) {
    char macStr[18];
    // Pega o MAC do cliente que se conectou
    uint8_t* mac = info.wifi_ap_staconnected.mac;
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    Serial.print("Novo cliente se conectou ao AP do Switch! MAC: ");
    Serial.println(macStr);

    // Notifica o controlador
    notifyControllerNewClient(String(macStr));
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Coloca o ESP32 em modo Station + Access Point
  WiFi.mode(WIFI_AP_STA);

  // Configura o Access Point do Switch
  WiFi.softAP(switch_ap_ssid, switch_ap_password);
  Serial.print("Switch AP IP: ");
  Serial.println(WiFi.softAPIP());

  // Registra o callback para o evento de cliente conectado
  WiFi.onEvent(onClientConnected, WiFiEvent_t::ARDUINO_EVENT_WIFI_AP_STACONNECTED);

  // Conecta ao Wi-Fi do Controlador
  Serial.printf("Conectando ao Controlador '%s'...\n", controller_ssid);
  WiFi.begin(controller_ssid, controller_password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado ao Controlador!");
  Serial.print("IP do Switch na rede do controlador: ");
  Serial.println(WiFi.localIP());

  // --- REGISTRA O SWITCH NO CONTROLADOR ---
  HTTPClient http;
  String serverPath = "http://" + String(controller_ip) + "/register";
  http.begin(serverPath);
  http.addHeader("Content-Type", "application/json");

  JsonDocument doc;
  doc["mac_address"] = WiFi.macAddress();
  doc["ip_address"] = WiFi.localIP().toString();
  String requestBody;
  serializeJson(doc, requestBody);

  int httpResponseCode = http.POST(requestBody);
  if(httpResponseCode > 0) {
    Serial.printf("Switch registrado! Resposta do controlador: %s\n", http.getString().c_str());
  } else {
    Serial.printf("Falha ao registrar. Erro: %s\n", http.errorToString(httpResponseCode).c_str());
  }
  http.end();
}

void loop() {
  // A lógica principal é baseada em eventos.
  // O loop pode ser usado para verificar a validade das regras, etc.

  // LÓGICA DE APLICAÇÃO DE REGRA (SIMPLIFICADA):
  // Aqui, poderíamos iterar sobre os clientes conectados e, se uma regra "deny"
  // existir para um deles, poderíamos forçar a desconexão.
  // wifi_sta_list_t sta_list;
  // esp_wifi_ap_get_sta_list(&sta_list);
  // for (int i = 0; i < sta_list.num; i++) {
  //   // ... verificar MAC e comparar com a flow_table ...
  //   // Se for "deny", usar esp_wifi_deauth_sta(sta_list.sta[i].aid)
  // }

  delay(5000);
}