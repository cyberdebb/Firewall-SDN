/*
 * ====================================================
 * ||         ESP32 - CONTROLADOR                     ||
 * ====================================================
 * - Agora armazena regras de firewall recebidas via API Northbound.
 * - Usa essas regras para decidir se permite ou nega novos clientes.
 */

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

const char* ssid = "Controlador_SDN_WiFi";
const char* password = "senha_segura";

AsyncWebServer server(80);

// Estruturas de dados
JsonDocument networkState;
JsonDocument firewallRules(2048); // Documento para armazenar as regras do firewall

// Função para verificar se um MAC deve ser bloqueado
String checkFirewallRules(const char* mac) {
  JsonArray rules = firewallRules["rules"].as<JsonArray>();
  for (JsonObject rule : rules) {
    if (String(rule["match"]["mac_address"]) == String(mac)) {
      return rule["action"]; // Retorna "deny" ou "allow"
    }
  }
  return "allow"; // Ação padrão: se não há regra, permite.
}

void setup() {
  Serial.begin(115200);
  Serial.println("\nIniciando Controlador SDN com Módulo de Firewall...");

  networkState["switches"] = JsonArray();
  networkState["clients"] = JsonArray();
  firewallRules["rules"] = JsonArray(); // Inicializa o array de regras

  WiFi.softAP(ssid, password);
  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(IP);

  // --- API SOUTHBOUND (Nenhuma mudança aqui) ---
  server.on("/register", HTTP_POST, ...); // O mesmo código de antes

  // --- LÓGICA DO CONTROLADOR ATUALIZADA ---
  server.on("/events/client_connected", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
    JsonDocument doc;
    deserializeJson(doc, data, len);
    const char* clientMac = doc["client_mac"];
    Serial.printf("Novo cliente [%s] reportado pelo switch.\n", clientMac);

    // Adiciona cliente à lista de "vistos"
    networkState["clients"].add(doc.as<JsonObject>());

    // *** LÓGICA DE DECISÃO CENTRAL ***
    // Consulta as regras do firewall antes de decidir.
    String action = checkFirewallRules(clientMac);
    Serial.printf("Decisão do Firewall para %s: %s\n", clientMac, action.c_str());

    // Envia a regra para o Switch
    JsonDocument ruleToSend;
    ruleToSend["action"] = action;
    ruleToSend["client_mac"] = clientMac;

    String response;
    serializeJson(ruleToSend, response);

    request->send(200, "application/json", response);
    Serial.println("Regra enviada para o switch.");
  });


  // --- NOVA API NORTHBOUND PARA O FIREWALL ---

  // Endpoint para o Firewall instalar uma nova regra
  server.on("/firewall/rules", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total){
    JsonDocument newRule;
    if (deserializeJson(newRule, data, len) == DeserializationError::Ok) {
      firewallRules["rules"].add(newRule.as<JsonObject>());
      Serial.println("Nova regra de firewall instalada:");
      serializeJsonPretty(newRule, Serial);
      Serial.println();
      request->send(200, "text/plain", "Regra instalada.");
    } else {
      request->send(400, "text/plain", "JSON inválido.");
    }
  });

  // Endpoint para ver as regras instaladas
  server.on("/firewall/rules", HTTP_GET, [](AsyncWebServerRequest *request){
    String response;
    serializeJson(firewallRules, response);
    request->send(200, "application/json", response);
  });

  server.begin();
  Serial.println("Servidor HTTP iniciado.");
}

void loop() {
  // ...
}