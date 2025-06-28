// --- Firmware do Firewall ---

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <vector>

#include "configs.h"

// --- Configurações de Rede e Segurança ---
const char* ssid = WIFI_SSID;
const char* password = WIFI_PASS;

// Endereço IP do ESP32-Controlador (interface de rede Wi-Fi)
const char* controllerAddress = CONTROLLER_URL; 

// Chave de API secreta compartilhada entre o Firewall e o Controlador
const char* apiKey = API_KEY;

// --- Estrutura de Dados para as Regras de Firewall ---
// Define uma única regra de firewall.
struct FirewallRule {
  String mac_address;
  String action; // "block" ou "allow"
};

// Usa std::vector para armazenar uma lista dinâmica de regras.
std::vector<FirewallRule> rules_to_block;

// --- Protótipos de Funções ---
void connectToWiFi();
void populateFirewallRules();
void sendRulesToController();
void addFirewallRule(String mac, String action);

void setup() {
  Serial.begin(115200);
  delay(1000);

  connectToWiFi();

  // Preenche a lista de regras de firewall com dados de exemplo.
  populateFirewallRules();

  // Envia as regras para o Controlador assim que a conexão for estabelecida.
  if (WiFi.status() == WL_CONNECTED) {
    sendRulesToController();
  } else {
    Serial.println("Falha ao conectar ao WiFi. Não foi possível enviar as regras.");
  }
}

void loop() {
  delay(30000);
}

// --- Implementação das Funções ---

/**
 * @brief Conecta o ESP32 à rede Wi-Fi especificada.
 */
void connectToWiFi() {
  Serial.print("Conectando a ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status()!= WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi conectado!");
    Serial.print("Endereço IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\nFalha na conexão Wi-Fi.");
  }
}

/**
 * @brief Atualiza vetor caso a regra em questão ainda não exista.
 */
void addFirewallRule(String mac, String action) {
  for (const auto& rule : rules_to_block) {
    if (rule.mac_address == mac) return; // já existe
  }
  rules_to_block.push_back({mac, action});
}

/**
 * @brief Adiciona regras de exemplo à lista de bloqueio.
 */
void populateFirewallRules() {
  Serial.println("Populando regras de firewall...");
  addFirewallRule("AA:BB:CC:11:22:33", "block");
  addFirewallRule("DE:AD:BE:EF:44:55", "block");
  addFirewallRule("12:34:56:78:9A:BC", "block");
}

/**
 * @brief Serializa as regras de firewall para JSON e as envia para o Controlador via HTTP POST.
 */
void sendRulesToController() {
  // Verifica se há regras para enviar
  if (rules_to_block.empty()) {
    Serial.println("Nenhuma regra de firewall para enviar.");
    return;
  }

  // Usa o ArduinoJson Assistant para calcular o tamanho necessário
  // JSON_OBJECT_SIZE(1) para o objeto raiz {"rules": [...]}
  // JSON_ARRAY_SIZE(rules_to_block.size()) para o array de regras
  // JSON_OBJECT_SIZE(2) para cada objeto de regra {"mac": "...", "action": "..."}
  const size_t capacity = JSON_OBJECT_SIZE(1) + JSON_ARRAY_SIZE(rules_to_block.size()) + rules_to_block.size() * JSON_OBJECT_SIZE(2);
  DynamicJsonDocument doc(capacity);

  // Cria um array aninhado chamado "rules"
  JsonArray jsonRules = doc.createNestedArray("rules");

  // Itera sobre o vetor de C++ e adiciona cada regra ao array JSON
  for (const auto& rule : rules_to_block) {
    JsonObject ruleObj = jsonRules.createNestedObject();
    ruleObj["mac"] = rule.mac_address;
    ruleObj["action"] = rule.action;
  }

  // Serializa o documento JSON para uma string
  String jsonPayload;
  serializeJson(doc, jsonPayload);

  Serial.println("Payload JSON a ser enviado:");
  serializeJsonPretty(doc, Serial);
  Serial.println();

  // Inicia o cliente HTTP
  HTTPClient http;
  http.begin(controllerAddress);

  // Adiciona os cabeçalhos HTTP necessários
  // O cabeçalho Content-Type informa ao servidor que estamos enviando JSON
  http.addHeader("Content-Type", "application/json");
  // O cabeçalho X-API-Key é usado para autenticação
  http.addHeader("X-API-Key", apiKey);

  // Envia a requisição POST com o payload JSON
  Serial.println("Enviando regras para o Controlador...");
  int httpResponseCode = http.POST(jsonPayload);

  // Processa a resposta do servidor
  if (httpResponseCode > 0) {
    Serial.print("Código de resposta HTTP: ");
    Serial.println(httpResponseCode);
    String responsePayload = http.getString();
    Serial.print("Payload da resposta: ");
    Serial.println(responsePayload);
  } else {
    Serial.print("Falha na requisição HTTP. Erro: ");
    Serial.println(http.errorToString(httpResponseCode).c_str());
  }

  // Libera os recursos
  http.end();
}