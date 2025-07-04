// ||   policy_pusher.cpp (ESP32 Extra)       ||
// - Ao ligar, conecta-se ao Wi-Fi.
// - Envia um conjunto pré-definido de regras para a API no Raspberry Pi.
// - Após enviar, seu trabalho está feito.

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// Configurações
const char* wifi_ssid = "SDN_Control_Net";
const char* wifi_password = "666666";

// IP do Raspberry Pi onde a dashboard_api.py está rodando
const char* pi_api_ip = "192.168.0.236";
const int pi_api_port = 5000;

// Função para instalar uma regra de firewall
void installFirewallRule(const String& ruleJson) {
  HTTPClient http;
  String serverPath = "http://" + String(pi_api_ip) + ":" + String(pi_api_port) + "/ui/add_rule";
  http.begin(serverPath);
  http.addHeader("Content-Type", "application/json");

  Serial.printf("Enviando regra: %s\n", ruleJson.c_str());
  int httpResponseCode = http.POST(ruleJson);

  if (httpResponseCode > 0) {
    Serial.printf("Regra enviada. Resposta do servidor: [%d] %s\n", httpResponseCode,
    http.getString().c_str());
  } else {
    Serial.printf("Erro ao enviar regra: %s\n", http.errorToString(httpResponseCode).c_str());
  }
  http.end();
}

void setup() {
  Serial.begin(115200);

  // Conectar ao Wi-Fi
  Serial.printf("Conectando a %s ", wifi_ssid);
  WiFi.begin(wifi_ssid, wifi_password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado!");

  Serial.println("Instalando políticas de firewall iniciais...");

  // Regra 1: Bloquear um dispositivo específico
  JsonDocument rule1;
  rule1["match"]["mac_address"] = "AA:BB:CC:DD:EE:FF";
  rule1["action"] = "deny";
  String rule1_json;
  serializeJson(rule1, rule1_json);
  installFirewallRule(rule1_json);

  delay(1000);

  // Regra 2: Bloquear outro dispositivo
  JsonDocument rule2;
  rule2["match"]["mac_address"] = "11:22:33:44:55:66";
  rule2["action"] = "deny";
  String rule2_json;
  serializeJson(rule2, rule2_json);
  installFirewallRule(rule2_json);

  Serial.println("Políticas enviadas. O trabalho deste dispositivo terminou.");
}

void loop() {
  delay(60000);
}