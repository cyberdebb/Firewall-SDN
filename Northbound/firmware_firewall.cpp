/*
 * ========================================================
 * ||        FIRMWARE: ESP32 - FIREWALL NORTHBOUND         ||
 * ========================================================
 * - Contém as políticas de segurança da rede.
 * - Ao iniciar, se conecta ao Controlador e envia as regras
 * de firewall para ele via API Northbound.
 * - Pode usar de exemplo e dar uma estudada nesse código Débora, não precisa fazer igual
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

const char* controller_ssid = "Controlador_SDN_WiFi";
const char* controller_password = "senha_segura";
const char* controller_ip = "192.168.4.1";

// Função para instalar uma regra no controlador
void installFirewallRule(const String& ruleJson) {
  HTTPClient http;
  String serverPath = "https://" + String(controller_ip) + "/firewall/rules";
  http.begin(serverPath);
  http.addHeader("Content-Type", "application/json");

  int httpResponseCode = http.POST(ruleJson);

  if (httpResponseCode > 0) {
    Serial.printf("Regra enviada. Resposta do controlador: [%d] %s\n", httpResponseCode, http.getString().c_str());
  } else {
    Serial.printf("Erro ao enviar regra: %s\n", http.errorToString(httpResponseCode).c_str());
  }
  http.end();
}

void setup() {
  Serial.begin(115200);

  // Conectar ao Wi-Fi do Controlador
  Serial.printf("Firewall conectando a %s ", controller_ssid);
  WiFi.begin(controller_ssid, controller_password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConectado ao Controlador!");

  // --- POLÍTICA DE SEGURANÇA (LISTA DE REGRAS) ---
  Serial.println("Instalando políticas de firewall...");

  // Regra 1: Bloquear um dispositivo específico (ex: uma câmera de segurança)
  JsonDocument rule1;
  rule1["rule_id"] = "block_camera_mac";
  rule1["match"]["mac_address"] = "AA:BB:CC:DD:EE:FF"; // <-- Mudar para o MAC a ser bloqueado
  rule1["action"] = "deny";
  String rule1_json;
  serializeJson(rule1, rule1_json);
  installFirewallRule(rule1_json);

  delay(500);

  // Regra 2: Bloquear outro dispositivo (ex: um celular antigo)
  JsonDocument rule2;
  rule2["rule_id"] = "block_old_phone";
  rule2["match"]["mac_address"] = "11:22:33:44:55:66"; // <-- Mudar para o MAC a ser bloqueado
  rule2["action"] = "deny";
  String rule2_json;
  serializeJson(rule2, rule2_json);
  installFirewallRule(rule2_json);

  Serial.println("Políticas de firewall enviadas para o controlador.");
  Serial.println("O módulo de firewall agora está em modo de monitoramento.");
}
