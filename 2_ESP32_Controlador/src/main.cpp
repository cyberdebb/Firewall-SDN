/*
 * - Atua como o CÉREBRO da rede SDN.
 * - Cria um Access Point (AP) para os clientes e o Switch se conectarem.
 * - Mantém a lista mestre de regras de firewall e a persiste no LittleFS.
 * - Detecta novos clientes em sua rede e toma decisões de firewall LOCALMENTE.
 * - Oferece uma API HTTP para ser gerenciado remotamente pelo Raspberry Pi.
 * - Comanda o(s) Switch(es) via WebSocket, enviando as regras a serem aplicadas.
 */

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

// Configurações da Rede
const char* controller_ssid = "SDN_Control_Net";
const char* controller_password = "666666";

AsyncWebServer server(80);
AsyncWebSocket ws("/ws"); // Endpoint do WebSocket /ws

// Armazenamento de Regras e Estado
JsonDocument firewallRules; // Documento JSON para armazenar as regras de firewall
const char* rulesFilePath = "/firewall_rules.json";

// Salva o documento de regras atual no sistema de arquivos
void saveFirewallRules() {
  File file = LittleFS.open(rulesFilePath, "w");
  if (!file) {
    Serial.println("Falha ao abrir arquivo de regras para escrita.");
    return;
  }
  if (serializeJson(firewallRules, file) == 0) {
    Serial.println("Falha ao escrever no arquivo de regras.");
  } else {
    Serial.println("Regras de firewall salvas no LittleFS.");
  }
  file.close();
}

// Carrega as regras do sistema de arquivos para a memória na inicialização
void loadFirewallRules() {
  if (!LittleFS.begin()) {
    Serial.println("Falha ao montar o LittleFS.");
    return;
  }
  File file = LittleFS.open(rulesFilePath, "r");
  if (!file) {
    Serial.println("Arquivo de regras não encontrado. Começando com lista vazia.");
    firewallRules["rules"] = JsonArray(); // Cria um array vazio se o arquivo não existe
    return;
  }
  DeserializationError error = deserializeJson(firewallRules, file);
  if (error) {
    Serial.println("Falha ao ler o arquivo de regras, usando lista vazia.");
    firewallRules["rules"] = JsonArray();
  } else {
    Serial.println("Regras de firewall carregadas do LittleFS.");
  }
  file.close();
}

// Lógica de Decisão do Firewall
// Consulta a lista LOCAL de regras para decidir a ação para um MAC
String checkLocalFirewallRules(String mac) {
  JsonArray rules = firewallRules["rules"].as<JsonArray>();
  for (JsonObject rule : rules) {
    // A regra vem do Pi, não esquecer
    if (mac.equalsIgnoreCase(rule["match"]["mac_address"])) {
      return rule["action"]; // Retorna a ação
    }
  }
  return "allow"; // Política Padrão: se não há regra específica, permite?
}


// Notifica todos os switches conectados sobre uma nova regra/decisão
void notifySwitches(String message) {
  ws.textAll(message);
  Serial.printf("Notificando switches: %s\n", message.c_str());
}

// Manipulador de eventos do WebSocket (comunicação com os Switches)
void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, AwsEventType type, void *arg,
uint8_t *data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    Serial.printf("Switch conectado via WebSocket: %u\n", client->id());
  } else if (type == WS_EVT_DISCONNECT) {
    Serial.printf("Switch desconectado: %u\n", client->id());
  } else if (type == WS_EVT_DATA) {
    Serial.printf("Mensagem recebida do switch [%u]: %s\n", client->id(), (char*)data);
  }
}

// Detector de cliente
void onClientConnected(WiFiEvent_t event, WiFiEventInfo_t info) {
    char macStr[18];
    // Pega o MAC do cliente que se conectou ao NOSSO AP
    uint8_t* mac_addr = info.wifi_ap_staconnected.mac;
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac_addr[0], mac_addr[1], mac_addr[2],
    mac_addr[3], mac_addr[4], mac_addr[5]);

    Serial.printf("Novo cliente conectado ao AP: %s. Verificando política de firewall...\n", macStr);

    // 1. TOMA A DECISÃO LOCALMENTE
    String action = checkLocalFirewallRules(String(macStr));
    Serial.printf("Decisão local para %s: %s\n", macStr, action.c_str());

    // 2. MONTA A REGRA PARA O SWITCH
    JsonDocument ruleToSend;
    ruleToSend["action"] = action;
    ruleToSend["client_mac"] = macStr;

    String response;
    serializeJson(ruleToSend, response);

    // 3. ENVIA A REGRA PARA O SWITCH VIA WEBSOCKET
    notifySwitches(response);
}


void setup() {
  Serial.begin(115200);
  Serial.println("\nIniciando Controlador SDN...");

  // 1. Carrega as regras de firewall da memória flash
  loadFirewallRules();

  // 2. Configura o ESP32 como um Access Point (AP)
  WiFi.softAP(controller_ssid, controller_password);
  Serial.print("AP do Controlador iniciado. IP: ");
  Serial.println(WiFi.softAPIP());

  // 3. Registra os handlers de eventos
  WiFi.onEvent(onClientConnected, WiFiEvent_t::ARDUINO_EVENT_WIFI_AP_STACONNECTED); // Para novos clientes
  ws.onEvent(onWsEvent); // Para comunicação com os switches
  server.addHandler(&ws);

  // 4. Configura a API DE GERENCIAMENTO para o Raspberry Pi
  // Endpoint para o Pi LER as regras atuais
  server.on("/firewall/rules", HTTP_GET, [](AsyncWebServerRequest *request) {
    String response;
    serializeJson(firewallRules, response);
    request->send(200, "application/json", response);
  });

  // Endpoint para o Pi ENVIAR uma nova regra
  server.on("/firewall/rules", HTTP_POST, [](AsyncWebServerRequest *request){}, NULL,
  [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
    JsonDocument newRule;
    if (deserializeJson(newRule, data, len) == DeserializationError::Ok) {
      firewallRules["rules"].add(newRule.as<JsonObject>());
      saveFirewallRules(); // Salva a nova lista de regras no LittleFS
      request->send(200, "text/plain", "Regra instalada no controlador.");

      // Opcional: notificar os switches sobre a nova regra imediatamente
      // String ruleStr;
      // serializeJson(newRule, ruleStr);
      // notifySwitches(ruleStr);
    } else {
      request->send(400, "text/plain", "JSON inválido.");
    }
  });

  // 5. Inicia o servidor web
  server.begin();
  Serial.println("Servidor web e WebSocket iniciados. Controlador pronto.");
}

void loop() {
  ws.cleanupClients();
  delay(2000);
}