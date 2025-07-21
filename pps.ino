// Pocket Password Storage — Final MVP Version
// core: Wi-Fi fallback, web server, AES encryption, password storage, UI interaction + auth

#include <Arduino.h>
#include <SPIFFS.h>    // вместо <LittleFS.h>
#include <FS.h>
#include <EEPROM.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <mbedtls/aes.h>
#include "interface.h"
#include <esp_partition.h>  // для esp_partition_find_first
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include <mbedtls/gcm.h>
#include <vector>
#include <DNSServer.h>

#define AES_KEY_SIZE 16
#define FILE_NAME "/passwords.enc"
#define EEPROM_ADDR 0

// Состояние Wi-Fi
enum WiFiState { WIFI_INIT, WIFI_CONNECTING, WIFI_CONNECTED, AP_MODE };
static WiFiState wifiState = WIFI_INIT;
static unsigned long wifiStartMillis = 0;
static const unsigned long WIFI_TIMEOUT_MS = 10000; // 10 секунд
volatile bool rebootPending = false;
String deviceSalt = "";

// Хранение конфигурации
struct WiFiConfig {
  String ssid;
  String password;
  String ap_ssid;
  String ap_password;
};
WiFiConfig wifiCfg;

int attempts = 0;
bool checked = false;
bool initialSetup = false;
uint8_t master_key[AES_KEY_SIZE];
WebServer server(80);
DNSServer dnsServer;

struct Session { String t; unsigned long exp; };
std::vector<Session> sessions;

static uint8_t failCount = 0;
static unsigned long blockUntil = 0;

bool loadPasswordsArray(DynamicJsonDocument&);

String generateRandomSalt(uint16_t length = 16) {
  const char hexChars[] = "0123456789abcdef";
  String salt = "";
  for (uint16_t i = 0; i < length; i++) {
    uint8_t byte = random(0, 256);
    salt += String(hexChars[(byte >> 4) & 0x0F]);
    salt += String(hexChars[byte & 0x0F]);
  }
  return salt;
}

String newToken() {
  char buf[33];
  for (int i=0;i<32;i++) buf[i]= "0123456789abcdef"[esp_random() % 16];
  buf[32]='\0';
  return String(buf);
}

bool getPasswordsDoc(DynamicJsonDocument &doc) {
   if (!loadPasswordsArray(doc)) { server.send(500); return false; }
   return doc.is<JsonArray>();
}

bool validIndex(JsonArray arr, int idx){
   return idx>=0 && idx < (int)arr.size();
}

bool getIndexParam(int &outIdx) {
    if (!server.hasArg("plain")) { server.send(400, "text/plain", "No data"); return false; }

    StaticJsonDocument<64> inJson;
    if (deserializeJson(inJson, server.arg("plain"))) {
        server.send(400, "text/plain", "Invalid JSON"); return false;
    }

    outIdx = inJson["index"] | -1;
    if (outIdx < 0) { server.send(400, "text/plain", "Bad index"); return false; }
    return true;
}

bool isAuthorized() {
  if (!server.hasHeader("Authorization")) return false;
  String hdr = server.header("Authorization");
  if (!hdr.startsWith("Bearer ")) return false;
  String tok = hdr.substring(7);
  unsigned long now = millis();
  for (auto &s:sessions) if (s.t==tok && now < s.exp) return true;
  return false;
}

void purgeSessions() {
  unsigned long now = millis();
  sessions.erase(
      std::remove_if(sessions.begin(), sessions.end(),
         [&](Session const& s){ return now > s.exp; }),
      sessions.end());
}

bool gcmEncrypt(const uint8_t *plain, size_t len, std::vector<uint8_t> &cipher, uint8_t iv[12], uint8_t tag[16]) {
    mbedtls_gcm_context ctx; mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           master_key, 128) != 0) return false;

    for (int i=0;i<12;i++) iv[i]=random(0,256);

    cipher.resize(len);
    int ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                len, iv, 12, nullptr, 0,
                plain, cipher.data(), 16, tag);
    mbedtls_gcm_free(&ctx);
    return ret==0;
}

bool gcmDecrypt(const uint8_t *cipher, size_t len, const uint8_t iv[12], const uint8_t tag[16], std::vector<uint8_t> &plain) {
    mbedtls_gcm_context ctx; mbedtls_gcm_init(&ctx);
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                           master_key, 128)!=0) return false;

    plain.resize(len);
    int ret = mbedtls_gcm_auth_decrypt(&ctx, len,
              iv, 12, nullptr, 0,
              tag, 16, cipher, plain.data());
    mbedtls_gcm_free(&ctx);
    return ret==0;
}

/* ---------- общая подпрограмма: грузим массив паролей ---------- */
bool loadPasswordsArray(DynamicJsonDocument &doc) {
  doc.to<JsonArray>();

  if (!SPIFFS.exists(FILE_NAME)) return true;

  File f = SPIFFS.open(FILE_NAME, "r");
  size_t sz = f.size();
  if (sz <= 28) { f.close(); return true; } // 12 iv + 16 tag

  uint8_t iv[12], tag[16];
  f.read(iv,12); f.read(tag,16);
  sz -= 28;
  std::vector<uint8_t> cipher(sz);
  f.read(cipher.data(), sz);
  f.close();

  std::vector<uint8_t> plain;
  if (!gcmDecrypt(cipher.data(), sz, iv, tag, plain)) return false;

  DeserializationError err = deserializeJson(doc,
        (const char*)plain.data(), plain.size());
  return !err && doc.is<JsonArray>();
}

/* ---------- сохраняем массив обратно ---------- */
bool savePasswordsArray(JsonArray arr) {
  String jsonStr;  serializeJson(arr, jsonStr);

  uint8_t iv[12], tag[16];
  std::vector<uint8_t> cipher;
  if (!gcmEncrypt((const uint8_t*)jsonStr.c_str(),
                  jsonStr.length(), cipher, iv, tag)) return false;

  File f = SPIFFS.open(FILE_NAME, "w");
  f.write(iv, 12);                 // nonce
  f.write(tag,16);                 // auth-tag
  f.write(cipher.data(), cipher.size());
  f.close();
  return true;
}

bool loadSalt() {
  if (!SPIFFS.exists("/settings.json")) {
    Serial.println("⚠️ settings.json не найден");
    return false;
  }

  File f = SPIFFS.open("/settings.json", "r");
  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();

  if (err) {
    Serial.println("❌ Ошибка чтения settings.json");
    return false;
  }

  if (!doc.containsKey("salt")) {
    Serial.println("❌ В settings.json нет соли");
    return false;
  }

  deviceSalt = doc["salt"].as<String>();
  Serial.print("✅ Загрузили соль: ");
  Serial.println(deviceSalt);
  return true;
}

bool saveSalt(const String& salt) {
  StaticJsonDocument<256> doc;
  doc["salt"] = salt;

  File f = SPIFFS.open("/settings.json", "w");
  if (!f) {
    Serial.println("❌ Не удалось открыть settings.json для записи");
    return false;
  }
  serializeJson(doc, f);
  f.close();
  Serial.println("✅ Соль сохранена в settings.json");
  return true;
}

bool deriveKeyFromPassword(const String& password, const String& saltHex, uint8_t* output, size_t outLen) {
  uint8_t saltBytes[16];
  for (int i = 0; i < 16; i++) {
    char byteStr[3] = { saltHex[i * 2], saltHex[i * 2 + 1], 0 };
    saltBytes[i] = strtoul(byteStr, nullptr, 16);
  }

  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(
    MBEDTLS_MD_SHA256,                             // тип хеша
    (const unsigned char*)password.c_str(), password.length(), // пароль
    saltBytes, sizeof(saltBytes),                  // соль
    10000,                                          // итерации
    outLen,                                         // длина выходного ключа
    output                                          // буфер для результата
  );

  return (ret == 0);
}

// --- считываем настройки из SPIFFS (вызывать один раз в setup) ---
void loadWiFiConfig() {
  if (!SPIFFS.exists("/settings.json")) {
    wifiCfg = { "", "" };
    return;
  }

  File f = SPIFFS.open("/settings.json", "r");
  StaticJsonDocument<512> doc;
  if (deserializeJson(doc, f) == DeserializationError::Ok) {
    if (doc.containsKey("ssid") && doc.containsKey("password")) {
      wifiCfg.ssid     = doc["ssid"].as<String>();
      wifiCfg.password = doc["password"].as<String>();
      wifiCfg.ap_password = doc["ap_password"] | ""; // по умолчанию пусто
    } else {
      wifiCfg = { "", "" }; // 👈 если нет Wi-Fi настроек, сбрасываем
    }
  } else {
    wifiCfg = { "", "" }; // 👈 если ошибка чтения
  }
  f.close();
}

// --- инициализация Wi-Fi, вызывается из setup() ---
void initWiFi() {
  loadWiFiConfig();

  WiFi.mode(WIFI_STA);
  if (wifiCfg.ssid.length()) {
    Serial.printf("📡 Trying to connect to '%s'\n", wifiCfg.ssid.c_str());
    WiFi.begin(wifiCfg.ssid.c_str(), wifiCfg.password.c_str());
    wifiState = WIFI_CONNECTING;
    wifiStartMillis = millis();
  } else {
    // нет сохранённых данных — сразу в AP
    Serial.println("❌ No SSID saved, starting AP");
    String apName = wifiCfg.ap_ssid.length() > 0 ? wifiCfg.ap_ssid : "Pocket-Password-Setup";
    if (wifiCfg.ap_password.length() >= 8) {
      WiFi.softAP(apName.c_str(), wifiCfg.ap_password.c_str());
    } else {
      WiFi.softAP(apName.c_str()); // без пароля
    }
    Serial.print("📶 AP IP: "); Serial.println(WiFi.softAPIP());
    wifiState = AP_MODE;
  }
}

bool isKeyValid() {
  if (!server.hasHeader("Authorization")) {
    Serial.println("[Auth] ❌ Нет заголовка Authorization");
    return false;
  }

  String key = server.header("Authorization");
  if (key.length() != 32) {
    Serial.println("[Auth] ❌ Длина ключа не 32 символа");
    return false;
  }

  for (int i = 0; i < 16; i++) {
    char byteStr[3] = {
      (char)tolower(key[i * 2]),
      (char)tolower(key[i * 2 + 1]),
      0
    };
    uint8_t byte = strtoul(byteStr, nullptr, 16);

    if (master_key[i] != byte) {
      Serial.println("[Auth] ❌ Несовпадение байта → отказ");
      return false;
    }
  }

  Serial.println("[Auth] ✅ Пароль принят");
  return true;
}

// --- проверка и перевод между состояниями, вызывается в loop() ---
void handleWiFi() {
  switch (wifiState) {
    case WIFI_CONNECTING:
      // если подключились раньше таймаута
      if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n✅ Wi-Fi connected!");
        Serial.print("📡 IP: "); Serial.println(WiFi.localIP());
        wifiState = WIFI_CONNECTED;
      }
      // если вышли за таймаут и ещё не подключены
      else if (millis() - wifiStartMillis > WIFI_TIMEOUT_MS) {
        Serial.println("\n❌ Wi-Fi timeout, switching to AP");
        WiFi.softAP("PPS-Setup");
        Serial.print("📶 AP IP: "); Serial.println(WiFi.softAPIP());
        wifiState = AP_MODE;
      } else {
        // печатаем точки не чаще, чем каждые 500 мс
        static unsigned long lastDot = 0;
        if (millis() - lastDot > 500) {
          Serial.print('.');
          lastDot = millis();
        }
      }
      break;

    case WIFI_CONNECTED:
      // здесь можно отслеживать разрыв и переход обратно в AP, если нужно
      if (WiFi.status() != WL_CONNECTED) {
        Serial.println("⚠️ Wi-Fi lost, restarting AP");
        WiFi.softAP("PPS-Setup");
        Serial.print("📶 AP IP: "); Serial.println(WiFi.softAPIP());
        wifiState = AP_MODE;
      }
      break;

    case AP_MODE:
      // при желании можно следить за появлением сохранённых creds и пытаться STA
      break;

    default:
      break;
  }
}

void loadMasterKey() {
  Serial.println("🔓 Loading master_key from EEPROM...");

  bool empty = true;
  for(int i=0; i<AES_KEY_SIZE; i++){
    master_key[i] = EEPROM.read(EEPROM_ADDR + i);
    if (master_key[i] != 0xFF) empty = false;
  }

  if (empty) {
    Serial.println("⚙️ EEPROM empty — entering initial setup mode");
    initialSetup = true;
  } else {
    Serial.print("🔑 Final Master Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) Serial.printf("%02X ", master_key[i]);
    Serial.println();
  }
}

void handleSetMasterKey() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  Serial.println(">> handleSetMasterKey called");
  Serial.println("Body: " + server.arg("plain"));
  if (!server.hasArg("plain")) return server.send(400, "text/plain", "No data received");
  StaticJsonDocument<128> doc;
  if (deserializeJson(doc, server.arg("plain"))) return server.send(400, "text/plain", "Invalid JSON");
  const char* newKeyHex = doc["key"];
  if (strlen(newKeyHex) != 32) return server.send(400, "text/plain", "Invalid key length");
  for (int i = 0; i < 16; i++) {
    char byteStr[3] = { newKeyHex[i * 2], newKeyHex[i * 2 + 1], 0 };
    master_key[i] = strtoul(byteStr, nullptr, 16);
    EEPROM.write(EEPROM_ADDR + i, master_key[i]);
  }
  EEPROM.commit();
  server.send(200, "text/plain", "Master key updated");
}

void handleGetSettings() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }
  StaticJsonDocument<256> doc;
  if (SPIFFS.exists("/settings.json")) {
    File f = SPIFFS.open("/settings.json", "r");
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (err) doc.clear();
  }
  // формируем ответ
  StaticJsonDocument<256> out;
  out["ssid"]     = doc["ssid"]     | "";
  out["password"] = doc["password"] | "";
  String s; serializeJson(out, s);
  server.send(200, "application/json", s);
}

void handleSaveSettings() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }
  if (!server.hasArg("plain")) return server.send(400, "text/plain", "No data");

  StaticJsonDocument<512> currentDoc;
  if (SPIFFS.exists("/settings.json")) {
    File f = SPIFFS.open("/settings.json", "r");
    deserializeJson(currentDoc, f);
    f.close();
  }

  StaticJsonDocument<256> newDoc;
  auto err = deserializeJson(newDoc, server.arg("plain"));
  if (err) return server.send(400, "text/plain", "Invalid JSON");

  // Обновляем только те поля, которые пришли
  if (newDoc.containsKey("ssid")) {
    currentDoc["ssid"] = newDoc["ssid"];
  }
  if (newDoc.containsKey("password")) {
    currentDoc["password"] = newDoc["password"];
  }
  if (newDoc.containsKey("ap_ssid")) {
    currentDoc["ap_ssid"] = newDoc["ap_ssid"];
  }
  if (newDoc.containsKey("ap_password")) {
    currentDoc["ap_password"] = newDoc["ap_password"];
  }

  // Сохраняем обратно
  File f = SPIFFS.open("/settings.json", "w");
  if (!f) return server.send(500, "text/plain", "FS error");
  serializeJson(currentDoc, f);
  f.close();

  server.send(200, "text/plain", "OK");
  rebootPending = true;
}

void handleGetPasswords() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }

  DynamicJsonDocument doc(4096);
  if (!loadPasswordsArray(doc)) {
    server.send(500, "text/plain", "Decrypt error");
    return;
  }

  String out;
  serializeJson(doc, out);
  server.send(200, "application/json", out);
}

void handleAddPassword() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }
  if (!server.hasArg("plain")) {
    server.send(400, "text/plain", "No data"); return;
  }

  /* 1. Разбираем новую запись */
  StaticJsonDocument<256> newEntry;
  if (deserializeJson(newEntry, server.arg("plain")) || !newEntry.is<JsonObject>()){
    server.send(400, "text/plain", "Invalid JSON");  return;
  }

  /* 2. Грузим текущий массив */
  DynamicJsonDocument doc(4096);
  if (!loadPasswordsArray(doc)) {
    server.send(500, "text/plain", "Decrypt error"); return;
  }

  /* 3. Добавляем и сохраняем */
  JsonArray arr = doc.as<JsonArray>();
  arr.add(newEntry);

  if (!savePasswordsArray(arr)) {
    server.send(500, "text/plain", "Save error");    return;
  }

  server.send(200, "text/plain", "OK");
}

/* ---------- DELETE /deletePassword (POST, body: {index}) ------- */
void handleDeletePassword() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }
  if (!server.hasArg("plain"))       { server.send(400, "text/plain", "No data");     return; }

  int idx;
  if (!getIndexParam(idx)) return;

  DynamicJsonDocument doc(4096);
  if (!getPasswordsDoc(doc)) return;

  JsonArray arr = doc.as<JsonArray>();
  if (!validIndex(arr, idx)) { server.send(400, "text/plain", "Index out of range"); return; }

  arr.remove(idx);
  if (!savePasswordsArray(arr)) { server.send(500, "text/plain", "Save error"); return; }

  server.send(200, "text/plain", "OK");
}

/* ---------- POST /editPassword  body: {index: n, … поля …} ----- */
void handleEditPassword() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }
  if (!server.hasArg("plain"))       { server.send(400, "text/plain", "No data");     return; }

  /* читаем данные и index */
  StaticJsonDocument<512> upd;
  if (deserializeJson(upd, server.arg("plain"))) {
      server.send(400, "text/plain", "Invalid JSON"); return;
  }
  int idx = upd["index"] | -1;
  upd.remove("index");
  if (idx < 0 || upd.size()==0) {
      server.send(400, "text/plain", "Bad data"); return;
  }

  /* получаем массив и валидируем индекс единым способом */
  DynamicJsonDocument doc(4096);
  if (!getPasswordsDoc(doc)) return;
  JsonArray arr = doc.as<JsonArray>();
  if (!validIndex(arr, idx)) { server.send(400, "text/plain", "Index out of range"); return; }

  JsonObject entry = arr[idx];
  for (JsonPair kv : upd.as<JsonObject>()) {
      entry[kv.key()] = kv.value();
  }
  if (!savePasswordsArray(arr)) { server.send(500, "text/plain", "Save error"); return; }

  server.send(200, "text/plain", "OK");
}

/* ====== GET  /exportPasswords  — выгрузка JSON-массива ========= */
void handleExportPasswords() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }

  DynamicJsonDocument doc(4096);
  if (!loadPasswordsArray(doc)) {
    server.send(500, "text/plain", "Decrypt error"); return;
  }

  String out;                // отдаём в чистом виде, без шифрования
  serializeJson(doc, out);
  server.send(200, "application/json", out);
}

/* ====== POST /importPasswords  — полная замена базы ============ */
void handleImportPasswords() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (server.hasArg("plain") && server.arg("plain").length() > 32768) {
      server.send(413, "text/plain", "Request too large");
      return;
  }

  if (!isAuthorized()) { server.send(401); return; }
  if (!server.hasArg("plain")) {
    server.send(400, "text/plain", "No data"); return;
  }

  DynamicJsonDocument doc(4096);
  DeserializationError err = deserializeJson(doc, server.arg("plain"));
  if (err || !doc.is<JsonArray>()) {
    server.send(400, "text/plain", "Invalid JSON"); return;
  }

  if (!savePasswordsArray(doc.as<JsonArray>())) {
    server.send(500, "text/plain", "Save error"); return;
  }

  server.send(200, "text/plain", "OK");
}

void handleLogin() {
  if (!server.hasArg("plain")) {
    server.send(400, "text/plain", "Нет данных");
    return;
  }

  if (millis() < blockUntil) { server.send(429,"text/plain","Slow down"); return; }

  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, server.arg("plain"));
  if (err) {
    server.send(400, "text/plain", "Неверный JSON");
    return;
  }

  String password = doc["password"];
  if (password.length() < 4) {
    server.send(400, "text/plain", "Пароль слишком короткий");
    return;
  }

  uint8_t testKey[16];
  if (!deriveKeyFromPassword(password, deviceSalt, testKey, 16)) {
    server.send(500, "text/plain", "Ошибка PBKDF2");
    return;
  }

  // Сравниваем полученный ключ с сохранённым master_key[]
  for (int i = 0; i < 16; i++) {
    if (master_key[i] != testKey[i]) {
      Serial.println("❌ Неверный пароль");
      failCount++;
      if (failCount>4) {
        blockUntil = millis()+ (1<<failCount)*1000; // 2-4-8-16 с
      }
      server.send(401, "text/plain", "Неверный пароль");
      return;
    }
  }

  Serial.println("✅ Успешный вход");
  purgeSessions();
  String tok = newToken();
  sessions.push_back({ tok, millis()+30*60*1000UL }); // 30 мин
  failCount=0;

  StaticJsonDocument<64> out; out["token"]=tok;
  String s; serializeJson(out,s);
  server.send(200,"application/json", s);
}

String getContentType(const String& path) {
  if (path.endsWith(".html")) return "text/html";
  if (path.endsWith(".css"))  return "text/css";
  if (path.endsWith(".js"))   return "application/javascript";
  return "text/plain";
}

void handleFileRead() {
  String path = server.uri();

  /* ➊  Корневой запрос → index.html */
  if (path == "/") path = "/index.html";

  /* ➋  Пока устройство не инициализировано – отдаём init.html,
         кроме css/js/json, чтобы страница могла загрузиться  */
  if (initialSetup) {
    if (!(path.endsWith(".css") || path.endsWith(".js") ||
          path.endsWith(".json") || path == "/initKey"))
    {
      File f = SPIFFS.open("/init.html", "r");
      server.sendHeader("Cache-Control", "no-cache");
      server.streamFile(f, "text/html");
      f.close();
      return;
    }
  }

  /* ➍  Отдаём статический файл (css/js/html/…) */
  if (!SPIFFS.exists(path)) {          // на всякий случай 404
    server.send(404, "text/plain", "File not found");
    return;
  }
  File file = SPIFFS.open(path, "r");
  server.sendHeader("Cache-Control", "no-cache");
  server.streamFile(file, getContentType(path));
  file.close();
}

void handleInitKey() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!server.hasArg("plain")) {
    server.send(400, "text/plain", "Нет данных");
    return;
  }

  StaticJsonDocument<256> doc;
  DeserializationError err = deserializeJson(doc, server.arg("plain"));
  if (err) {
    server.send(400, "text/plain", "Неверный JSON");
    return;
  }

  String password = doc["password"];
  if (password.length() < 4) {
    server.send(400, "text/plain", "Пароль слишком короткий");
    return;
  }

  uint8_t derivedKey[16];
  if (!deriveKeyFromPassword(password, deviceSalt, derivedKey, 16)) {
    server.send(500, "text/plain", "Ошибка PBKDF2");
    return;
  }

  // Сохраняем Derived Key в EEPROM
  for (int i = 0; i < 16; i++) {
    EEPROM.write(i, derivedKey[i]);
  }
  EEPROM.commit();

  Serial.println("✅ Мастер-ключ сохранён");

  server.send(200, "text/plain", "Мастер-пароль установлен");

  Serial.println("⌛ Ожидание 3 секунды перед перезапуском...");
  delay(3000);
  ESP.restart();
}

void handleChangeMasterKey() {
  if (server.hasHeader("Origin")) {
      String o = server.header("Origin");
      String ip = WiFi.localIP().toString();
      if (!o.startsWith("http://" + ip) && !o.startsWith("http://pps.local")) {
          server.send(403);
          return;
      }
  }

  if (!isAuthorized()) { server.send(401); return; }

  if (!server.hasArg("plain")) {
    server.send(400, "text/plain", "No data");
    return;
  }

  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, server.arg("plain")) != DeserializationError::Ok) {
    server.send(400, "text/plain", "Invalid JSON");
    return;
  }

  String oldKey = doc["old_key"];
  String newKey = doc["new_key"];

  if (oldKey.length() != 32 || newKey.length() != 32) {
    server.send(400, "text/plain", "Bad keys");
    return;
  }

  // Проверяем старый ключ
  for (int i = 0; i < 16; i++) {
    char byteStr[3] = { (char)tolower(oldKey[i * 2]), (char)tolower(oldKey[i * 2 + 1]), 0 };
    uint8_t byte = strtoul(byteStr, nullptr, 16);
    if (master_key[i] != byte) {
      server.send(401, "text/plain", "Incorrect old password");
      return;
    }
  }

  // Записываем новый ключ
  for (int i = 0; i < 16; i++) {
    char byteStr[3] = { (char)tolower(newKey[i * 2]), (char)tolower(newKey[i * 2 + 1]), 0 };
    master_key[i] = strtoul(byteStr, nullptr, 16);
    EEPROM.write(EEPROM_ADDR + i, master_key[i]);
  }
  EEPROM.commit();

  server.send(200, "text/plain", "Master key changed");

  delay(100);
  ESP.restart();
}

void handleGetSalt() {
  StaticJsonDocument<64> doc;
  doc["salt"] = deviceSalt;
  String out;
  serializeJson(doc, out);
  server.send(200, "application/json", out);
}

void setupWebServer() {
  server.on("/getPasswords", HTTP_GET, handleGetPasswords);
  server.on("/exportPasswords", HTTP_GET,  handleExportPasswords);
  server.on("/importPasswords", HTTP_POST, handleImportPasswords);
  server.on("/addPassword", HTTP_POST, handleAddPassword);
  server.on("/setMasterKey", HTTP_POST, handleSetMasterKey);
  server.on("/settings", HTTP_GET, handleGetSettings);
  server.on("/saveSettings", HTTP_POST, handleSaveSettings);
  server.on("/settings.html", HTTP_GET, []() {
    File f = SPIFFS.open("/settings.html", "r");
    server.streamFile(f, "text/html");
    f.close();
  });
  server.on("/initKey", HTTP_POST, handleInitKey);
  server.on("/changeMasterKey", HTTP_POST, handleChangeMasterKey);
  server.on("/login", HTTP_POST, handleLogin);
  server.on("/deletePassword", HTTP_POST, handleDeletePassword);
  server.on("/editPassword",   HTTP_POST, handleEditPassword);
  server.on("/getSalt", HTTP_GET, handleGetSalt);
  server.onNotFound(handleFileRead);
  server.begin();
  Serial.println("✅ Web server started!");
}

void setup() {
  Serial.begin(115200);
  delay(100);

  EEPROM.begin(64);

  while(!Serial);  // дождаться монитора

  if (!SPIFFS.begin()) {
    Serial.println("❌ SPIFFS mount failed!");
    while(true) delay(1000);

  }
  Serial.println("✅ SPIFFS mounted");
  
  // Проверка наличия соли
  if (!loadSalt()) {
    Serial.println("⚠️ Соль не найдена, создаём новую...");
    String newSalt = generateRandomSalt(16);
    saveSalt(newSalt);
    deviceSalt = newSalt;
  }

  setupInterface();
  loadMasterKey();
  initWiFi();
  setupWebServer();

  if (wifiState == AP_MODE) {
      dnsServer.start(53, "*", WiFi.softAPIP());
  }
}

void loop() {
  handleInterface();  // обновление интерфейса
  server.handleClient();
  handleWiFi();

  if (wifiState == AP_MODE) {
      dnsServer.processNextRequest();
  }

  if (rebootPending) {
    delay(50);        // give the client time to receive the “OK”
    ESP.restart();    // now do it safely from the main loop
  }
}
