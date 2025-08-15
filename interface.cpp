// interface.cpp
#include "interface.h"
#include <Adafruit_ST7735.h>
//#include <Adafruit_ST7789.h>
#include <WiFi.h>
#include <SPI.h>
#include <EEPROM.h>
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <Arduino.h>
#include <vector>
#include <utility>
#include <FS.h>
#include <mbedtls/platform_util.h>
#include "esp_sleep.h"
#include "driver/gpio.h"
#include <WebServer.h>
#include <DNSServer.h>

// joystick and screen pins (commented ones for TTGO ESP32 TFT)
#define UP_PIN       8 //2
#define DOWN_PIN     13 //15
#define LEFT_PIN     5 //13
#define RIGHT_PIN    9 //12
#define SELECT_PIN   4 //17

#define TFT_SCLK     2 //18
#define TFT_MOSI     3 //19
#define TFT_MISO    -1
#define TFT_RST     10 //23
#define TFT_DC       6 //16
#define TFT_CS       7 //5
#define TFT_SPI_SPEED 24000000

#define BATTERY_ADC_PIN 0

#define AES_KEY_SIZE 16

Adafruit_ST7735 tft(TFT_CS, TFT_DC, TFT_RST);
//Adafruit_ST7789 tft(TFT_CS, TFT_DC, TFT_RST);

// main menu items
const char* menuItems[] = {"Passwords", "Connection", "Battery", "Sleep mode", "About", "Mode", "Fact. reset", "Change PIN"};
const int menuSize = sizeof(menuItems)/sizeof(menuItems[0]);

static bool batteryDrawn = false;
static unsigned long lastUpdate = 0;
static const int MAX_FAILED_ATTEMPTS = 10;

extern WebServer server;
extern DNSServer dnsServer;

enum AppState {
  ST_LOCKED,
  ST_UNLOCK_PROMPT,
  ST_SET_PIN,
  ST_CONFIRM_PIN,
  ST_MENU,
  ST_PASSWORDS,
  ST_PASSWORD_DETAILS,
  ST_CONNECTION,
  ST_ABOUT,
  ST_SETTINGS,
  ST_ERASE,
  ST_WIFI_MODE,
  ST_BATTERY,
  ST_SLEEP_MODE
};

enum WiFiModeOption { UI_WIFI_STA, UI_WIFI_AP };

// === Helpers for Wi‑Fi mode screen ===
static WiFiModeOption getRuntimeWiFiMode() {
  wifi_mode_t m = WiFi.getMode();  // WIFI_MODE_NULL/STA/AP/APSTA
  if (m == WIFI_MODE_STA || m == WIFI_MODE_APSTA) return UI_WIFI_STA;
  if (m == WIFI_MODE_AP) return UI_WIFI_AP;
  return UI_WIFI_STA;
}

static WiFiModeOption getConfiguredWiFiMode() {
  DynamicJsonDocument doc(256);
  if (!loadJsonFromFile("/settings.json", doc)) return UI_WIFI_STA;
  String s;
  if (doc.containsKey("wifi_mode")) s = doc["wifi_mode"].as<String>();
  else if (doc.containsKey("mode")) s = doc["mode"].as<String>();
  else s = "wifi";
  s.toLowerCase();
  return (s == "ap") ? UI_WIFI_AP : UI_WIFI_STA;
}
// ====================================

// ---- Runtime Wi‑Fi switch helpers (no reboot) ----
static void stopNetServices() {
  dnsServer.stop();
  server.stop();
}

static void startNetServices(bool apMode) {
  if (apMode) {
    dnsServer.start(53, "*", IPAddress(192,168,4,1));
  }
  server.begin();
}

static bool switchToSTA() {
  DynamicJsonDocument doc(512);
  if (!loadJsonFromFile("/settings.json", doc)) return false;
  String ssid = doc.containsKey("ssid")     ? String(doc["ssid"].as<const char*>())     : "";
  String pass = doc.containsKey("password") ? String(doc["password"].as<const char*>()) : "";

  if (!ssid.length()) return false;

  stopNetServices();

  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid.c_str(), pass.c_str());

  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < 12000) {
    delay(100);
  }
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.disconnect(true, true);
    return false;
  }

  startNetServices(false);
  return true;
}

static bool switchToAP() {
  DynamicJsonDocument doc(512);
  loadJsonFromFile("/settings.json", doc);

  String apSsid = (doc.containsKey("ap_ssid")     ? String(doc["ap_ssid"].as<const char*>())     : "");
  String apPass = (doc.containsKey("ap_password") ? String(doc["ap_password"].as<const char*>()) : "");

  if (apSsid.length() == 0) apSsid = generateRandomSSID();
  if (apPass.length() < 8)  apPass = generateRandomPassword(8);

  stopNetServices();

  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_AP);
  bool ok = WiFi.softAP(apSsid.c_str(), apPass.c_str());

  startNetServices(true);
  return ok;
}

static bool applyWiFiModeRuntime(WiFiModeOption m) {
  if (m == UI_WIFI_STA) return switchToSTA();
  if (m == UI_WIFI_AP)  return switchToAP();
  return false;
}
// ---------------------------------------------------

static WiFiModeOption wifiModeSelection = UI_WIFI_STA;
static int pageOffset = 0;
static AppState state = ST_LOCKED;
static int menuIndex = 0;
static int sequenceIndex = 0;
static int failedAttempts = 0;
static unsigned long lockUntil = 0;
static String pinBuffer = "";
static String confirmBuffer = "";
static const int MAX_PIN_LEN = 8;
static int pinPos = 0;

std::vector<PasswordEntry> passwordEntries;
int passwordListIndex = 0;
int passwordDetailIndex = 0;
bool showPassword = false;
int passwordScreenState = 0;

static bool redraw = true;
static char current = '0';

// edge-detector for buttons (active LOW)
static bool selLatched = false;
static bool rightLatched = false;

static inline bool justPressed(int pin, bool &latched) {
  bool now = (digitalRead(pin) == LOW);
  if (now && !latched) { latched = true; return true; }
  if (!now && latched) latched = false;
  return false;
}

static inline void swallowHeldSelect() {
  selLatched = (digitalRead(SELECT_PIN) == LOW);
}

bool loadJsonFromFile(const char* path, DynamicJsonDocument& doc) {
  File file = SPIFFS.open(path, "r");
  if (!file) return false;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  return !error;
}

static void factoryResetAuto() {
  for (int i = 0; i < 128; i++) EEPROM.write(i, 0xFF);
  EEPROM.commit();
  SPIFFS.format();
  pinBuffer = "";
  confirmBuffer = "";
  passwordEntries.clear();
  ESP.restart();
}

bool saveJsonToFile(const char* path, const DynamicJsonDocument& doc) {
  File file = SPIFFS.open(path, "w");
  if (!file) return false;
  serializeJson(doc, file);
  file.close();
  return true;
}

String getApPassword() {
  DynamicJsonDocument doc(512);
  if (!loadJsonFromFile("/settings.json", doc)) return "-";
  if (!doc.containsKey("ap_password")) return "-";
  String pw = doc["ap_password"].as<String>();
  if (pw.length() < 8) return "-";  // безопасная проверка
  return pw;
}

void setupInterface() {
  EEPROM.begin(128);

  // initialize display
  SPI.begin(TFT_SCLK, TFT_MISO, TFT_MOSI);
  tft.initR(INITR_MINI160x80_PLUGIN);
  //tft.init(135, 240);
  tft.setSPISpeed(TFT_SPI_SPEED);
  tft.setRotation(3);

  // buttons
  pinMode(UP_PIN,    INPUT);
  pinMode(RIGHT_PIN, INPUT);

  pinMode(DOWN_PIN, INPUT_PULLUP);
  pinMode(LEFT_PIN, INPUT_PULLUP);
  pinMode(SELECT_PIN, INPUT_PULLUP);

  // ___ START SCREEN WITH TEXT ___
  tft.fillScreen(ST77XX_BLACK);
  tft.setTextColor(ST77XX_WHITE);
  tft.setTextSize(2);
  tft.setCursor(10, 20);
  tft.print("Pocket");
  tft.setCursor(10, 40);
  tft.print("Password");
  tft.setCursor(10, 60);
  tft.print("Storage");
  delay(2000);
  // — end of start screen —

  bool pinSet = false;
  for (int i = 0; i < 16; i++) if (EEPROM.read(PIN_EE_ADDR + i) != 0xFF) pinSet = true;

  if (!pinSet) {
    state = ST_SET_PIN;
  } else {
    state = ST_UNLOCK_PROMPT;
  }
  swallowHeldSelect();
  redraw = true;
}

void handleInterface() {
  if (state == ST_UNLOCK_PROMPT) {
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 20);
      tft.print("Enter PIN:");
      pinBuffer = "";
      pinPos = 0;
      redraw = false;
      current = '0';
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    // Навигация цифрами 0-9 (UP/DOWN смена символа)
    if (digitalRead(UP_PIN) == LOW)  { current = (current == '9') ? '0' : current + 1; delay(200);
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    if (digitalRead(DOWN_PIN) == LOW){ current = (current == '0') ? '9' : current - 1; delay(200);
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    if (digitalRead(RIGHT_PIN) == LOW && pinPos < MAX_PIN_LEN) {
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
      pinBuffer += current;
      pinPos++;

      current = '0';
      if (pinPos < MAX_PIN_LEN) {
        tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
        tft.setCursor(10 + pinPos*15, 50);
        tft.setTextColor(ST77XX_YELLOW);
        tft.print(current);
      }

      delay(200);
    }
    if (digitalRead(LEFT_PIN) == LOW && pinPos > 0) {
      int oldPos = pinPos;
      pinPos--;

      char last = pinBuffer[pinPos];
      pinBuffer.remove(pinPos);

      tft.fillRect(10 + oldPos*15, 50, 15, 20, ST77XX_BLACK);

      current = last;
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);

      delay(200);
    }
    if (justPressed(SELECT_PIN, selLatched)) {
      if ((int)pinBuffer.length() == pinPos && pinPos < MAX_PIN_LEN) {
        tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
        tft.setCursor(10 + pinPos*15, 50);
        tft.setTextColor(ST77XX_YELLOW);
        tft.print(current);

        pinBuffer += current;
        pinPos++;
      }
      
      if ((int)pinBuffer.length() < 4) {
        tft.fillScreen(ST77XX_RED);
        tft.setCursor(10, 30);
        tft.print("Min 4 digits!");
        delay(1000);
        redraw = true;
        return;
      }
      
      if (verifyPin(pinBuffer)) {
        state = ST_MENU;
        swallowHeldSelect();
        explicit_bzero(&pinBuffer[0], pinBuffer.length());
        pinBuffer.clear();
        failedAttempts = 0;
      } else {
        failedAttempts++;

        tft.fillScreen(ST77XX_RED);
        tft.setCursor(10, 30);
        tft.print("Wrong PIN!");
        tft.setCursor(10, 50);
        tft.print("Left: ");
        tft.print(MAX_FAILED_ATTEMPTS - failedAttempts);
        delay(1000);

        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
          tft.fillScreen(ST77XX_BLACK);
          tft.setTextColor(ST77XX_YELLOW);
          tft.setCursor(10, 30);
          tft.print("Too many tries");
          tft.setCursor(10, 50);
          tft.print("Wiping data...");
          delay(1200);
          factoryResetAuto();
          return;
        }

        if (failedAttempts >= 3) {
          lockUntil = millis() + (1UL << failedAttempts) * 1000UL;
          state = ST_LOCKED;
          swallowHeldSelect();
        }
      }
      redraw = true;
    }
    return;
  }

  if (state == ST_LOCKED) {
    if (redraw) {
      tft.fillScreen(ST77XX_RED);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10,30);
      tft.print("LOCKED!");
      redraw=false;
    }
    if (millis() > lockUntil) {
      state = ST_UNLOCK_PROMPT;
      swallowHeldSelect();
      redraw = true;
    }
    return;
  }

  if (state == ST_ERASE) {
    static bool confirmStage = false;

    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextSize(1);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 10);
      tft.print("Clear all data?");
      tft.setCursor(10, 20);
      tft.print("PIN/Keys will be erased");
      tft.setTextSize(1);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 50);
      tft.print("< Left = Cancel");
      tft.setCursor(10, 60);
      tft.print("Select = Confirm");
      redraw = false;
      confirmStage = false;
    }

    if (digitalRead(LEFT_PIN) == LOW) {
      state   = ST_MENU;
      redraw  = true;
      delay(200);
      return;
    }

    if (justPressed(SELECT_PIN, selLatched)) {
      if (!confirmStage) {
        tft.fillScreen(ST77XX_BLACK);
        tft.setTextSize(2);
        tft.setTextColor(ST77XX_WHITE);
        tft.setCursor(10, 20);
        tft.print("Really Reset?");
        delay(300);
        confirmStage = true;
      } else {
        for (int i = 0; i < 128; i++) EEPROM.write(i, 0xFF);
          EEPROM.commit();
          SPIFFS.format();
          ESP.restart();
      }
      delay(200);
    }
    return;
  }

  if (state == ST_MENU) {
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      
      const uint8_t txtSize   = 2;
      tft.setTextSize(txtSize);

      const uint8_t charW     = 6 * txtSize;
      const uint8_t charH     = 8 * txtSize;
      const uint8_t vPadding  = 4;
      const uint8_t spacing   = charH + vPadding;
      const uint8_t visible   = 3;

      if (menuIndex < pageOffset) {
        pageOffset = menuIndex;
      } else if (menuIndex >= pageOffset + visible) {
        pageOffset = menuIndex - visible + 1;
      }

      if (pageOffset > 0) {
        tft.setCursor(tft.width() - charW, 0);
        tft.print("^");
      }
      if (pageOffset + visible < menuSize) {
        tft.setCursor(tft.width() - charW, tft.height() - charH);
        tft.print("v");
      }

      for (uint8_t  i = 0; i < visible; i++) {
        uint8_t  idx = pageOffset + i;
        if (idx >= menuSize) break;
        tft.setCursor(10, 10 + i * spacing);
        tft.setTextColor(idx == menuIndex ? ST77XX_YELLOW : ST77XX_WHITE);
        tft.print(menuItems[idx]);
      }
      redraw = false;
    }

    if (digitalRead(UP_PIN) == LOW) {
      menuIndex = (menuIndex - 1 + menuSize) % menuSize;
      redraw = true;
      delay(200);
    }
    if (digitalRead(DOWN_PIN) == LOW) {
      menuIndex = (menuIndex + 1) % menuSize;
      redraw = true;
      delay(200);
    }
    if (justPressed(SELECT_PIN, selLatched)) {
      switch (menuIndex) {
        case 0:
          if (loadPasswordsFromFile()) {
            passwordScreenState = 0;
            passwordListIndex = 0;
            state = ST_PASSWORDS;
            swallowHeldSelect();
            redraw = true;
          } else {
          }
          break;
        case 1: state = ST_CONNECTION; swallowHeldSelect(); redraw = true; break;
        case 2: state = ST_BATTERY; swallowHeldSelect(); redraw = true; break;
        case 3: state = ST_SLEEP_MODE; swallowHeldSelect(); redraw = true; break;
        case 4: state = ST_ABOUT; swallowHeldSelect();          break;
        case 5: state = ST_WIFI_MODE; swallowHeldSelect(); redraw = true; break;
        case 6: state = ST_ERASE; swallowHeldSelect();  break;
        case 7: state = ST_SET_PIN; swallowHeldSelect(); redraw = true; break;
      }
      delay(200);
      redraw = true;
    }
    return;
  }

  if (state == ST_SET_PIN || state == ST_CONFIRM_PIN) {
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 20);
      tft.print(state == ST_SET_PIN ? "Set PIN:" : "Confirm PIN:");
      pinBuffer = "";
      pinPos = 0;
      redraw = false;
      current = '0';
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    if (digitalRead(UP_PIN) == LOW)  { current = (current == '9') ? '0' : current + 1; delay(200);
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    if (digitalRead(DOWN_PIN) == LOW){ current = (current == '0') ? '9' : current - 1; delay(200);
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
    }
    if (digitalRead(RIGHT_PIN) == LOW && pinPos < MAX_PIN_LEN) {
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);
      pinBuffer += current;
      pinPos++;

      current = '0';
      if (pinPos < MAX_PIN_LEN) {
        tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
        tft.setCursor(10 + pinPos*15, 50);
        tft.setTextColor(ST77XX_YELLOW);
        tft.print(current);
      }

      delay(200);
    }
    if (digitalRead(LEFT_PIN) == LOW && pinPos > 0) {
      int oldPos = pinPos;
      pinPos--;

      char last = pinBuffer[pinPos];
      pinBuffer.remove(pinPos);

      tft.fillRect(10 + oldPos*15, 50, 15, 20, ST77XX_BLACK);

      current = last;
      tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
      tft.setCursor(10 + pinPos*15, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print(current);

      delay(200);
    }
    if (justPressed(SELECT_PIN, selLatched)) {
      if (state == ST_SET_PIN) {
        if ((int)pinBuffer.length() == pinPos && pinPos < MAX_PIN_LEN) {
          // дорисуем текущую цифру в активной ячейке
          tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
          tft.setCursor(10 + pinPos*15, 50);
          tft.setTextColor(ST77XX_YELLOW);
          tft.print(current);

          pinBuffer += current;
          pinPos++;
        }

        if ((int)pinBuffer.length() < 4) {
          tft.fillScreen(ST77XX_RED);
          tft.setCursor(10, 30);
          tft.print("Min 4 digits!");
          delay(1000);
          redraw = true;
          return;
        }
        confirmBuffer = pinBuffer;
        pinBuffer = "";
        pinPos = 0;
        current = '0';

        state = ST_CONFIRM_PIN;
        swallowHeldSelect();
        redraw = true;
        return;
      } else {
        if ((int)pinBuffer.length() == pinPos && pinPos < MAX_PIN_LEN) {
          tft.fillRect(10 + pinPos*15, 50, 15, 20, ST77XX_BLACK);
          tft.setCursor(10 + pinPos*15, 50);
          tft.setTextColor(ST77XX_YELLOW);
          tft.print(current);

          pinBuffer += current;
          pinPos++;
        }

        if ((int)pinBuffer.length() < 4) {
          tft.fillScreen(ST77XX_RED);
          tft.setCursor(10, 30);
          tft.print("Min 4 digits!");
          delay(1000);
          redraw = true;
          return;
        }
        if (pinBuffer == confirmBuffer) {
          savePinToEEPROM(pinBuffer);

          explicit_bzero(&pinBuffer[0], pinBuffer.length());
          pinBuffer.clear();
          confirmBuffer.clear();

          state = ST_MENU;
          swallowHeldSelect();
          redraw = true;
          return;
        } else {
          tft.fillScreen(ST77XX_RED);
          tft.setCursor(10, 30);
          tft.print("Mismatch!");
          delay(1000);

          pinBuffer = "";
          confirmBuffer = "";
          pinPos = 0;
          current = '0';

          state = ST_SET_PIN;
          swallowHeldSelect();
          redraw = true;
          return;
        }
      }
    }
    }

  // screens Passwords / Info / About / Settings / Clear
  switch(state){
    case ST_PASSWORDS: showPasswordsScreen(); break;
    case ST_CONNECTION:  showConnectionScreen();  break;
    case ST_ABOUT:     showAboutScreen();     break;
    case ST_WIFI_MODE:  showWiFiModeScreen();  break;
    case ST_BATTERY:      showBatteryScreen();    break;
    case ST_SLEEP_MODE:   showSleepModeScreen();  break;
    default: break;
  }
}

void showMainMenuScreen(){
  state = ST_MENU;
  swallowHeldSelect();
  redraw = true;
  menuIndex = 0;
}

void showAboutScreen(){
  static bool first = true;

  if (first || redraw) {
    first = false;
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);

    tft.setCursor(10, 10); tft.print("PocketPasswordStorage");
    tft.setCursor(10, 30); tft.print("v1.3.1");
    tft.setCursor(10, 50); tft.print("(c) 2025 by tizhproger");

    tft.setCursor(10, 70); tft.print("< Back");
  }

  // выход назад
  if (digitalRead(LEFT_PIN) == LOW) {
    state  = ST_MENU;
    swallowHeldSelect();   // чтобы удержанный SELECT/LEFT не триггерил меню
    redraw = true;
    first  = true;         // КРИТИЧЕСКО: чтобы About заново рисовался при следующем входе
    delay(150);
  }
}

void showWiFiModeScreen() {
  static bool first = true;
  if (first || redraw) {
    WiFiModeOption runtime  = getRuntimeWiFiMode();
    WiFiModeOption config   = getConfiguredWiFiMode();

    if (first) {
      wifiModeSelection = runtime;
      first = false;
    }
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10, 10);
    tft.print("Wi-Fi Mode:");

    // Wi‑Fi (STA)
    tft.setCursor(10, 30);
    tft.setTextColor(wifiModeSelection == UI_WIFI_STA ? ST77XX_YELLOW : ST77XX_WHITE);
    tft.print("> Wi-Fi");
    tft.setTextColor(ST77XX_GREEN);
    if (runtime == UI_WIFI_STA) { tft.print(" [ACTIVE]"); }
    tft.setTextColor(ST77XX_BLUE);
    if (config  == UI_WIFI_STA)  { tft.print(" [CONFIG]"); }

    // AP
    tft.setCursor(10, 50);
    tft.setTextColor(wifiModeSelection == UI_WIFI_AP ? ST77XX_YELLOW : ST77XX_WHITE);
    tft.print("> AP");
    tft.setTextColor(ST77XX_GREEN);
    if (runtime == UI_WIFI_AP) { tft.print(" [ACTIVE]"); }
    tft.setTextColor(ST77XX_BLUE);
    if (config  == UI_WIFI_AP)  { tft.print(" [CONFIG]"); }
    
    tft.setTextColor(ST77XX_WHITE);
    tft.setTextSize(1);
    tft.setCursor(10, 70);
    tft.print("< Back   RIGHT: Save def.");
  }

  if (digitalRead(UP_PIN) == LOW || digitalRead(DOWN_PIN) == LOW) {
    wifiModeSelection = (wifiModeSelection == UI_WIFI_STA) ? UI_WIFI_AP : UI_WIFI_STA;
    redraw = true;
    delay(150);
  }

  if (justPressed(SELECT_PIN, selLatched)) {
    WiFiModeOption runtime = getRuntimeWiFiMode();
    if (wifiModeSelection == runtime) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setCursor(10, 40);
      tft.setTextColor(ST77XX_YELLOW);
      tft.setTextSize(1);
      tft.print("Already active");
      delay(900);
      redraw = true;
      return;
    }

    bool ok = applyWiFiModeRuntime(wifiModeSelection);

    tft.fillScreen(ST77XX_BLACK);
    tft.setCursor(10, 40);
    tft.setTextColor(ok ? ST77XX_GREEN : ST77XX_RED);
    tft.setTextSize(1);
    tft.print(ok ? "Mode switched" : "Switch failed");
    delay(900);

    redraw = true;
  }

  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    swallowHeldSelect();
    redraw = true;
    first = true;
    delay(200);
  }

  if (justPressed(RIGHT_PIN, rightLatched)) {
    saveWiFiModeToSettings(wifiModeSelection == UI_WIFI_STA ? "wifi" : "ap");

    tft.fillScreen(ST77XX_BLACK);
    tft.setCursor(10, 40);
    tft.setTextColor(ST77XX_GREEN);
    tft.setTextSize(1);
    tft.print("Saved as default");
    delay(800);

    redraw = true;
  }
}

void showBatteryScreen() {
  static bool first = true;
  static unsigned long lastUpdate = 0;
  static float vFilt = NAN;     // for smoothing
  const uint8_t sz = 1;         // text size
  const int labelX = 10, valX = 80;  // where to write marks and values
  const int yVolt = 30, yPct = 48, yBack = 70;
  const int lineH = 10 * sz + 2;     // line heightfor clearing

  if (first || redraw) {
    first = false;
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextColor(ST77XX_WHITE);
    tft.setTextSize(sz);

    tft.setCursor(10, 10);
    tft.print("Battery:");

    tft.setCursor(labelX, yVolt);
    tft.print("Voltage:");
    tft.setCursor(labelX, yPct);
    tft.print("Charge:");

    tft.setCursor(10, yBack);
    tft.print("< Back");

    tft.fillRect(valX, yVolt, tft.width() - valX - 2, lineH, ST77XX_BLACK);
    tft.fillRect(valX, yPct,  tft.width() - valX - 2, lineH, ST77XX_BLACK);
  }

  // Updating not often than 2 seconds
  if (millis() - lastUpdate > 500) {
    lastUpdate = millis();

    int raw = analogRead(BATTERY_ADC_PIN);
    float v = raw * 3.3f / 4095.0f * 2.0f;  // divider coefficient
    if (isnan(vFilt)) vFilt = v;
    vFilt = 0.85f * vFilt + 0.15f * v;      // smoothing

    int percent = (int)((vFilt - 3.2f) * 100.0f / (4.2f - 3.2f));
    percent = constrain(percent, 0, 100);

    // Clear values area before redrawing
    tft.fillRect(valX, yVolt, tft.width() - valX - 2, lineH, ST77XX_BLACK);
    tft.fillRect(valX, yPct,  tft.width() - valX - 2, lineH, ST77XX_BLACK);

    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(valX, yVolt);
    tft.print(vFilt, 2);
    tft.print(" V");

    tft.setCursor(valX, yPct);
    tft.print(percent);
    tft.print("%");
  }

  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    swallowHeldSelect();
    redraw = true;
    first = true;
    delay(200);
  }
}

void showSleepModeScreen() {
  static bool first = true;
  static WiFiModeOption prevMode;

  if (first || redraw) {
    first = false;
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10, 20); tft.print("Sleep mode");

    tft.setTextSize(1);
    tft.setCursor(10, 50); tft.print("SELECT: Sleep");
    tft.setCursor(10, 70); tft.print("< Back");
  }

  if (justPressed(SELECT_PIN, selLatched)) {
    tft.fillScreen(ST77XX_BLACK);
    tft.setCursor(10, 30);
    tft.setTextColor(ST77XX_YELLOW);
    tft.setTextSize(2);
    tft.print("Sleeping...");
    delay(300);

    prevMode = getRuntimeWiFiMode();
    WiFi.mode(WIFI_OFF);
    btStop();

    gpio_wakeup_enable((gpio_num_t)SELECT_PIN, GPIO_INTR_LOW_LEVEL);
    esp_sleep_enable_gpio_wakeup();

    esp_light_sleep_start();

    gpio_wakeup_disable((gpio_num_t)SELECT_PIN);
    delay(120);

    if (prevMode == UI_WIFI_AP || prevMode == UI_WIFI_STA) {
      applyWiFiModeRuntime(prevMode);
    }

    state = ST_MENU;
    swallowHeldSelect();
    redraw = true;
    first = true;
    return;
  }

  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    swallowHeldSelect();
    redraw = true;
    first = true;
    delay(200);
  }
}

void showPasswordsScreen(){
  if (passwordEntries.size() == 0) {
    static bool noPasswordsDrawn = false;

    if (!noPasswordsDrawn) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextColor(ST77XX_RED);
      tft.setTextSize(1);
      tft.setCursor(20, 30);
      tft.print("No saved passwords");
      noPasswordsDrawn = true;
    }

    if (digitalRead(LEFT_PIN) == LOW) {
      state = ST_MENU;
      swallowHeldSelect();
      noPasswordsDrawn = false;
      delay(200);
    }

    return;
  }

  if (state == ST_PASSWORDS && passwordScreenState == 0) {
      if (redraw) {
        tft.fillScreen(ST77XX_BLACK);
        tft.setTextSize(1);
        tft.setTextColor(ST77XX_WHITE);
        tft.setCursor(10, 0);
        tft.print("Passwords:");

        int start = max(0, passwordListIndex - 1);
        int visible = min(3, (int)passwordEntries.size() - start);

        for (int i = 0; i < visible; i++) {
          int idx = start + i;
          tft.setCursor(10, 20 + i*18);
          if (idx == passwordListIndex)
            tft.setTextColor(ST77XX_YELLOW);
          else
            tft.setTextColor(ST77XX_WHITE);

          String label = passwordEntries[idx].site;
          if (passwordEntries[idx].login.length())
            label += " (" + passwordEntries[idx].login + ")";
          tft.print(label);
        }
        redraw = false;
      }

      if (digitalRead(UP_PIN)==LOW && passwordListIndex>0) {
        passwordListIndex--;
        redraw = true;
        delay(150);
      }
      if (digitalRead(DOWN_PIN)==LOW && passwordListIndex<(int)passwordEntries.size()-1) {
        passwordListIndex++;
        redraw = true;
        delay(150);
      }

      if (justPressed(SELECT_PIN, selLatched)) {
        passwordDetailIndex = passwordListIndex;
        showPassword = false;
        passwordScreenState = 1;
        redraw = true;
        delay(200);
      }

      if (digitalRead(LEFT_PIN)==LOW) {
        state = ST_MENU;
        swallowHeldSelect();
        redraw = true;
        delay(200);
      }
      return;
    }

  if (state == ST_PASSWORDS && passwordScreenState == 1) {
      if (redraw) {
        tft.fillScreen(ST77XX_BLACK);
        tft.setTextSize(1);

        const PasswordEntry& entry = passwordEntries[passwordDetailIndex];

        tft.setCursor(4, 4); tft.print("Site:");    tft.setCursor(60, 4);  tft.print(entry.site);
        tft.setCursor(4, 20); tft.print("Login:");  tft.setCursor(60, 20); tft.print(entry.login);

        tft.setCursor(4, 36); tft.print("Password:");
        tft.setCursor(60, 36);
        if (showPassword)
          tft.print(entry.password);
        else {
          for (size_t i=0; i<entry.password.length(); i++) tft.print('*');
        }

        int y = 52;
        for (const auto& kv : entry.extras) {
          tft.setCursor(4, y);
          tft.print(kv.first + ":");
          tft.setCursor(60, y);
          tft.print(kv.second);
          y += 16;
          if (y > 78) break;
        }
        tft.setCursor(4, 68); tft.setTextColor(ST77XX_WHITE); tft.print("< Back  Hold SELECT: Show");
        redraw = false;
      }

      if (digitalRead(SELECT_PIN) == LOW) {
        if (!showPassword) { showPassword = true; redraw = true; }
      } else {
        if (showPassword) { showPassword = false; redraw = true; }
      }

      if (digitalRead(LEFT_PIN)==LOW) {
        passwordScreenState = 0;
        redraw = true;
        delay(200);
      }
      return;
    }
}

void showConnectionScreen() {
  static String lastMode = "";
  static String lastSSID = "";
  static String lastPass = "";
  static String lastIP = "";
  static bool first = true;

  if (first || redraw) {
    first = false;
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);

    String mode, ssid, pass, ip;
    if (WiFi.getMode() & WIFI_AP) {

      mode = "AP";
      ssid = WiFi.softAPSSID();
      pass = getApPassword() != "-" ? getApPassword() : apRandomPassword;
      ip = WiFi.softAPIP().toString();
    } else if (WiFi.status() == WL_CONNECTED) {

      mode = "Wi-Fi";
      ssid = WiFi.SSID();
      pass = WiFi.psk();
      ip = WiFi.localIP().toString();
    } else {
      mode = "Idle";
      ssid = "-";
      pass = "-";
      ip = "-";
    }

    lastMode = mode;
    lastSSID = ssid;
    lastPass = pass;
    lastIP   = ip;

    int y = 8;
    tft.setCursor(4, y);   tft.print("Mode:   "); tft.print(mode);
    y += 16;
    tft.setCursor(4, y);   tft.print("SSID:   "); tft.print(ssid);
    y += 16;
    tft.setCursor(4, y);   tft.print("PASS:   "); tft.print(pass.length() ? pass : "-");
    y += 16;
    tft.setCursor(4, y);   tft.print("IP:     "); tft.print(ip);
    y += 15;
    tft.setCursor(4, y);   tft.print("< Back");
  }

  if (digitalRead(LEFT_PIN)==LOW) {
    state = ST_MENU;
    swallowHeldSelect();
    redraw = true;
    first = true;
    delay(200);
  }
}
