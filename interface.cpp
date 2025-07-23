// interface.cpp
#include "interface.h"
//#include <Adafruit_ST7735.h>
#include <Adafruit_ST7789.h>
#include <WiFi.h>
#include <SPI.h>
#include <EEPROM.h>
#include <ArduinoJson.h>  // если понадобится в Settings
#include <SPIFFS.h>
#include <Arduino.h> // уже есть через interface.h, но пусть будет
#include <vector>
#include <utility>
#include <FS.h>

// пины джойстика и дисплея (закоментированные для CORE-ESP32 + Air101-LCD)
#define UP_PIN       2 //8
#define DOWN_PIN     15 //1
#define LEFT_PIN     13 //5
#define RIGHT_PIN    12 //9
#define SELECT_PIN   17 //4

#define TFT_SCLK     18 //2
#define TFT_MOSI     19 //3
#define TFT_MISO    -1
#define TFT_RST     23 //10
#define TFT_DC       16 //6
#define TFT_CS       5 //7
#define TFT_SPI_SPEED 24000000

#define BATTERY_ADC_PIN 0

#define AES_KEY_SIZE 16

//Adafruit_ST7735 tft(TFT_CS, TFT_DC, TFT_RST);
Adafruit_ST7789 tft(TFT_CS, TFT_DC, TFT_RST);

// пункты главного меню
const char* menuItems[] = {"Passwords", "Connection", "Battery", "Sleep mode", "About", "Mode", "Factory reset"};
const int menuSize = sizeof(menuItems)/sizeof(menuItems[0]);

static bool batteryDrawn = false;
static unsigned long lastUpdate = 0;

// текущие переменные
enum AppState {
  ST_LOCKED,
  ST_UNLOCK_PROMPT,
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

static WiFiModeOption wifiModeSelection = UI_WIFI_STA;
static int pageOffset = 0;
static AppState state = ST_LOCKED;
static int menuIndex = 0;
static int sequenceIndex = 0;
static const int correctSeq[] = {UP_PIN, UP_PIN, DOWN_PIN, RIGHT_PIN};
static const int seqLen = sizeof(correctSeq)/sizeof(correctSeq[0]);
static int userSeq[seqLen];
static int failedAttempts = 0;
static unsigned long lockUntil = 0;

// Глобальные переменные (теперь только здесь!)
// (убери их из других файлов, если есть дублирование)
std::vector<PasswordEntry> passwordEntries;
int passwordListIndex = 0;
int passwordDetailIndex = 0;
bool showPassword = false;
int passwordScreenState = 0;

// вспомогалки для перерисовки
static bool redraw = true;

bool loadJsonFromFile(const char* path, DynamicJsonDocument& doc) {
  File file = SPIFFS.open(path, "r");
  if (!file) return false;
  DeserializationError error = deserializeJson(doc, file);
  file.close();
  return !error;
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
  EEPROM.begin(64);

  // инициализируем дисплей
  SPI.begin(TFT_SCLK, TFT_MISO, TFT_MOSI);
  //tft.initR(INITR_MINI160x80_PLUGIN);
  tft.init(135, 240);
  tft.setSPISpeed(TFT_SPI_SPEED);
  tft.setRotation(3);

  // кнопки
  pinMode(UP_PIN, INPUT_PULLUP);
  pinMode(DOWN_PIN, INPUT_PULLUP);
  pinMode(LEFT_PIN, INPUT_PULLUP);
  pinMode(RIGHT_PIN, INPUT_PULLUP);
  pinMode(SELECT_PIN, INPUT_PULLUP);
  pinMode(4, INPUT_PULLUP);

  // ___ СТАРТОВЫЙ ЭКРАН С ТЕКСТОМ ___
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
  // — конец стартового экрана —

  // стартовый экран
  state = ST_UNLOCK_PROMPT;
  redraw = true;
}

void handleInterface() {
  // общая разблокировка
  if (state==ST_UNLOCK_PROMPT) {
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10,20);
      tft.print("Enter Code:");
      sequenceIndex = 0;
      redraw = false;
    }
    int in = -1;
    if (digitalRead(UP_PIN)==LOW)    in=UP_PIN;
    if (digitalRead(DOWN_PIN)==LOW)  in=DOWN_PIN;
    if (digitalRead(LEFT_PIN)==LOW)  in=LEFT_PIN;
    if (digitalRead(RIGHT_PIN)==LOW) in=RIGHT_PIN;
    if (in!=-1 && sequenceIndex<seqLen) {
      userSeq[sequenceIndex++] = in;
      tft.setCursor(10 + sequenceIndex*20, 50);
      tft.setTextColor(ST77XX_YELLOW);
      tft.print("*");
      delay(200);
    }
    if (sequenceIndex>=seqLen) {
      bool ok=true;
      for(int i=0;i<seqLen;i++) if(userSeq[i]!=correctSeq[i]) { ok=false; break; }
      if (ok) {
        state = ST_MENU;
        redraw = true;
        failedAttempts=0;
      } else {
        failedAttempts++;
        tft.fillScreen(ST77XX_RED);
        tft.setCursor(10,30);
        tft.setTextColor(ST77XX_WHITE);
        tft.print("Wrong Code!");
        delay(1000);
        if (failedAttempts>=3) {
          lockUntil = millis()+30000;
          state = ST_LOCKED;
        } else {
          state = ST_UNLOCK_PROMPT;
        }
        redraw = true;
      }
    }
    return;
  }

  // экран блокировки
  if (state==ST_LOCKED) {
    if (redraw) {
      tft.fillScreen(ST77XX_RED);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10,30);
      tft.print("LOCKED!");
      redraw=false;
    }
    if (millis()>lockUntil) {
      state=ST_UNLOCK_PROMPT;
      redraw=true;
    }
    return;
  }

  // в самом начале handleInterface(), вместо твоего case ST_ERASE
  if (state == ST_ERASE) {
    static bool confirmStage = false;

    // 1) Рисуем экран очистки только раз
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextSize(2);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 20);
      tft.print("Clear all data?");
      tft.setTextSize(1);
      tft.setTextColor(ST77XX_WHITE);
      tft.setCursor(10, 50);
      tft.print("< Left = Cancel");
      tft.setCursor(10, 60);
      tft.print("Select = Confirm");
      redraw = false;
      confirmStage = false;
    }

    // 2) Отмена — сразу назад в главное меню
    if (digitalRead(LEFT_PIN) == LOW) {
      state   = ST_MENU;
      redraw  = true;
      delay(200);
      return;
    }

    // 3) Подтверждение — два шага
    if (digitalRead(SELECT_PIN) == LOW) {
      if (!confirmStage) {
        // первый тап — спрашиваем ещё раз
        tft.fillScreen(ST77XX_BLACK);
        tft.setTextSize(2);
        tft.setTextColor(ST77XX_WHITE);
        tft.setCursor(10, 20);
        tft.print("Really Reset?");
        delay(300);
        confirmStage = true;
      } else {
        EEPROM.begin(64);
        for (int i = 0; i < 64; i++) EEPROM.write(i, 0xFF);   // Стереть все 64 байта (весь диапазон)
          EEPROM.commit();
          SPIFFS.format();
          ESP.restart();
      }
      delay(200);
    }

    return;
  }

  // Главное меню
  if (state == ST_MENU) {
    if (redraw) {
      tft.fillScreen(ST77XX_BLACK);
      
      const uint8_t txtSize   = 2;
      tft.setTextSize(txtSize);

      // 3) Вычисляем ширину/высоту символа и отступы
      const uint8_t charW     = 6 * txtSize;   // ширина символа≈6px при size=1
      const uint8_t charH     = 8 * txtSize;   // высота символа≈8px при size=1
      const uint8_t vPadding  = 4;             // дополнительный промежуток
      const uint8_t spacing   = charH + vPadding; // вертикальный шаг между пунктами
      const uint8_t visible   = 3;             // показываем по 2 пункта

      // Рассчитываем, если курсор вышел за текущую «страницу», корректируем pageOffset
      if (menuIndex < pageOffset) {
        pageOffset = menuIndex;
      } else if (menuIndex >= pageOffset + visible) {
        pageOffset = menuIndex - visible + 1;
      }

      // Рисуем стрелки, если есть скрытые пункты вверх/вниз
      if (pageOffset > 0) {
        tft.setCursor(tft.width() - charW, 0);
        tft.print("^");
      }
      if (pageOffset + visible < menuSize) {
        tft.setCursor(tft.width() - charW, tft.height() - charH);
        tft.print("v");
      }

      // Выводим только visible пунктов
      for (uint8_t  i = 0; i < visible; i++) {
        uint8_t  idx = pageOffset + i;
        if (idx >= menuSize) break;
        tft.setCursor(10, 10 + i * spacing);
        tft.setTextColor(idx == menuIndex ? ST77XX_YELLOW : ST77XX_WHITE);
        tft.print(menuItems[idx]);
      }
      redraw = false;
    }

    // Обработка кнопок
    if (digitalRead(UP_PIN) == LOW) {
      // двигаем курсор вверх, не выше 0
      menuIndex = (menuIndex - 1 + menuSize) % menuSize;
      redraw = true;
      delay(200);
    }
    if (digitalRead(DOWN_PIN) == LOW) {
      // двигаем курсор вниз, не ниже menuSize-1
      menuIndex = (menuIndex + 1) % menuSize;
      redraw = true;
      delay(200);
    }
    if (digitalRead(SELECT_PIN) == LOW) {
      // сохраняем выбранный пункт — menuIndex уже установлен
      // переходим в соответствующее состояние
      switch (menuIndex) {
        case 0:
          if (loadPasswordsFromFile()) {
            passwordScreenState = 0; // показывать список
            passwordListIndex = 0;
            state = ST_PASSWORDS;
            redraw = true;
          } else {
            // ошибка чтения — вывести на экран
          }
          break;
        case 1: state = ST_CONNECTION; redraw = true; break;
        case 2: state = ST_BATTERY; redraw = true; break;     // Battery
        case 3: state = ST_SLEEP_MODE; redraw = true; break;  // Sleep mode
        case 4: state = ST_ABOUT;          break;
        case 5: state = ST_WIFI_MODE; redraw = true; break;
        case 6: state = ST_ERASE;  break;
      }
      delay(200);
      redraw = true;
    }
    return;
  }

  // экраны Passwords / Info / About / Settings / Clear
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

// возврат в меню
void showMainMenuScreen(){
  state = ST_MENU;
  redraw = true;
  menuIndex = 0;
}

// About: версия и автор
void showAboutScreen(){
  static bool first=true;
  if(first){
    first=false;
    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10,20);
    tft.print("PocketPassStor");
    tft.setCursor(10,40);
    tft.print("v1.0.0");
    tft.setCursor(10,60);
    tft.print("(c) 2025 by Zeus");
  }
  if(digitalRead(LEFT_PIN)==LOW){
    state  = ST_MENU;
    redraw = true;
    delay(200);
  }
}

// Settings: пример пункта — сброс всех паролей
void showWiFiModeScreen() {
  static bool first = true;
  if (first || redraw) {
    first = false;
    redraw = false;

    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10, 10);
    tft.print("Wi-Fi Mode:");

    tft.setTextSize(2);
    tft.setCursor(10, 35);
    tft.setTextColor(wifiModeSelection == UI_WIFI_STA ? ST77XX_YELLOW : ST77XX_WHITE);
    tft.print("> Wi-Fi");

    tft.setCursor(10, 60);
    tft.setTextColor(wifiModeSelection == UI_WIFI_AP ? ST77XX_YELLOW : ST77XX_WHITE);
    tft.print("> Access Point");

    tft.setTextColor(ST77XX_WHITE);
    tft.setTextSize(1);
    tft.setCursor(10, 78);
    tft.print("< Back");
  }

  // Навигация
  if (digitalRead(UP_PIN) == LOW || digitalRead(DOWN_PIN) == LOW) {
    wifiModeSelection = (wifiModeSelection == UI_WIFI_STA) ? UI_WIFI_AP : UI_WIFI_STA;
    redraw = true;
    delay(150);
  }
  // SELECT — применить и сохранить
  if (digitalRead(SELECT_PIN) == LOW) {
    // Сохранить выбор в settings.json
    saveWiFiModeToSettings(wifiModeSelection == UI_WIFI_STA ? "wifi" : "ap");
    tft.fillScreen(ST77XX_BLACK);
    tft.setCursor(10, 40);
    tft.setTextColor(ST77XX_YELLOW);
    tft.setTextSize(2);
    tft.print("Restarting...");
    delay(800);
    ESP.restart();
  }
  // LEFT — назад
  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    redraw = true;
    first = true;
    delay(200);
  }
}

void showBatteryScreen() {
  if (!batteryDrawn) {
      tft.fillScreen(ST77XX_BLACK);
      tft.setTextColor(ST77XX_WHITE);
      tft.setTextSize(1);
      tft.setCursor(10, 10);
      tft.print("Battery:");
      batteryDrawn = true;
  }
  // Считать напряжение
    if (millis() - lastUpdate > 500) {
      lastUpdate = millis();
      int raw = analogRead(BATTERY_ADC_PIN);
      // Преобразование — поправь коэффициент под делитель!
      float voltage = raw * 3.3 / 4095 * 2.0; // *2, если делитель 1:2

      // Расчёт процента (упрощенно: 4.2В — 100%, 3.2В — 0%)
      int percent = (int)((voltage - 3.2) * 100.0 / (4.2 - 3.2));
      percent = constrain(percent, 0, 100);

      tft.setTextSize(1);
      tft.setCursor(10, 40);
      tft.print("Voltage: ");
      tft.print(voltage, 2);
      tft.print(" V");

      tft.setCursor(10, 58);
      tft.print("Charge: ");
      tft.print(percent);
      tft.print("%");

      tft.setCursor(10, 74);
      tft.print("< Back");
  }

  // Выход по LEFT
  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    redraw = true;
    batteryDrawn = false;
    lastUpdate = 0;
    delay(200);
  }
}

void showSleepModeScreen() {
  tft.fillScreen(ST77XX_BLACK);
  tft.setTextSize(2);
  tft.setTextColor(ST77XX_WHITE);
  tft.setCursor(10, 30);
  tft.print("Sleep mode");
  tft.setTextSize(1);
  tft.setCursor(10, 60);
  tft.print("SELECT: Sleep");
  tft.setCursor(10, 74);
  tft.print("< Back");

  // В сон по SELECT
  if (digitalRead(SELECT_PIN) == LOW) {
    tft.fillScreen(ST77XX_BLACK);
    tft.setCursor(10, 30);
    tft.setTextColor(ST77XX_YELLOW);
    tft.setTextSize(2);
    tft.print("Sleeping...");
    delay(300);
    // Пробуждение по той же кнопке
    esp_sleep_enable_ext0_wakeup((gpio_num_t)SELECT_PIN, 0); // LOW — wake
    esp_deep_sleep_start();
  }
  // Выход по LEFT
  if (digitalRead(LEFT_PIN) == LOW) {
    state = ST_MENU;
    redraw = true;
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

    // вернуться в меню по кнопке LEFT
    if (digitalRead(LEFT_PIN) == LOW) {
      state = ST_MENU;
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

        int start = max(0, passwordListIndex - 1); // показывать выбранную строку +1 выше/ниже (3 на экран)
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
      // UP/DOWN навигация
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
      // SELECT — открыть детали
      if (digitalRead(SELECT_PIN)==LOW) {
        passwordDetailIndex = passwordListIndex;
        showPassword = false;
        passwordScreenState = 1; // DETAIL
        redraw = true;
        delay(200);
      }
      // LEFT — выход назад
      if (digitalRead(LEFT_PIN)==LOW) {
        state = ST_MENU;
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
        // доп. поля (по одной строке на поле)
        int y = 52;
        for (const auto& kv : entry.extras) {
          tft.setCursor(4, y);
          tft.print(kv.first + ":");
          tft.setCursor(60, y);
          tft.print(kv.second);
          y += 16;
          if (y > 78) break; // ограничить количеством строк
        }
        tft.setCursor(4, 68); tft.setTextColor(ST77XX_WHITE); tft.print("Hold SELECT: Show");
        tft.setCursor(4, 78); tft.print("< Back");
        redraw = false;
      }
      // Hold SELECT для показа пароля
      if (digitalRead(SELECT_PIN)==LOW) {
        if (!showPassword) {
          showPassword = true;
          redraw = true;
        }
      } else if (showPassword) {
        showPassword = false;
        redraw = true;
      }
      // LEFT — назад к списку
      if (digitalRead(LEFT_PIN)==LOW) {
        passwordScreenState = 0; // LIST
        redraw = true;
        delay(200);
      }
      return;
    }
}

// Info: e.g. uptime + FS stats
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

    // Определяем режим работы и параметры (STA/AP)
    String mode, ssid, pass, ip;
    if (WiFi.getMode() & WIFI_AP) {
      // AP режим
      mode = "AP";
      ssid = WiFi.softAPSSID();
      pass = getApPassword() != "-" ? getApPassword() : apRandomPassword;
      ip = WiFi.softAPIP().toString();
    } else if (WiFi.status() == WL_CONNECTED) {
      // STA режим
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
    y += 20;
    tft.setCursor(4, y);   tft.print("< Back");
  }

  // LEFT — выход назад
  if (digitalRead(LEFT_PIN)==LOW) {
    state = ST_MENU;
    redraw = true;
    first = true;
    delay(200);
  }
}
