// interface.cpp
#include "interface.h"
#include <Adafruit_ST7735.h>
#include <SPI.h>
#include <EEPROM.h>
#include <ArduinoJson.h>  // если понадобится в Settings
#include <SPIFFS.h>

// пины джойстика и дисплея
#define UP_PIN       8
#define DOWN_PIN     1
#define LEFT_PIN     5
#define RIGHT_PIN    9
#define SELECT_PIN   4

#define TFT_SCLK     2
#define TFT_MOSI     3
#define TFT_MISO    -1
#define TFT_RST     10
#define TFT_DC       6
#define TFT_CS       7
#define TFT_SPI_SPEED 24000000

#define AES_KEY_SIZE 16

Adafruit_ST7735 tft(TFT_CS, TFT_DC, TFT_RST);

// пункты главного меню
const char* menuItems[] = {"Passwords", "Info", "About", "Settings", "Clear"};
const int menuSize = sizeof(menuItems)/sizeof(menuItems[0]);

// текущие переменные
enum AppState {
  ST_LOCKED,
  ST_UNLOCK_PROMPT,
  ST_MENU,
  ST_PASSWORDS,
  ST_INFO,
  ST_ABOUT,
  ST_SETTINGS,
  ST_CLEAR
};
static int pageOffset = 0;
static AppState state = ST_LOCKED;
static int menuIndex = 0;
static int sequenceIndex = 0;
static const int correctSeq[] = {UP_PIN, UP_PIN, DOWN_PIN, RIGHT_PIN};
static const int seqLen = sizeof(correctSeq)/sizeof(correctSeq[0]);
static int userSeq[seqLen];
static int failedAttempts = 0;
static unsigned long lockUntil = 0;

// вспомогалки для перерисовки
static bool redraw = true;

void setupInterface() {
  EEPROM.begin(64);

  // инициализируем дисплей
  SPI.begin(TFT_SCLK, TFT_MISO, TFT_MOSI);
  tft.initR(INITR_MINI160x80_PLUGIN);
  tft.setSPISpeed(TFT_SPI_SPEED);
  tft.setRotation(3);

  // кнопки
  pinMode(UP_PIN, INPUT_PULLUP);
  pinMode(DOWN_PIN, INPUT_PULLUP);
  pinMode(LEFT_PIN, INPUT_PULLUP);
  pinMode(RIGHT_PIN, INPUT_PULLUP);
  pinMode(SELECT_PIN, INPUT_PULLUP);

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

  // в самом начале handleInterface(), вместо твоего case ST_CLEAR
  if (state == ST_CLEAR) {
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
        // второй тап — чистим FS и настройки (кроме мастер-ключа)
        SPIFFS.format();
        EEPROM.begin(64);
        for (int i = AES_KEY_SIZE; i < 64; i++) EEPROM.write(i, 0xFF);
        EEPROM.commit();
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
        case 0: state = ST_PASSWORDS;      break;
        case 1: state = ST_INFO;           break;
        case 2: state = ST_ABOUT;          break;
        case 3: state = ST_SETTINGS;       break;
        case 4: state = ST_CLEAR;  break;
      }
      delay(200);
      redraw = true;
    }
    return;
  }

  // экраны Passwords / Info / About / Settings / Clear
  switch(state){
    case ST_PASSWORDS: showPasswordsScreen(); break;
    case ST_INFO:      showInfoScreen();      break;
    case ST_ABOUT:     showAboutScreen();     break;
    case ST_SETTINGS:  showSettingsScreen();  break;
    default: break;
  }
}

// возврат в меню
void showMainMenuScreen(){
  state = ST_MENU;
  redraw = true;
  menuIndex = 0;
}

// Заглушка: Passwords
void showPasswordsScreen(){
  static bool first=true;
  if(first){
    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10,20);
    tft.print("Passwords:");
    tft.setTextSize(1);
    tft.setCursor(10,50);
    tft.print("Use Web UI");
    first=false;
  }
  // Back по LEFT
  if(digitalRead(LEFT_PIN)==LOW){
    state  = ST_MENU;
    redraw = true;
    delay(200);
  }
}

// Info: e.g. uptime + FS stats
void showInfoScreen(){
  static bool first=true;
  if(first){
    first=false;
    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10,10);
    tft.print("Uptime(s):");
    tft.setCursor(100,10);
    tft.printf("%lu", millis()/1000);
    tft.setCursor(10,30);
    tft.print("FS files:");
    // можно вывести реальное число, тут заглушка
    tft.setCursor(10,45);
    tft.print("index.html etc.");
  }
  if(digitalRead(LEFT_PIN)==LOW){
    state  = ST_MENU;
    redraw = true;
    delay(200);
  }
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
void showSettingsScreen(){
  static bool first=true;
  if(first){
    first=false;
    tft.fillScreen(ST77XX_BLACK);
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(10,20);
    tft.print("Settings:");
    tft.setCursor(10,40);
    tft.print("← Back");
    tft.setCursor(10,60);
    tft.print("PRESS SELECT");
  }
  // Back
  if(digitalRead(LEFT_PIN)==LOW){
    state  = ST_MENU;
    redraw = true;
    delay(200);
  }
  // пример действия: при SELECT — очистить EEPROM+FS
  if(digitalRead(SELECT_PIN)==LOW){
    // например:
    EEPROM.begin(64);
    for(int i=0;i<64;i++) EEPROM.write(i,0xFF);
    EEPROM.commit();
    SPIFFS.format();
    tft.fillScreen(ST77XX_RED);
    tft.setCursor(10,30);
    tft.print("RESET DONE!");
    delay(1000);
    first=true;
    showMainMenuScreen();
  }
}
