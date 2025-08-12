// interface.h
#ifndef INTERFACE_H
#define INTERFACE_H

#include <Arduino.h>
#include <ArduinoJson.h> 
#include <vector>
#include <utility>

struct PasswordEntry {
  String site;
  String login;
  String password;
  std::vector<std::pair<String, String>> extras; // дополнительные поля
};

// Экспортируем все глобальные переменные для работы с паролями
extern std::vector<PasswordEntry> passwordEntries;
extern int passwordListIndex;
extern int passwordDetailIndex;
extern bool showPassword;
extern int passwordScreenState;
extern const int MK_EE_ADDR;
constexpr int PIN_EE_ADDR = 32;
constexpr int PIN_EE_MAX  = 16;
extern String apRandomPassword;

void setupInterface();
void handleInterface();
String getApPassword();
String generateRandomSSID();
String generateRandomPassword(int length);

// новые экраны
bool loadPasswordsFromFile();
bool loadJsonFromFile(const char* path, DynamicJsonDocument& doc);
bool saveJsonToFile(const char* path, const DynamicJsonDocument& doc);
bool verifyPin(const String &pin);
bool savePinToEEPROM(const String &pin);
void showPasswordsScreen();
void showConnectionScreen();
void showAboutScreen();
void showWiFiModeScreen();
void showClearScreen();
void saveWiFiModeToSettings(const String& mode);
void showBatteryScreen();
void showSleepModeScreen();
void handleClear();

// для возврата в главное меню
void showMainMenuScreen();

#endif
