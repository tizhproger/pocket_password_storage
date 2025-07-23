// interface.h
#ifndef INTERFACE_H
#define INTERFACE_H

#include <Arduino.h> // для String!
#include <vector>    // для std::vector
#include <utility>   // для std::pair

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

void setupInterface();
void handleInterface();
String getApPassword();

// новые экраны
bool loadPasswordsFromFile();
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
