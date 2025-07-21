// interface.h
#ifndef INTERFACE_H
#define INTERFACE_H

void setupInterface();
void handleInterface();

// новые экраны
void showPasswordsScreen();
void showInfoScreen();
void showAboutScreen();
void showSettingsScreen();
void showClearScreen();
void handleClear();

// для возврата в главное меню
void showMainMenuScreen();

#endif
