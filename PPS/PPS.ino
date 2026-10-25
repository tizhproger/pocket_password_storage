// Pocket Password Storage (c) 2025 tizhproger
#include "arduino_build_check.h"
#include "crypto.h"
#include "storage.h"
#include "app.h"
#include "pps_network.h"
#include "web.h"
#include "ui.h"
#include <WiFi.h>
static bool runtimeReady=false;
void setup(){
  Serial.begin(115200);
  bool rng=Crypto::begin(); // Internal entropy source
  UI::begin();if(!rng){UI::fatal("Random source failed");return;}
  Vault::begin();if(!App::resumeReset()||!App::begin()){UI::fatal("NVS startup failed");return;}
  WiFi.persistent(false);
  Crypto::radioEntropy(WiFi.mode(WIFI_STA)); // Reseeding requires a live entropy source
  if(!Web::begin()){runtimeReady=true;UI::offline("TLS identity failed");return;}
  if(!Net::begin()){runtimeReady=true;UI::offline("Network setup failed");return;}
  if(Vault::state()==Vault::State::Locked&&!Vault::finishLegacyCleanup()){runtimeReady=true;UI::offline("Legacy cleanup failed");return;}
  runtimeReady=true;
}
void loop(){if(!runtimeReady){delay(20);return;}App::tick();UI::tick();Net::tick();Web::tick();delay(1);}
