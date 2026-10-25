#include "ui.h"
#include "config.h"
#include "storage.h"
#include "app.h"
#include "pps_network.h"
#include "web.h"
#include "crypto.h"
#include "display_text.h"
#include "Logo.h"
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <SPI.h>
#include <esp_sleep.h>
#include <driver/gpio.h>
namespace UI {
static Adafruit_ST7735 tft(Config::CS,Config::DC,Config::RST);
enum Screen {Locked,Menu,Pin,NewPin,ConfirmPin,Setup,Entries,Details,Connection,Fingerprint,Mode,Battery,Sleep,Reset1,Reset2,About,Message};
static Screen screen=Locked,afterMessage=Locked;
enum Purpose {Unlock,Change,Create,Recover};
static Purpose purpose=Unlock;
struct Button {int pin;bool raw=false,down=false;uint64_t changed=0,next=0;bool event=false;};
static Button buttons[]={{Config::UP},{Config::DOWN},{Config::LEFT},{Config::RIGHT},{Config::SELECT}};
static bool fence=true,dirty=true,revealed=false,sleepArmed=false,lastSetup=false;
static int menu=0,entryIndex=0,scroll=0,digit=0;
static String pinValue,firstPin,selectedId,messageText,lastRevision,lastNet;
static uint64_t lastFrame=0,batteryAt=0,splashUntil=0;
static float voltage=0;
static Vault::State lastState=Vault::State::FsError;
static const char* menuItems[]={"Passwords","Connection","Battery","Sleep","About / TLS","Wi-Fi mode","Change PIN","Lock","Factory reset"};
static bool allReleased(){for(auto& b:buttons)if(b.raw||b.down)return false;return true;}
static void go(Screen next){screen=next;scroll=0;fence=true;revealed=false;dirty=true;sleepArmed=false;}
static void message(const String& s,Screen next=Locked){messageText=s;afterMessage=next;go(Message);}
static void text(int x,int y,const char* s,uint16_t color=ST77XX_WHITE){
  tft.setCursor(x,y);tft.setTextColor(color);
  for(const unsigned char* p=reinterpret_cast<const unsigned char*>(s?s:"");*p;p++){char c=DisplayText::glyph(*p);if(c)tft.write(c);}
}
static void text(int x,int y,const String& s,uint16_t color=ST77XX_WHITE){text(x,y,s.c_str(),color);}
static void title(const char* s){tft.fillScreen(ST77XX_BLACK);text(0,0,s,ST77XX_CYAN);tft.drawFastHLine(0,10,160,ST77XX_BLUE);}
static void footer(const char* s){tft.fillRect(0,69,160,11,ST77XX_BLACK);text(0,71,s,ST77XX_YELLOW);}
static void lines(const DisplayText::Rows& list){int maxScroll=std::max<int>(0,int(list.size())-5);scroll=std::max(0,std::min(scroll,maxScroll));if(list.first()!=size_t(scroll)){dirty=true;return;}for(int i=0;i<5&&i+scroll<int(list.size());i++)text(0,13+i*11,list[i+scroll].value);}
using DisplayText::append;
static void append(DisplayText::Rows& rows,const String& s){DisplayText::append(rows,s.c_str());}
static const char* localError(Outcome r){switch(r){case Outcome::NoMemory:return "Low RAM; close web tabs";case Outcome::Invalid:return "Invalid values";case Outcome::Conflict:return "Changed; reload settings";case Outcome::Credentials:return "Incorrect password / PIN";case Outcome::Corrupt:return "Vault damaged; recover";case Outcome::Storage:return "Storage error; retry later";case Outcome::Throttled:return "Too many attempts; wait";default:return "Operation failed";}}
static void progress(uint32_t done,uint32_t total){
  static uint64_t last=0;uint64_t now=App::now();
  if(done==0||done==total||now-last>=250){last=now;splashUntil=0;title("Processing...");text(0,20,"Checking protected data");text(0,38,String(total?done*100u/total:0)+"%");footer("Please wait");dirty=true;}
}
static void startPin(Purpose p){purpose=p;wipe(pinValue);wipe(firstPin);digit=0;go(p==Create?NewPin:Pin);}
static void submitPin(){
  if(!Vault::validPin(pinValue)){message("PIN needs 6-8 digits",screen);return;}
  if(screen==NewPin){firstPin=pinValue;wipe(pinValue);digit=0;go(ConfirmPin);return;}
  if(screen==ConfirmPin){
    if(pinValue!=firstPin){wipe(firstPin);wipe(pinValue);message("PINs differ; try again",NewPin);return;}
    bool ok=purpose==Create?App::startSetup(pinValue):App::changePin(pinValue);wipe(firstPin);wipe(pinValue);
    if(ok)go(purpose==Create?Setup:Locked);else message(localError(App::lastResult()));return;
  }
  bool ok=App::pin(pinValue,purpose==Recover);wipe(pinValue);digit=0;
  if(!ok){message(String(localError(App::lastResult()))+"; wait "+String(App::waitSeconds(true))+"s",Pin);return;}
  if(purpose==Change)go(NewPin);else if(purpose==Recover)message("Recovered. Sign in again");else go(Menu);
}
enum class SleepPhase {None,Entering,Exiting};
static SleepPhase sleepPhase=SleepPhase::None;
static uint64_t sleepAt=0;
static String wakeMode;
static esp_err_t sleepResult=ESP_OK;
static bool disableWake(){bool a=gpio_wakeup_disable(static_cast<gpio_num_t>(Config::SELECT))==ESP_OK;bool b=esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_GPIO)==ESP_OK;return a&&b;}
static void sleepNow(){
  wakeMode=Net::mode();App::lock();Net::stop();
  esp_err_t a=gpio_wakeup_enable(static_cast<gpio_num_t>(Config::SELECT),GPIO_INTR_LOW_LEVEL);
  esp_err_t b=a==ESP_OK?esp_sleep_enable_gpio_wakeup():ESP_FAIL;
  if(a!=ESP_OK||b!=ESP_OK){disableWake();Net::apply(wakeMode);message("Wake configuration failed");return;}
  if(Config::BACKLIGHT>=0)digitalWrite(Config::BACKLIGHT,!Config::BACKLIGHT_HIGH);
  tft.writeCommand(ST77XX_SLPIN);sleepPhase=SleepPhase::Entering;sleepAt=App::now()+120;
}
static void sleeping(uint64_t now){
  if(now<sleepAt)return;
  if(sleepPhase==SleepPhase::Entering){
    if(!allReleased())return;
    sleepResult=esp_light_sleep_start();tft.writeCommand(ST77XX_SLPOUT);
    sleepPhase=SleepPhase::Exiting;sleepAt=App::now()+120;return;
  }
  if(Config::BACKLIGHT>=0)digitalWrite(Config::BACKLIGHT,Config::BACKLIGHT_HIGH);
  bool clean=disableWake();sleepPhase=SleepPhase::None;bool network=Net::apply(wakeMode);wakeMode="";
  if(sleepResult!=ESP_OK||!clean)message("Sleep / wake failed");else if(!network)message(Net::warning().length()?Net::warning():"Network retry pending");else go(Locked);
}
static void act(int key){
  App::touch();dirty=true;
  if(screen==Message){if(key==4)go(afterMessage);return;}
  if(screen==Pin||screen==NewPin||screen==ConfirmPin){
    if(key==0)digit=(digit+1)%10;if(key==1)digit=(digit+9)%10;
    if(key==3&&pinValue.length()<8)pinValue+=char('0'+digit);
    if(key==2){if(pinValue.length()){size_t last=pinValue.length()-1;pinValue[last]=0;pinValue.remove(last);}else{wipe(firstPin);go(App::local()?Menu:Locked);}}
    if(key==4)submitPin();return;
  }
  if(screen==Locked){
    if(key==3)go(Connection);else if(key==2)go(Fingerprint);
    else if(key==4){auto s=Vault::state();if(s==Vault::State::Empty||s==Vault::State::Legacy)startPin(Create);else if(s==Vault::State::Corrupt)startPin(Recover);else if(s==Vault::State::FsError)go(Reset1);else startPin(Unlock);}
    else if(key==1&&(Vault::state()==Vault::State::Corrupt||Vault::state()==Vault::State::FsError))go(Reset1);return;
  }
  if(screen==Menu){
    if(key==0)menu=(menu+8)%9;if(key==1)menu=(menu+1)%9;
    if(key==4)switch(menu){case 0:go(Entries);break;case 1:go(Connection);break;case 2:go(Battery);break;case 3:go(Sleep);break;case 4:go(About);break;case 5:go(Mode);break;case 6:startPin(Change);break;case 7:App::lock();go(Locked);break;case 8:go(Reset1);break;}return;
  }
  if(screen==Entries){
    if(key==2){go(Menu);return;}SecureJson doc(Config::JSON_CAPACITY);if(!Vault::read(doc)){message(localError(Vault::lastResult()));return;}int n=doc["entries"].size();
    if(n){if(key==0)entryIndex=(entryIndex+n-1)%n;if(key==1)entryIndex=(entryIndex+1)%n;if(key==4){entryIndex=std::min(entryIndex,n-1);selectedId=doc["entries"][entryIndex]["id"].as<String>();go(Details);}}return;
  }
  if(screen==Details){if(key==2)go(Entries);if(key==0)scroll--;if(key==1)scroll++;return;}
  if(screen==Reset1){if(key==2)go(App::local()?Menu:Locked);if(key==4)go(Reset2);return;}
  if(screen==Reset2){if(key==2)go(App::local()?Menu:Locked);if(key==4){if(!App::factoryReset())message("Reset failed; restart");else message("Reset complete; rebooting");}return;}
  if(screen==Mode){if(key==4){if(!Net::apply(Net::mode()=="ap"?"wifi":"ap"))message(Net::warning().length()?Net::warning():"Network retry pending");return;}if(key==3){Outcome r=Net::saveMode(Net::mode());message(r==Outcome::Ok?"Mode saved":localError(r));return;}if(key==2)go(Menu);return;}
  if(screen==Sleep){if(key==2)go(Menu);if(key==4)sleepArmed=true;return;}
  if(screen==Setup){if(key==2){App::lock();go(Locked);}if(key==3)go(Connection);return;}
  if(screen==About&&key==4){go(Fingerprint);return;}
  if(key==2)go(App::local()?Menu:Locked);if(key==0)scroll--;if(key==1)scroll++;
}
static void draw(){
  DisplayText::Rows rows(std::max(0,scroll));
  switch(screen){
    case Locked:{title("PPS locked");append(rows,String("State: ")+Vault::stateName());append(rows,"SEL: unlock / setup");append(rows,"RIGHT: network");append(rows,"LEFT: TLS fingerprint");if(Vault::state()==Vault::State::Corrupt)append(rows,"SEL recover; DOWN reset");lines(rows);footer("PIN: 6-8 digits");break;}
    case Menu:title("Pocket Password Storage");for(int i=0;i<5;i++){int j=(menu+i)%9;text(0,13+i*11,String(i?"  ":"> ")+menuItems[j]);}footer("UP/DOWN  SEL: open");break;
    case Pin:case NewPin:case ConfirmPin:{title(screen==Pin?(purpose==Recover?"PIN: recover previous":"Enter current PIN"):screen==NewPin?"Choose new PIN":"Repeat new PIN");String mask;for(size_t i=0;i<pinValue.length();i++)mask+='*';text(0,15,mask+"  digit:"+String(digit));text(0,30,"RIGHT adds; LEFT erases");text(0,44,"6-8 digits, then SELECT");footer("UP/DOWN: choose digit");break;}
    case Setup:title("Setup / migration");append(rows,"Open HTTPS on browser");append(rows,"Code: ",App::setupCode().c_str());append(rows,"Expires after 3 minutes");append(rows,"RIGHT: network");lines(rows);footer("LEFT: cancel");break;
    case Entries:{title("Passwords");SecureJson doc(Config::JSON_CAPACITY);if(!Vault::read(doc)){message(localError(Vault::lastResult()));return;}auto a=doc["entries"].as<JsonArray>();int n=a.size();
      if(!n)text(0,15,"No entries. Use browser.");else{entryIndex=std::min(entryIndex,n-1);int selectedRow=0;for(int i=0;i<n;i++){if(i==entryIndex)selectedRow=rows.size();append(rows,i==entryIndex?"> ":"  ",a[i]["site"].as<const char*>());}scroll=std::min(selectedRow,std::max(0,int(rows.size())-5));rows.reset(scroll);for(int i=0;i<n;i++)append(rows,i==entryIndex?"> ":"  ",a[i]["site"].as<const char*>());lines(rows);}footer("SEL: open  LEFT: menu");break;}
    case Details:{title("Entry");SecureJson doc(Config::JSON_CAPACITY);if(!Vault::read(doc)){message(localError(Vault::lastResult()));return;}JsonObject entry;
      for(auto e:doc["entries"].as<JsonArray>())if(e["id"].as<String>()==selectedId)entry=e.as<JsonObject>();
      if(entry.isNull()){go(Entries);return;}append(rows,entry["site"].as<const char*>());append(rows,"Login: ",entry["login"].as<const char*>());append(rows,"Password: ",revealed?entry["password"].as<const char*>():"********");
      auto extras=entry["extras"].as<JsonArray>();for(auto e:extras){append(rows,"");append(rows,e["name"].as<const char*>(),": ",e["value"].as<const char*>());}lines(rows);footer("Hold SEL: show; LEFT: back");break;}
    case Connection:{title("Connection");append(rows,"Mode: "+Net::mode());append(rows,"SSID: ",Net::ssid().c_str());append(rows,"State: ",Net::stateName());if(Net::warning().length())append(rows,Net::warning());append(rows,"https://"+Net::ip());append(rows,"https://pps.local");
      bool bootstrap=Vault::state()==Vault::State::Empty||Vault::state()==Vault::State::Legacy;
      if(Net::mode()=="ap"){if(App::local()||bootstrap)append(rows,"Wi-Fi key: ",Net::apPassword().c_str());else append(rows,"Unlock PIN for Wi-Fi key");}if(App::setupReady())append(rows,"Setup code: ",App::setupCode().c_str());lines(rows);footer("UP/DOWN scroll LEFT back");break;}
    case Fingerprint:{title("TLS SHA-256 (all 64)");String fp=Web::fingerprint();for(int i=0;i<4;i++)text(0,14+i*12,fp.substring(i*16,(i+1)*16));footer("Compare in browser; LEFT");break;}
    case Mode:title("Wi-Fi mode");text(0,15,"Active: "+Net::mode());text(0,30,"SELECT: switch + lock");text(0,44,"RIGHT: save active mode");footer("LEFT: back");break;
    case Battery:{title("Battery estimate");text(0,15,String(voltage,2)+" V");int pct=std::max(0,std::min(100,int((voltage-3.2f)*100)));text(0,32,String(pct)+"% (approximate)");text(0,48,"Calibrate divider first");footer("LEFT: back");break;}
    case Sleep:title("Sleep");text(0,15,"SELECT then release");text(0,31,"Wi-Fi off, vault locked");text(0,47,"Wake with SELECT");footer("LEFT: cancel");break;
    case Reset1:title("Factory reset?");text(0,15,"Deletes ALL vault data");text(0,31,"and network settings");text(0,47,"SELECT: next confirmation");footer("LEFT: cancel");break;
    case Reset2:title("Confirm deletion");text(0,15,"Data cannot be undone");text(0,31,"SELECT again: ERASE");footer("LEFT: cancel");break;
    case About:title("Pocket Password Storage");text(0,15,Config::VERSION);text(0,30,"Original: tizhproger");text(0,45,"SELECT: TLS fingerprint");footer("LEFT: back");break;
    case Message:title("Status");append(rows,messageText);lines(rows);footer("SELECT: continue");break;
  }
}
void begin(){
  for(auto& b:buttons)pinMode(b.pin,INPUT_PULLUP);if(Config::BACKLIGHT>=0){pinMode(Config::BACKLIGHT,OUTPUT);digitalWrite(Config::BACKLIGHT,Config::BACKLIGHT_HIGH);}
  SPI.begin(Config::SCLK,Config::MISO,Config::MOSI);tft.initR(INITR_MINI160x80_PLUGIN);tft.setSPISpeed(24000000);tft.setRotation(3);tft.setTextWrap(false);tft.setTextSize(1);
  Crypto::setProgress(progress);analogReadResolution(12);analogSetPinAttenuation(Config::BATTERY,ADC_11db);
  tft.fillScreen(ST77XX_BLACK);tft.drawBitmap(0,0,PpsLogo::PICTURE,PpsLogo::WIDTH,PpsLogo::HEIGHT,ST77XX_WHITE);
  splashUntil=App::now()+Config::BOOT_LOGO_MS;fence=true;dirty=true;
}
void fatal(const char* msg){splashUntil=0;title("Startup failed");text(0,15,msg);footer("Check README; restart");}
void offline(const char* msg){splashUntil=0;message(String(msg)+"; local vault available");}
void tick(){
  uint64_t now=App::now();
  for(size_t i=0;i<5;i++){auto& b=buttons[i];bool raw=digitalRead(b.pin)==LOW;b.event=false;
    if(raw!=b.raw){b.raw=raw;b.changed=now;}
    if(now-b.changed>=30&&b.down!=raw){b.down=raw;if(raw){b.event=true;b.next=now+350;}}
    if(i<2&&b.down&&now>=b.next){b.event=true;b.next=now+120;}
  }

  if(splashUntil){fence=true;if(now<splashUntil)return;splashUntil=0;dirty=true;}
  if(sleepPhase!=SleepPhase::None){sleeping(now);return;}
  auto s=Vault::state();if(s!=lastState){lastState=s;dirty=true;if(s!=Vault::State::Unlocked){wipe(pinValue);wipe(firstPin);wipe(selectedId);if(screen!=Setup&&screen!=Locked&&screen!=Message)go(Locked);}}
  bool needsUnlock=screen==Menu||screen==Entries||screen==Details||screen==Mode||screen==Battery||screen==Sleep||((screen==Pin||screen==NewPin||screen==ConfirmPin)&&purpose==Change)||((screen==Reset1||screen==Reset2)&&s!=Vault::State::Corrupt&&s!=Vault::State::FsError);
  if(needsUnlock&&!App::local()){wipe(pinValue);wipe(firstPin);wipe(selectedId);go(Locked);}
  if(fence){if(allReleased())fence=false;}else for(int i=0;i<5;i++)if(buttons[i].event){act(i);if(fence)break;}
  bool show=screen==Details&&buttons[4].down&&!fence;if(show!=revealed){revealed=show;dirty=true;}
  if(sleepArmed&&allReleased()){sleepArmed=false;sleepNow();return;}
  if(now-batteryAt>=500){batteryAt=now;float sample=analogReadMilliVolts(Config::BATTERY)*0.001f*Config::DIVIDER*Config::CALIBRATION;voltage=voltage>0?voltage*.85f+sample*.15f:sample;if(screen==Battery)dirty=true;}
  String rev=Vault::revision(),net=Net::mode()+Net::ip()+Net::stateName()+Net::warning();if(rev!=lastRevision||net!=lastNet){dirty=true;lastRevision=rev;lastNet=net;}
  bool setup=App::setupReady();if(setup!=lastSetup){lastSetup=setup;dirty=true;}
  if(screen==Setup&&!setup)go(Locked);
  if(dirty&&now-lastFrame>=40){dirty=false;lastFrame=now;draw();}
}
}
