#include "solo_app.h"
#include "board.h"
#include "record_font.h"
#include "solo_buttons.h"
#include "solo_engine.h"
#include "solo_platform.h"
#include <Adafruit_ST7735.h>
#include <SPI.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <driver/gpio.h>
#include <esp_sleep.h>
#include <esp_timer.h>
namespace {
using namespace solo;
constexpr uint16_t BG = 0x0841, FG = 0xEFFF, ACCENT = 0x6FD5, WARN = 0xFDC0;
uint64_t clockMs() { return uint64_t(esp_timer_get_time()) / 1000; }
const char *stateName(DiskState s) {
  switch (s) {
  case DiskState::Empty:
    return "Empty";
  case DiskState::Sealed:
    return "Ready";
  case DiskState::Recovery:
    return "Recovery required";
  case DiskState::Foreign:
    return "Other files found";
  case DiskState::Corrupt:
    return "Storage damaged";
  default:
    return "Storage unavailable";
  }
}
const char *resultName(Result s) {
  switch (s) {
  case Result::Ok:
    return "Saved and verified";
  case Result::Locked:
    return "Unlock locally first";
  case Result::Invalid:
    return "Invalid data";
  case Result::Busy:
    return "Another action pending";
  case Result::Conflict:
    return "List changed; retry";
  case Result::Denied:
    return "Cancelled";
  case Result::Storage:
    return "Write failed; restart";
  case Result::Corrupt:
    return "Storage needs recovery";
  case Result::Full:
    return "Storage full";
  case Result::Expired:
    return "Approval expired";
  default:
    return "Unable to complete";
  }
}
enum class Screen {
  Home,
  Menu,
  OwnerCard,
  OwnerInput,
  Deriving,
  Records,
  Details,
  Usb,
  ConfirmUsb,
  ConfirmDelete,
  ConfirmRepair,
  Reset1,
  Reset2,
  Diagnostics,
  Message,
  SleepWait,
  Sleeping,
  Waking
};
enum class KeyTask { Unlock, Create, Rotate, Restore };
class App {
  EspVolume volume_;
  SnapshotStore store_{volume_};
  Engine engine_{store_, hardwareRandom};
  Adafruit_ST7735 display_{&SPI, board::cs, board::dc, board::reset};
  Buttons buttons_;
  FrameDecoder decoder_;
  Bytes transmit_;
  size_t txAt_ = 0;
  Screen screen_ = Screen::Home;
  KeyTask keyTask_ = KeyTask::Unlock;
  Derivation derivation_;
  Identity newIdentity_{};
  char owner_[21]{}, input_[21]{};
  uint8_t inputSize_ = 0, cursor_ = 0;
  bool selectDeleted_ = false;
  uint64_t now_ = 0, screenSince_ = 0, lastDraw_ = 0, keyDeadline_ = 0;
  bool dirty_ = true, reveal_ = false, ownerMismatch_ = false;
  int menu_ = 0, selected_ = 0, scroll_ = 0, totalLines_ = 0;
  Id selectedId_{};
  char message_[40]{}, message2_[40]{};
  static constexpr const char *menus_[10] = {"Records",
                                             "Generate password",
                                             "USB manage",
                                             "Encrypted backup",
                                             "Change owner key",
                                             "Lock",
                                             "Sleep",
                                             "Diagnostics",
                                             "Repair interrupted write",
                                             "Erase / reset"};
  void transition(Screen s) {
    screen_ = s;
    screenSince_ = now_;
    dirty_ = true;
    buttons_.fence();
    reveal_ = false;
  }
  void wipeInput() {
    erase(owner_, sizeof(owner_));
    erase(input_, sizeof(input_));
    erase(&newIdentity_, sizeof(newIdentity_));
    inputSize_ = cursor_ = 0;
    derivation_.cancel();
    keyDeadline_ = 0;
  }
  void message(const char *a, const char *b = "LEFT: back") {
    snprintf(message_, sizeof(message_), "%s", a);
    snprintf(message2_, sizeof(message2_), "%s", b);
    transition(Screen::Message);
  }
  void queue(const Reply &reply) {
    if (txAt_ < transmit_.size())
      return;
    transmit_ = responseFrame(reply);
    txAt_ = 0;
  }
  void cancelPending() {
    if (engine_.pending())
      queue(engine_.approve(false, now_));
  }
  void lock() {
    cancelPending();
    engine_.lock();
    wipeInput();
    decoder_.reset();
    while (Serial.available())
      Serial.read();
    transition(Screen::Home);
  }
  void startInput(KeyTask task) {
    keyTask_ = task;
    erase(input_, sizeof(input_));
    inputSize_ = cursor_ = 0;
    selectDeleted_ = false;
    keyDeadline_ = now_ + 300000;
    transition(Screen::OwnerInput);
  }
  void newKey(KeyTask task) {
    wipeInput();
    ownerMismatch_ = false;
    keyTask_ = task;
    if (!makeOwner(hardwareRandom, owner_) ||
        !makeIdentity(hardwareRandom, newIdentity_)) {
      wipeInput();
      message("Random source failed");
      return;
    }
    keyDeadline_ = now_ + 300000;
    transition(Screen::OwnerCard);
  }
  void startDerivation() {
    const uint8_t *salt = keyTask_ == KeyTask::Unlock
                              ? store_.active().identity.salt.data()
                          : keyTask_ == KeyTask::Restore
                              ? engine_.restoreInfo().identity.salt.data()
                              : newIdentity_.salt.data();
    if ((keyTask_ == KeyTask::Create || keyTask_ == KeyTask::Rotate) &&
        !constantEqual(owner_, input_, 20)) {
      erase(input_, sizeof(input_));
      inputSize_ = 0;
      ownerMismatch_ = true;
      transition(Screen::OwnerCard);
      return;
    }
    bool ok = validOwner(input_) && derivation_.start(input_, 20, salt, 16);
    erase(input_, sizeof(input_));
    erase(owner_, sizeof(owner_));
    inputSize_ = 0;
    if (!ok) {
      cancelPending();
      wipeInput();
      message("Key derivation failed");
      return;
    }
    transition(Screen::Deriving);
  }
  void derivationTick() {
    derivation_.advance(128);
    if (derivation_.failed()) {
      cancelPending();
      wipeInput();
      message("Crypto error");
      return;
    }
    if (!derivation_.finished())
      return;
    Key key{};
    if (!derivation_.take(key))
      return;
    bool ok = false;
    Result r = Result::Storage;
    switch (keyTask_) {
    case KeyTask::Unlock:
      ok = engine_.unlock(key, now_);
      break;
    case KeyTask::Create:
      ok = engine_.initialize(key, newIdentity_, now_);
      break;
    case KeyTask::Rotate:
      r = engine_.rotate(key, newIdentity_, now_);
      ok = r == Result::Ok;
      break;
    case KeyTask::Restore:
      ok = engine_.verifyRestore(key);
      break;
    }
    erase(key.data(), 32);
    KeyTask task = keyTask_;
    wipeInput();
    if (!ok) {
      cancelPending();
      message(task == KeyTask::Unlock || task == KeyTask::Restore
                  ? "Wrong key / damaged data"
                  : resultName(r));
      return;
    }
    if (task == KeyTask::Restore) {
      transition(Screen::ConfirmUsb);
      return;
    }
    if (task == KeyTask::Rotate) {
      message(store_.cleanupWarning ? "Key changed; cleanup failed"
                                    : "Owner key changed",
              "Old backups use old key");
      return;
    }
    if (store_.state() == DiskState::Recovery)
      message("Read-only recovery", "Menu: repair or backup");
    else
      transition(Screen::Home);
  }
  void openUsb(Access a) {
    if (!engine_.openWindow(a, now_)) {
      message("USB mode unavailable");
      return;
    }
    decoder_.reset();
    while (Serial.available())
      Serial.read();
    transition(Screen::Usb);
  }
  void serviceUsb() {
    if (txAt_ < transmit_.size()) {
      int room = Serial.availableForWrite();
      size_t n = std::min<size_t>(
          room > 0 ? room : 0, std::min<size_t>(256, transmit_.size() - txAt_));
      if (n)
        txAt_ += Serial.write(transmit_.data() + txAt_, n);
      if (txAt_ == transmit_.size()) {
        erase(transmit_.data(), transmit_.size());
        transmit_.clear();
        txAt_ = 0;
      }
      return;
    }
    decoder_.expire(now_);
    unsigned budget = 512;
    while (budget-- && Serial.available()) {
      if (!decoder_.feed(uint8_t(Serial.read()), now_))
        continue;
      Request request = decoder_.request();
      Reply reply = engine_.request(request, now_);
      if (request.op == Op::Status && reply.result == Result::Ok) {
        String chip = ESP.getChipModel();
        reply.data.push_back(uint8_t(std::min<size_t>(chip.length(), 32)));
        for (size_t i = 0; i < chip.length() && i < 32; i++)
          reply.data.push_back(chip[i]);
        reply.data.push_back(ESP.getChipRevision());
        size_t n = reply.data.size();
        reply.data.resize(n + 4);
        put32(reply.data.data() + n, ESP.getFlashChipSize());
      }
      decoder_.reset();
      if (reply.result == Result::Pending)
        transition(Screen::ConfirmUsb);
      else if (reply.result == Result::NeedKey)
        startInput(KeyTask::Restore);
      else {
        queue(reply);
        if (request.op == Op::Backup && reply.result == Result::Ok) {
          engine_.closeWindow();
          message("Encrypted backup sent");
        }
      }
      break;
    }
  }
  void text(int x, int y, const char *s, uint16_t color = FG) {
    display_.setTextColor(color);
    display_.setCursor(x, y);
    display_.print(s);
  }
  void title(const char *s) {
    text(2, 1, s, ACCENT);
    display_.drawFastHLine(0, 11, 160, ACCENT);
  }
  void footer(const char *s) {
    display_.fillRect(0, 69, 160, 11, BG);
    text(1, 71, s, ACCENT);
  }
  void number(int x, int y, unsigned n) {
    char b[16];
    snprintf(b, sizeof(b), "%u", n);
    text(x, y, b);
  }
  static uint32_t nextCp(const char *&s) {
    uint8_t c = uint8_t(*s++);
    if (c < 128)
      return c;
    unsigned n = c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
    uint32_t cp = c & ((1 << (6 - n)) - 1);
    while (n--)
      cp = (cp << 6) | (uint8_t(*s++) & 63);
    return cp;
  }
  void glyph(uint32_t cp, int x, int y, uint16_t color) {
    int i = recordGlyph(cp);
    if (i < 0)
      return;
    for (int row = 0; row < 12; row++) {
      uint8_t bits = pgm_read_byte(&recordFont[i][row]);
      for (int col = 0; col < 8; col++)
        if (bits & (0x80 >> col))
          display_.drawPixel(x + col, y + row, color);
    }
  }
  // Always walk all text to compute height; drawing alone is viewport-limited.
  void block(const char *value, int &line, int &col, bool draw,
             uint16_t color) {
    auto emit = [&](uint32_t cp) {
      if (cp == '\n') {
        line++;
        col = 0;
        return;
      }
      if (col == 20) {
        line++;
        col = 0;
      }
      int y = 15 + (line - scroll_) * 12;
      if (draw && y >= 15 && y + 12 <= 68)
        glyph(cp, col * 8, y, color);
      col++;
    };
    const char *p = value;
    while (*p) {
      uint32_t cp = nextCp(p);
      if (cp == '\n' || recordGlyph(cp) >= 0)
        emit(cp);
      else {
        char escaped[12];
        snprintf(escaped, sizeof(escaped), "U+%04lX",
                 static_cast<unsigned long>(cp));
        for (const char *t = escaped; *t; t++)
          emit(*t);
      }
    }
  }
  void line(const char *value, int &row, bool draw, uint16_t color = FG) {
    int col = 0;
    block(value, row, col, draw, color);
    row++;
  }
  const Record *currentRecord() {
    const Document *d = engine_.document();
    if (!d)
      return nullptr;
    for (size_t i = 0; i < d->count; i++)
      if (d->items[i].id == selectedId_)
        return &d->items[i];
    return nullptr;
  }
  void detailContent(bool draw) {
    const Record *r = currentRecord();
    if (!r)
      return;
    int row = 0;
    line("Title", row, draw, ACCENT);
    line(r->title, row, draw);
    line("User", row, draw, ACCENT);
    line(r->user[0] ? r->user : "(empty)", row, draw);
    line("Password", row, draw, ACCENT);
    line(reveal_ ? r->password : "[hold SELECT]", row, draw);
    line("Note", row, draw, ACCENT);
    line(r->note[0] ? r->note : "(empty)", row, draw);
    totalLines_ = row;
  }
  void previewTitle(const char *name) {
    int row = 0, col = 0;
    block(name, row, col, true, FG);
  }
  void render() {
    display_.fillScreen(BG);
    display_.setTextSize(1);
    display_.setTextWrap(false);
    switch (screen_) {
    case Screen::Home:
      title("SoloVault 0.1.0");
      if (volume_.unsafeDumpConfiguration()) {
        text(2, 18, "Unsafe crash dump config", WARN);
        text(2, 34, "Remove coredump partition");
        text(2, 49, "See README before setup");
        footer("DOWN: diagnostics");
        break;
      }
      text(2, 16, stateName(store_.state()),
           store_.state() == DiskState::Sealed ? FG : WARN);
      if (engine_.unlocked()) {
        text(2, 29, "UNLOCKED - local use");
        number(2, 41, engine_.document()->count);
        text(22, 41, "records");
        text(2, 54, "SELECT: menu  LEFT: lock");
      } else if (store_.state() == DiskState::Empty) {
        text(2, 30, "SELECT: create vault");
        text(2, 43, "RIGHT: restore backup");
      } else if (store_.state() == DiskState::Sealed ||
                 store_.state() == DiskState::Recovery) {
        text(2, 30, "SELECT: enter owner key");
        text(2, 43, "RIGHT: encrypted backup");
      } else {
        text(2, 30, "No automatic formatting");
        text(2, 43, "DOWN: service menu");
      }
      footer("DOWN: menu");
      break;
    case Screen::Menu:
      title(engine_.unlocked() ? "Vault menu" : "Service menu");
      for (int i = 0; i < 3; i++) {
        int at = std::max(0, menu_ - 1) + i;
        if (at >= 10)
          break;
        text(1, 17 + i * 15, at == menu_ ? ">" : " ");
        text(9, 17 + i * 15, menus_[at], at == menu_ ? ACCENT : FG);
      }
      footer("UP/DN choose  SEL execute");
      break;
    case Screen::OwnerCard:
      title(ownerMismatch_                ? "KEY MISMATCH - TRY AGAIN"
            : keyTask_ == KeyTask::Rotate ? "NEW OWNER KEY"
                                          : "WRITE THIS KEY ON PAPER");
      for (unsigned row = 0; row < 2; row++) {
        char formatted[12]{};
        memcpy(formatted, owner_ + row * 10, 5);
        formatted[5] = ' ';
        memcpy(formatted + 6, owner_ + row * 10 + 5, 5);
        display_.setTextSize(2);
        text(8, 19 + row * 20, formatted, WARN);
        erase(formatted, sizeof(formatted));
      }
      display_.setTextSize(1);
      footer("SEL: re-enter LEFT:cancel");
      break;
    case Screen::OwnerInput: {
      title(keyTask_ == KeyTask::Unlock    ? "ENTER OWNER KEY"
            : keyTask_ == KeyTask::Restore ? "BACKUP OWNER KEY"
                                           : "RE-ENTER ALL 20 SYMBOLS");
      char mask[21]{};
      memset(mask, '*', inputSize_);
      text(2, 15, mask);
      number(130, 15, inputSize_);
      for (unsigned i = 0; i < 32; i++) {
        int x = (i % 8) * 20, y = 27 + (i / 8) * 10;
        if (i == cursor_)
          display_.fillRect(x, y, 19, 10, ACCENT);
        char c[2] = {ALPHABET[i], 0};
        text(x + 6, y + 1, c, i == cursor_ ? BG : FG);
      }
      footer("SEL add/hold del; hold L X");
      break;
    }
    case Screen::Deriving:
      title("DERIVING KEY");
      number(60, 30, derivation_.progress());
      text(85, 30, "%");
      footer("LEFT: cancel");
      break;
    case Screen::Records: {
      title("RECORDS");
      const Document *d = engine_.document();
      if (!d || !d->count)
        text(2, 28, "No records - use menu");
      else
        for (int i = 0; i < 3; i++) {
          int at = std::max(0, selected_ - 1) + i;
          if (at >= d->count)
            break;
          text(1, 16 + i * 16, at == selected_ ? ">" : " ");
          const char *p = d->items[at].title;
          int x = 10;
          while (*p && x <= 144) {
            uint32_t cp = nextCp(p);
            glyph(recordGlyph(cp) < 0 ? '?' : cp, x, 14 + i * 16,
                  at == selected_ ? ACCENT : FG);
            x += 8;
          }
        }
      footer("SEL open  LEFT menu");
      break;
    }
    case Screen::Details:
      title(reveal_ ? "VISIBLE (max 10 sec)" : "RECORD - UP/DOWN scroll");
      detailContent(false);
      scroll_ = std::max(0, std::min(scroll_, std::max(0, totalLines_ - 4)));
      detailContent(true);
      footer("hold SEL show  RIGHT del");
      break;
    case Screen::Usb:
      title("PHYSICAL USB WINDOW");
      text(2, 19,
           engine_.access(now_) == Access::Manage    ? "Manage: 2 min total"
           : engine_.access(now_) == Access::Restore ? "Restore: 5 min total"
                                                     : "Backup: 2 min total");
      text(2, 34, "Start desktop command.");
      text(2, 47, "Check each action here.");
      footer("LEFT: close USB window");
      break;
    case Screen::ConfirmUsb:
      title(engine_.pendingOp() == Op::Put      ? "USB SAVE / REPLACE"
            : engine_.pendingOp() == Op::Delete ? "USB DELETE"
                                                : "USB REPLACE WHOLE VAULT");
      scroll_ = 0;
      if (engine_.pendingOp() == Op::Restore) {
        text(2, 20, "Verified records:");
        number(112, 20, engine_.restoreCount());
        text(2, 38, "Replaces current data");
      } else
        previewTitle(engine_.pendingTitle());
      footer("hold SEL 1s yes LEFT no");
      break;
    case Screen::ConfirmDelete:
      title("DELETE THIS RECORD?");
      scroll_ = 0;
      if (currentRecord())
        previewTitle(currentRecord()->title);
      footer("hold SEL 1s yes LEFT no");
      break;
    case Screen::ConfirmRepair:
      title("REPAIR FROM GOOD SNAPSHOT");
      text(2, 21, "Unfinished write ignored.");
      text(2, 36, "Last good data is used.");
      footer("hold SEL 1s yes LEFT no");
      break;
    case Screen::Reset1:
      title("ERASE ALL STORED DATA?");
      text(2, 22, "This cannot recover keys.");
      text(2, 38, "Have an encrypted backup?");
      footer("hold SEL 2s next LEFT no");
      break;
    case Screen::Reset2:
      title("FINAL: FORMAT DATA FLASH");
      text(2, 22, "ALL FILES WILL BE LOST.", WARN);
      text(2, 38, "Old flash pages may remain");
      footer("hold SEL 3s erase LEFT no");
      break;
    case Screen::Diagnostics: {
      title("HARDWARE / BUILD");
      String chip = ESP.getChipModel();
      text(2, 16, chip.c_str());
      text(2, 28, "revision");
      number(62, 28, ESP.getChipRevision());
      text(2, 40, "flash KiB");
      number(65, 40, ESP.getFlashChipSize() / 1024);
      text(2, 52, "Battery: not calibrated");
      footer("LEFT: back");
      break;
    }
    case Screen::Message:
      title("STATUS");
      text(2, 23, message_);
      text(2, 42, message2_);
      footer("LEFT or SELECT: home");
      break;
    case Screen::SleepWait:
      title("LOCKED - PREPARING SLEEP");
      text(2, 24, "Release all buttons");
      text(2, 40, "SELECT wakes device");
      break;
    default:
      break;
    }
    dirty_ = false;
    lastDraw_ = now_;
  }
  void chooseMenu() {
    if (volume_.unsafeDumpConfiguration() && menu_ != 7) {
      message("Unsafe crash dump config", "See README; data not loaded");
      return;
    }
    switch (menu_) {
    case 0:
      if (!engine_.unlocked())
        message("Unlock locally first");
      else {
        selected_ = 0;
        transition(Screen::Records);
      }
      break;
    case 1:
      if (!engine_.unlocked())
        message("Unlock locally first");
      else {
        Result r = engine_.localGenerate(now_);
        message(resultName(r),
                r == Result::Ok ? "View in Records" : "LEFT: back");
      }
      break;
    case 2:
      openUsb(Access::Manage);
      break;
    case 3:
      openUsb(Access::Backup);
      break;
    case 4:
      if (engine_.unlocked() && store_.state() == DiskState::Sealed) {
        engine_.closeWindow();
        newKey(KeyTask::Rotate);
      } else
        message("Unlock healthy vault first");
      break;
    case 5:
      lock();
      break;
    case 6:
      lock();
      transition(Screen::SleepWait);
      break;
    case 7:
      transition(Screen::Diagnostics);
      break;
    case 8:
      if (engine_.unlocked() && store_.state() == DiskState::Recovery)
        transition(Screen::ConfirmRepair);
      else
        message("No unlocked recovery data");
      break;
    case 9:
      cancelPending();
      engine_.closeWindow();
      transition(Screen::Reset1);
      break;
    }
  }
  void inputTick() {
    if (buttons_.held(Buttons::Left, now_) >= 1200) {
      cancelPending();
      wipeInput();
      transition(Screen::Home);
      return;
    }
    if (buttons_.step(Buttons::Up))
      cursor_ = (cursor_ + 24) % 32;
    if (buttons_.step(Buttons::Down))
      cursor_ = (cursor_ + 8) % 32;
    if (buttons_.step(Buttons::Left))
      cursor_ = (cursor_ + 31) % 32;
    if (buttons_.step(Buttons::Right))
      cursor_ = (cursor_ + 1) % 32;
    if (buttons_.pressed(Buttons::Select))
      selectDeleted_ = false;
    if (!selectDeleted_ && buttons_.held(Buttons::Select, now_) >= 700) {
      if (inputSize_)
        input_[--inputSize_] = 0;
      selectDeleted_ = true;
      dirty_ = true;
    }
    if (buttons_.released(Buttons::Select) && !selectDeleted_) {
      input_[inputSize_++] = ALPHABET[cursor_];
      input_[inputSize_] = 0;
      dirty_ = true;
      if (inputSize_ == 20)
        startDerivation();
    }
  }
  void sleepTick() {
    if (screen_ == Screen::SleepWait) {
      bool released = true;
      for (int pin :
           {board::up, board::down, board::left, board::right, board::select})
        if (digitalRead(pin) == LOW)
          released = false;
      if (!released || now_ - screenSince_ < 150 || !transmit_.empty())
        return;
      if (gpio_wakeup_enable(gpio_num_t(board::select), GPIO_INTR_LOW_LEVEL) !=
              ESP_OK ||
          esp_sleep_enable_gpio_wakeup() != ESP_OK) {
        gpio_wakeup_disable(gpio_num_t(board::select));
        message("Sleep wake setup failed");
        return;
      }
      display_.fillScreen(BG);
      display_.enableDisplay(false);
      display_.enableSleep(true);
      transition(Screen::Sleeping);
      return;
    }
    if (screen_ == Screen::Sleeping && now_ - screenSince_ >= 130) {
      esp_err_t result = digitalRead(board::select) == HIGH
                             ? esp_light_sleep_start()
                             : ESP_ERR_INVALID_STATE;
      gpio_wakeup_disable(gpio_num_t(board::select));
      esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_GPIO);
      now_ = clockMs();
      display_.enableSleep(false);
      transition(Screen::Waking);
      if (result != ESP_OK)
        snprintf(message_, sizeof(message_), "Sleep cancelled / failed");
      else
        message_[0] = 0;
    } else if (screen_ == Screen::Waking && now_ - screenSince_ >= 130) {
      display_.enableDisplay(true);
      if (message_[0])
        message("Sleep cancelled / failed");
      else
        transition(Screen::Home);
    }
  }
  void uiTick() {
    const bool left = buttons_.pressed(Buttons::Left),
               select = buttons_.pressed(Buttons::Select);
    switch (screen_) {
    case Screen::Home:
      if (engine_.unlocked()) {
        if (left)
          lock();
        else if (select) {
          menu_ = 0;
          transition(Screen::Menu);
        }
      } else if (select) {
        if (store_.state() == DiskState::Empty)
          newKey(KeyTask::Create);
        else if (store_.state() == DiskState::Sealed ||
                 store_.state() == DiskState::Recovery)
          startInput(KeyTask::Unlock);
      }
      if (buttons_.pressed(Buttons::Right) && !engine_.unlocked())
        openUsb(store_.state() == DiskState::Empty ? Access::Restore
                                                   : Access::Backup);
      if (buttons_.pressed(Buttons::Down)) {
        menu_ = engine_.unlocked() ? 0 : 7;
        transition(Screen::Menu);
      }
      break;
    case Screen::Menu:
      if (left)
        transition(Screen::Home);
      else if (select)
        chooseMenu();
      else {
        if (buttons_.step(Buttons::Up))
          menu_ = (menu_ + 9) % 10;
        if (buttons_.step(Buttons::Down))
          menu_ = (menu_ + 1) % 10;
      }
      break;
    case Screen::OwnerCard:
      if (left) {
        wipeInput();
        transition(Screen::Home);
      } else if (select)
        startInput(keyTask_);
      break;
    case Screen::OwnerInput:
      inputTick();
      break;
    case Screen::Deriving:
      if (left) {
        cancelPending();
        wipeInput();
        transition(Screen::Home);
      } else
        derivationTick();
      break;
    case Screen::Records: {
      const Document *d = engine_.document();
      if (!d) {
        lock();
        break;
      }
      if (left)
        transition(Screen::Menu);
      else if (d->count) {
        if (buttons_.step(Buttons::Up))
          selected_ = (selected_ + d->count - 1) % d->count;
        if (buttons_.step(Buttons::Down))
          selected_ = (selected_ + 1) % d->count;
        if (select) {
          selectedId_ = d->items[selected_].id;
          scroll_ = 0;
          transition(Screen::Details);
        }
      }
      break;
    }
    case Screen::Details:
      if (!currentRecord()) {
        lock();
        break;
      }
      if (left) {
        transition(Screen::Records);
        break;
      }
      if (buttons_.pressed(Buttons::Right)) {
        transition(Screen::ConfirmDelete);
        break;
      }
      if (buttons_.step(Buttons::Up) && scroll_ > 0)
        --scroll_;
      if (buttons_.step(Buttons::Down) && scroll_ < totalLines_ - 4)
        ++scroll_;
      {
        bool visible = buttons_.down(Buttons::Select) &&
                       buttons_.held(Buttons::Select, now_) < 10000;
        if (visible != reveal_) {
          reveal_ = visible;
          dirty_ = true;
        }
      }
      break;
    case Screen::Usb:
      if (left || engine_.access(now_) == Access::Closed) {
        engine_.closeWindow();
        decoder_.reset();
        transition(Screen::Home);
      }
      break;
    case Screen::ConfirmUsb:
      if (left || buttons_.held(Buttons::Select, now_) >= 1000) {
        Reply reply = engine_.approve(!left, now_);
        queue(reply);
        engine_.closeWindow();
        message(resultName(reply.result));
      }
      break;
    case Screen::ConfirmDelete:
      if (left)
        transition(Screen::Details);
      else if (buttons_.held(Buttons::Select, now_) >= 1000) {
        Result r = engine_.localDelete(selectedId_, now_);
        selected_ = 0;
        message(resultName(r));
      }
      break;
    case Screen::ConfirmRepair:
      if (left)
        transition(Screen::Home);
      else if (buttons_.held(Buttons::Select, now_) >= 1000) {
        Result r = engine_.repair(now_);
        message(resultName(r));
      }
      break;
    case Screen::Reset1:
      if (left)
        transition(Screen::Home);
      else if (buttons_.held(Buttons::Select, now_) >= 2000)
        transition(Screen::Reset2);
      break;
    case Screen::Reset2:
      if (left)
        transition(Screen::Home);
      else if (buttons_.held(Buttons::Select, now_) >= 3000) {
        lock();
        display_.fillScreen(BG);
        title("FORMATTING - KEEP POWER");
        bool ok = volume_.factoryReset();
        store_.scan();
        message(ok ? "Erased; create a new vault" : "Reset failed; use backup");
      }
      break;
    case Screen::Diagnostics:
      if (left || select)
        transition(Screen::Home);
      break;
    case Screen::Message:
      if (left || select)
        transition(Screen::Home);
      break;
    case Screen::SleepWait:
    case Screen::Sleeping:
    case Screen::Waking:
      sleepTick();
      break;
    }
  }

public:
  void setup() {
    Serial.begin(115200);
    for (int pin :
         {board::up, board::down, board::left, board::right, board::select})
      pinMode(pin, INPUT_PULLUP);
    SPI.begin(board::sclk, board::miso, board::mosi, board::cs);
    display_.initR(INITR_MINI160x80_PLUGIN);
    display_.setRotation(board::rotation);
    display_.setSPISpeed(board::spiHz);
    display_.fillScreen(BG);
    title("SoloVault - mounting");
    volume_.begin();
    store_.scan();
    now_ = clockMs();
    transition(Screen::Home);
    render();
  }
  void loop() {
    now_ = clockMs();
    std::array<bool, 5> raw = {
        digitalRead(board::up) == LOW, digitalRead(board::down) == LOW,
        digitalRead(board::left) == LOW, digitalRead(board::right) == LOW,
        digitalRead(board::select) == LOW};
    buttons_.update(raw, now_);
    // Check expiry before a new physical event could extend an expired session.
    if (engine_.expired(now_))
      lock();
    if (engine_.pendingExpired(now_)) {
      queue(engine_.approve(false, now_));
      wipeInput();
      engine_.closeWindow();
      message("USB approval expired");
    }
    if (keyDeadline_ && now_ >= keyDeadline_) {
      cancelPending();
      wipeInput();
      message("Key entry expired");
    }
    if (buttons_.activity()) {
      engine_.localActivity(now_);
      dirty_ = true;
    }
    if (screen_ != Screen::Sleeping && screen_ != Screen::Waking)
      serviceUsb();
    uiTick();
    if (screen_ != Screen::Sleeping && screen_ != Screen::Waking &&
        (dirty_ || (screen_ == Screen::Deriving && now_ - lastDraw_ >= 250)))
      render();
    delay(1); // RTOS yield; no waiting for serial/network/buttons.
  }
};
constexpr const char *App::menus_[10];
App app;
} // namespace
void soloSetup() { app.setup(); }
void soloLoop() { app.loop(); }
