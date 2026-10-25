# SoloVault — Offline Password Vault

**Firmware `0.1.0` · independent ESP32 prototype · display and buttons · optional USB management · no wireless services**

SoloVault is a **from-scratch alternative to Pocket Password Storage (PPS)**. It is not a renamed PPS release: the only design details carried over from the earlier project are the confirmed button/display pin assignments and ST7735 configuration. The application sources, storage format, authentication, web client, and migration procedures were **not reused**.

> **PPS vaults and backups are not compatible with SoloVault.** There is no automatic PPS migration or PPS unlock/recovery procedure. Changing the partition map, formatting SPIFFS, or flashing the wrong image can make existing data inaccessible.

## Contents

- [Version history and relationship to PPS](#version-history-and-relationship-to-pps)
- [Features and design goals](#features-and-design-goals)
- [Repository layout and hardware](#repository-layout-and-hardware)
- [Building and flashing](#building-and-flashing)
- [Required crash-dump protection and partitions](#required-crash-dump-protection-and-partitions)
- [First-time setup](#first-time-setup)
- [On-device operation](#on-device-operation)
- [Desktop USB client](#desktop-usb-client)
- [Encrypted backups, restore, and recovery](#encrypted-backups-restore-and-recovery)
- [Security architecture and limitations](#security-architecture-and-limitations)
- [Storage format and USB protocol](#storage-format-and-usb-protocol)

## Version history and relationship to PPS

| Version | Release description |
| --- | --- |
| **`SoloVault 0.1.0`** | **Initial documented SoloVault prototype:** independent offline firmware, 20-character random owner code, on-device viewing/password generation, locally approved USB management, authenticated encrypted snapshots, encrypted backup/restore, explicit repair after an interrupted write, and crash-dump safety checks. |

**SoloVault 0.1.0 source code and documentation are available and the features listed below have been checked against the implementation.** There are no earlier/later SoloVault source releases in the supplied materials, so this is an **initial release summary**, not a version-to-version changelog. SoloVault does **not** inherit the PPS version sequence (2.1.0 → 2.1.1 → 2.1.3).

### SoloVault compared with PPS 2.1.3

| Topic | SoloVault 0.1.0 | PPS 2.1.3 |
| --- | --- | --- |
| Architecture | Independent rewrite; standalone offline vault | Existing PPS firmware evolved across releases |
| User interface | TFT display, buttons, physically approved USB commands | TFT/buttons and local HTTPS browser interface |
| Networking | **No Wi-Fi, BLE, HTTP, or OTA application services** | Protected Wi-Fi AP/STA, HTTPS, mDNS |
| Vault capacity | **32** records | **128** records |
| Unlocking | **Board-generated 20-character, 100-bit owner code** entered on the board | Physical **6–8-digit PIN** plus web-side master-password workflow |
| Stored password retrieval | On-device display only; **no USB read-password command** | Device screen and authenticated Web UI |
| PC management | Python client over local USB serial; requires physical permission | Embedded Web UI over HTTPS; `web/` assets compiled into firmware |
| Encryption architecture | PBKDF2 root key → per-snapshot HKDF key → AES-256-GCM | Wrapped data-encryption key and protected v3 snapshot protocol |
| Backup format | `.solovault`, format/USB protocol **1** | PPS-specific encrypted backups; **not compatible** |
| Data migration | **No import of PPS formats** | Legacy PPS migration subject to its own rules |
| Referenced Arduino core | **2.0.17** for the documented test build | **3.x** for the provided PPS 2.1.3 sources |
| Deployment | Hardware qualification **pending** | Also experimental; tests and build status depend on archive |

**Switching branches is a new installation, not a direct upgrade.** Export and independently verify any PPS records *before* changing firmware or partitions. Do not flash SoloVault onto a PPS data partition expecting it to read PPS records.

## Features and design goals

- Fully usable without a computer after setup: view up to **32 entries** and generate a local **20-character password**.
- Show a stored password only while **SELECT** is held, with a maximum continuous reveal of **10 seconds**.
- Use the display and physical buttons for unlocking, destructive-operation confirmation, and sleep/lock controls.
- Provide a Python USB client for listing **IDs and titles**, creating/replacing/deleting entries, and transferring **encrypted** backups. USB has no command for retrieving a stored password or the owner code.
- Keep USB access closed by default; changes require on-device unlock and a fresh physical confirmation. USB traffic does not prolong an unlocked session.
- Lock manually, after **90 seconds** without button input, after an absolute **15 minutes** unlocked, and before sleep.
- Use an owner code generated *on the device*: **20 symbols from a 32-character alphabet = 100 bits** if the device RNG behaves correctly. There is no short fallback PIN or recovery bypass.

> [!IMPORTANT]
> **Write down the owner code on paper and keep it separate from the board and any backup.** Losing it means losing access to the encrypted vault; the documented alternative is a destructive reset. Existing encrypted backups still need the particular owner code that protected them when created.

## Repository layout and hardware

The following tree matches the supplied `SoloVault.zip` source archive and the English documentation assembled for GitHub. The `docs/` entries were provided separately and are included in the reviewed documentation bundle.

```text
SoloVault/
  SoloVault.ino                 Arduino entry point
  board.h, build_opt.h         Hardware pinout and build options
  solo_app.cpp, solo_buttons.h  UI, buttons, USB flow and sleep
  solo_core.*, solo_engine.*    Crypto, snapshots, vault and access policy
  solo_wire.*, solo_platform.h  USB framing, RNG and SPIFFS/NVS adapter
  record_font.h                Pre-generated text glyphs
desktop/
  requirements.txt             pyserial==3.5
  solovault.py                 Local USB client (Python 3.10+)
tools/
  remove_coredump.py           Partition CSV copy helper
  make_font.py                 Optional font-header generator (Pillow)
third_party/
  DejaVu-LICENSE.txt           Font attribution/license
docs/
  ARCHITECTURE.md              Architecture and security limits
  FORMAT_AND_USB.md            Exact snapshot and USB wire format
  BOARD_TESTS.md               Hardware test plan (not executed)
  SOURCE_REVIEW.md             Scope and results of code review
  partitions-no-coredump-4MB-example.csv
  source_ru/                   Original Russian documents
README.md                     This English guide
```

### Display and confirmed pin assignments

| Hardware/function | GPIO or setting |
| --- | --- |
| UP / DOWN | **8 / 13** |
| LEFT / RIGHT | **5 / 9** |
| SELECT | **4** |
| TFT SCLK / MOSI / MISO | **2 / 3 / none** |
| TFT CS / DC / RST | **7 / 6 / 10** |
| Display | **ST7735, 160 × 80** |
| Display init / rotation | `INITR_MINI160x80_PLUGIN`, rotation **3** |
| SPI frequency | **24 MHz** |
| Buttons | Active LOW; `INPUT_PULLUP` |
| Battery input | **GPIO0**; battery measurement **disabled** in 0.1.0 |

The **exact chip model/revision, battery-divider circuit, and separately controllable backlight GPIO are not confirmed**. A successful ESP32-C3 test build does not identify your physical board. Read the hardware identity shown by **Diagnostics** or the USB `status` command and verify its wiring before relying on the firmware.

## Building and flashing

1. Obtain and fully extract the **SoloVault source archive**; open `SoloVault/SoloVault.ino` in Arduino IDE. Keep every adjacent `.cpp` and `.h` file in the sketch folder.
2. In Boards Manager, install **esp32 by Espressif Systems `2.0.17`**. This is the **documented pinned test environment**, not a statement that it is the latest SDK. Compatibility with Arduino-ESP32 3.x was **not tested** for this release.
3. Install **Adafruit GFX Library `1.11.11`**, **Adafruit ST7735 and ST7789 Library `1.10.4`**, and **Adafruit BusIO `1.16.2`**. ArduinoJson and web-server libraries are not needed.
4. Select the **previously verified** board model, flash size, USB mode and `USB CDC On Boot` setting if using native CDC. External USB–UART uses its own serial device. Set **Core Debug Level: None**. Do not infer a board model solely from the ESP32-C3 reference build.
5. Prepare a verified partition layout **without `data,coredump`** as described in the next section. The firmware checks that mounted SPIFFS has at least **128 KiB total capacity** (`SPIFFS.totalBytes() >= 131072`). Each snapshot write additionally requires free space for the new encrypted file **plus 8 KiB**. A **256 KiB or larger SPIFFS partition** is a practical starting point, subject to your actual partition layout and backup strategy.
6. Run **Verify**, then **Upload**. The firmware does not wait for Serial to be connected before starting. **Do not enable Erase All Flash** unless you have explicitly accepted losing old data.

The firmware UI/font are compiled into the sketch. There is **no `web/` source-to-header pipeline, HTML/CSS upload, `data/` directory, or SPIFFS filesystem-image upload** in SoloVault. SPIFFS is used for encrypted vault snapshots.

## Required crash-dump protection and partitions

The standard Arduino ESP32 core can save task stack data to a `data,coredump` flash partition after a crash. That memory can contain keys or other sensitive data. **SoloVault refuses to initialize or load secrets** when it finds such a partition, or if the SDK is configured for a complete core dump to UART. It reports **`Unsafe crash dump config`**; Diagnostics/status remain available. This safety stop is **not** an incorrect owner code.

Modify **your actual working CSV**, removing only the row whose **type = `data`** and **subtype = `coredump`**, preserving the other partition offsets and sizes. With the documented helper present in your **source archive**:

```sh
python tools/remove_coredump.py current-partitions.csv SoloVault/partitions.csv
```

The described utility writes a new CSV, refuses to overwrite an existing output, and does **not** flash the board. It rejects an unsafe deletion if following partitions rely on implicit offsets; fix those offsets first. The installed Arduino core's reference CSVs are described as being in `tools/partitions`; verify your selected **Partition Scheme** against its `boards.txt`.

The supplied [`4 MiB example CSV`](docs/partitions-no-coredump-4MB-example.csv) follows a documented Arduino Default-type layout with the coredump row omitted, leaving the last **64 KiB unassigned**. It is an **example only**, not a safe default for every board or installed vault; copy it into `SoloVault/partitions.csv` only if all offsets and sizes match your board's required layout. Removing a partition row does **not** securely erase existing crash dumps. Moving or resizing SPIFFS can make previous data unreadable.

> [!CAUTION]
> **`Core Debug Level: None` and deleting a coredump partition do not fully disable ordinary panic register output.** For a stronger deployment, use a custom SDK build with all core dumps and sensitive panic output disabled. This limitation remains in the documented 0.1.0 prototype.

## First-time setup

1. On an empty, valid SPIFFS vault, press **SELECT**. The device displays a randomly generated owner code as **four groups of five symbols**.
2. Write down all **20 symbols** exactly, then press SELECT and re-enter the whole code using the on-device character grid. Spaces shown between groups are **not** entered.
3. Move between symbols with the arrow keys; a short **SELECT** press adds a symbol when released. Hold **SELECT** for at least **0.7 s** to delete the last symbol; hold **LEFT** for at least **1.2 s** to cancel.
4. Finish within **5 minutes**. Only a complete correct repeat derives the root key and commits the first verified encrypted snapshot. A mismatch returns to the original code display; setup is not finished until the write succeeds.

Allowed alphabet: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (excludes **I, O, 0, 1** to reduce transcription mistakes).

If the device reports **`Other files found`**, a mount failure, or non-SoloVault data, it will **not** silently migrate or format the filesystem. Only after saving old data should you choose **DOWN → Erase / reset** and confirm by holding SELECT **2 s**, releasing it, then holding it **3 s** separately. This **formats all of SPIFFS** and does not clear other NVS namespaces or bypass the crash-dump check. Logical deletion is not guaranteed physical flash erasure.

## On-device operation

- **Unlocked home screen:** SELECT opens the menu; LEFT locks. **Generate password** creates an entry titled `Password N` with a new random **20-character** password; rename or edit its other fields later using the desktop client.
- **Entry list:** UP/DOWN selects, SELECT opens, LEFT returns.
- **Entry details:** UP/DOWN scrolls through all fields; LEFT returns; RIGHT requests delete confirmation; a fresh hold of SELECT reveals the password for **at most 10 seconds** until released.
- **Character display:** values support ASCII, Latin-1 and Cyrillic; unsupported Unicode scalars appear as `U+XXXX` in details or `?` in the short list. Valid UTF-8 remains intact in storage.
- **Sleep:** clears the root key and entries from RAM, waits for buttons to be released, enters light sleep, and wakes on a fresh SELECT LOW event. Unlock with the owner code again. There is no guarantee that the backlight turns off or that sleep current is low. Battery percentage is not shown because battery-divider calibration is unknown; ADC0 is unused.

## Desktop USB client

The included `desktop/solovault.py` client uses **Python 3.10+** and `pyserial==3.5` (pinned in `desktop/requirements.txt`). Open a terminal in the repository root:

```sh
python -m pip install -r desktop/requirements.txt
python desktop/solovault.py ports
python desktop/solovault.py --port COM5 status
python desktop/solovault.py --port COM5 add --title "Email" --user "name@example.test" --generate 20
python desktop/solovault.py --port COM5 list
python desktop/solovault.py --port COM5 add --title "Existing password" --user "login"
python desktop/solovault.py --port COM5 edit 0123456789abcdef --title "Email" --user "login" --note "Note" --keep-password
python desktop/solovault.py --port COM5 delete 0123456789abcdef
python desktop/solovault.py --port COM5 backup first-backup.solovault
python desktop/solovault.py --port COM5 restore first-backup.solovault
```

Use your real port (`COM5` is an example; Linux native CDC is often `/dev/ttyACM0`) and an actual record ID from `list`; `0123456789abcdef` is **illustrative only**. Close Arduino Serial Monitor before using the client. The client opens the port **before** asking you to unlock, because some USB bridges reset the board when opened. It disables RTS/DTR ahead of time; actual behavior still needs hardware testing.

### Physical permission and operation flow

- **`status`** is publicly available when USB is closed but contains only version, vault state, lock/access state, and reported hardware identity.
- For **`add` / `edit` / `delete` / `list`**, unlock locally, select **USB manage**, then press Enter on the PC when prompted. The **Manage** window lasts **120 seconds**. Mutating operations wait up to **60 seconds** for a new physical confirmation: inspect the operation/title on the screen and hold SELECT for **1 second**. Release a previously held SELECT first. LEFT denies. Manage closes after a change; after `list` it remains until timeout or cancellation.
- **`edit` replaces title, user and note in full**: omitted `user`/`note` become empty. `--keep-password` keeps only the old password. Otherwise, unless `--generate` is used, the client prompts twice in the terminal for a hidden password. There is **no password argument** on the command line.
- A **board-generated** password is not returned to the PC. No USB operation accepts the owner code, unlocks the vault, exposes plaintext stored passwords, formats storage, or performs OTA.

> [!WARNING]
> **USB serial is not an encrypted or authenticated transport.** A new password typed on the PC appears in the Python process memory and is transmitted **in plaintext over USB**. Python strings cannot reliably be scrubbed. Frame CRC32 detects accidental corruption; it does **not** authenticate the computer or provide confidentiality. Use a trusted PC and check each requested change on the physical screen.

## Encrypted backups, restore, and recovery

### Backup

Select **Encrypted backup** on the device even while it is locked. This grants one **120-second, single-use** transfer window for an *already encrypted* snapshot. The desktop client checks structure and SHA-256, writes with no silent overwrite, and calls `fsync`. A backup cannot be decrypted without the **owner code used for that copy**. Store that code separately from the `.solovault` backup.

### Restore

- **Empty vault:** RIGHT enables Restore for **5 minutes**. Send the encrypted backup, then enter *its* owner code using the **physical buttons**, let the device verify GCM, and approve the replacement with SELECT. Nothing is committed before validation and confirmation. Restart the restore command after an incorrect owner code.
- **Nonempty unlocked vault:** Restore from Manage requires a backup with the **same vault identity and key**, authenticated GCM/schema, and a fresh physical confirmation; it replaces the whole record set as a new local generation. Importing an unrelated vault requires an empty instance or deliberate destructive reset.
- **Intentional rollback:** a valid old backup may restore **older records**. Independently verify the record set after restoring.

### Change owner code

**Change owner key** creates a new random code, requires writing it down and correctly repeating all 20 symbols, then re-encrypts current entries under a **new vault identity/salt**, verifies the new snapshot, removes old snapshot files, and locks. Previous external backups and residual erased pages can remain protected by the **old** code. Make a new backup; if the old code was exposed, change affected passwords at their online services too.

### Interrupted writes and recovery

When a newer generation was interrupted, the vault enters **`Recovery required`**. After owner-code entry, the last complete snapshot is available **read-only**, including a ciphertext-only backup, but regular modifications are blocked. A separate **Repair interrupted write** action, with confirmation, publishes a new verified generation based on the valid data. If every snapshot or SPIFFS itself is corrupt, recovery requires an **external backup**. Normally retaining three generations on one filesystem does not protect against a failure of that filesystem.

## Security architecture and limitations

This summarizes [Architecture and threat model](docs/ARCHITECTURE.md). The mechanisms were cross-checked against `solo_core.cpp`, `solo_engine.cpp`, `solo_wire.cpp`, `solo_platform.h`, and `solo_app.cpp`, but **this limited review is not a comprehensive security audit or certification**.

| Mechanism | Design in 0.1.0 |
| --- | --- |
| Owner secret | **20 random base-32 characters**, 100-bit target entropy; never stored in firmware/NVS/files or sent via USB |
| Root key | **PBKDF2-HMAC-SHA256**, 100,000 iterations, 16-byte vault salt → 32-byte root key |
| Per-snapshot key | **HKDF-SHA256** from the root, fresh 32-byte snapshot salt, `info="SoloVault snapshot key v1"` |
| Encryption and integrity | **AES-256-GCM**, unique random 12-byte IV, 16-byte tag; 100-byte authenticated header (AAD) |
| Snapshots | Immutable `/sv_XXXXXXXX.dat` generations, write/flush/commit/hash/read-back verification; usually three complete generations retained |
| NVS | Only `soloctl/initialized` status flag; **no root key, owner code or active-generation pointer** |
| USB access | Explicit board modes and physical confirmation; bounded frames, CRC32, request IDs, revisions and timeouts |
| RNG | `esp_fill_random` with temporary hardware entropy enabling; no radio operation in the application; physical-board RNG quality **not measured** |
| Secret lifetime | Owner code/PBKDF2 context cleared after derivation; RAM key and records wiped on lock and sleep, subject to lower-level platform limits |

The storage format has a separate random per-generation key/salt to reduce the probability of key/IV repetition across interrupted writes; this is **not** a monotonic hardware anti-rollback counter. SHA-256 footers detect file truncation, but **AES-GCM**, after key derivation, supplies authenticity. An attacker with arbitrary physical flash-write access can cause denial of service or restore an older flash image; **complete flash rollback is not reliably detected**.

### Important limits of protection

- **No Secure Boot, Flash Encryption or eFuse provisioning** is performed. An attacker who replaces firmware may be able to capture a **future** owner-code entry; the design does not authenticate running firmware to the user.
- **Unlocked-device theft, debug access, RAM extraction, side channels, camera observation and malicious host PCs** are outside the verified protection scope. Clearing application buffers cannot guarantee clearing all registers, transient copies or third-party libraries.
- **Crash dumps and panic output** require special care: the app rejects known unsafe coredump configurations, but the standard panic handler can still reveal register values. Removing a partition does not securely erase prior dumps.
- **Lost owner code means no decryption recovery.** Reset is destructive. SPIFFS formatting and removal of old generation files are not guaranteed physical sanitization of flash.
- Entropy sourcing, hardware identity, power-loss behavior, endurance and low-voltage behavior are **not qualified on the intended board**. The project has **not been independently audited**.

## Storage format and USB protocol

SoloVault uses its **own format version 1 / serial protocol 1**. Full byte-level specifications and status codes are in [`docs/FORMAT_AND_USB.md`](docs/FORMAT_AND_USB.md); the crucial interoperability details are:

- **Encrypted file:** `SOLOV1\r\n` magic, format/generation/length/KDF parameters, 16-byte vault ID, 16-byte vault salt, 32-byte snapshot salt, 12-byte GCM IV, ciphertext and tag, `SVCOMMIT`, and a final SHA-256. The GCM AAD is the first **100 bytes**.
- **Encrypted backup:** `.solovault` extension, containing the already-encrypted snapshot; never plaintext export. No support for previous PPS storage formats.
- **Document:** `SVDOC001` magic and up to **32** entries, each with an **8-byte random ID** and bounded UTF-8 title/user/password/note fields (max **48 / 64 / 96 / 160 bytes** respectively). Title and password must not be empty.
- **Serial:** **115200, 8N1**, native CDC possibly ignoring the baud rate; binary `SVC1` frames with op, request ID, payload length, and CRC32; maximum payload **12,524 bytes**, partial-frame timeout **5 seconds**. Messages are **not** text/JSON commands.
- **Operations:** `Status (0x01)`, `List (0x10)`, `Put (0x11)`, `Delete (0x12)`, `Backup (0x20)`, `Restore (0x21)`. `Put` can use a supplied password, generate one on the board, or preserve an existing password. Revisions are SHA-256 concurrency tokens, **not MACs**.

**Do not develop a PPS-format converter or USB plaintext-read endpoint on the assumption that one already exists.** No conversion from PPS, host unlock, remote erase, plaintext export, or OTA endpoint is specified.
