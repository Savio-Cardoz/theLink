# theLink MQTT Security — Implementation Log

Tracked implementation of TLS transport, config-guarded HMAC command
authentication, and signed-OTA (hash-then-sign) hardening.

Environment: ESP-IDF 5.4.1 at ~/.espressif/v5.4.1/esp-idf.

## Tasks

- [x] Scaffold (this file, todos)
- [x] Kconfig.projbuild: TLS broker default, creds, HMAC mode/key/window, OTA verify toggle
- [x] components/mqtt_auth: HMAC-SHA256 verify against MQTT5 user properties
- [x] main.cpp: TLS + credentials wiring in mqtt5_app_start
- [x] main.cpp: HMAC gate in mqtt5_event_handler (MQTT_EVENT_DATA)
- [x] main.cpp: firmware signature verify (SHA-256 of update.bin, ECDSA P-256)
- [x] main/firmware_pubkey.h: embedded public key (+ keys/ gitignored)
- [x] scripts/sign_update.py + scripts/verify_update.py
- [x] sdkconfig.defaults/.prod, CMakeLists (main + new component), .gitignore, Readme
- [x] docs/ota_signing.md
- [x] Build Dev + Prod to verify

## Detailed steps

### 2026-09-24 — Scaffold
- Created this log; checked environment (cryptography 41.0.7 available, openssl ok).
- Confirmed IDF 5.4 esp-mqtt API: `.broker.verification.crt_bundle_attach`,
  `.credentials.username` / `.authentication.password`, MQTT5 received
  user-properties via `event->property->user_property`
  (`esp_mqtt5_client_get_user_property` / `..._count`).

### 2026-09-24 — Kconfig.projbuild
- `BROKER_URL` default now `mqtts://broker.emqx.io:8883` (TLS).
- Added `MQTT_USERNAME`, `MQTT_PASSWORD` (optional broker credentials).
- Added `MQTT_HMAC_MODE` choice (DISABLED / OPTIONAL / REQUIRED, default DISABLED).
- Added `MQTT_HMAC_KEY` (string, default "") + `MQTT_HMAC_REPLAY_WINDOW_S` (int, default 0).
- Added `OTA_SIGNATURE_VERIFY` (bool, default y).
- Note: device has no clock sync — SNTP must be added or TLS cert validation
  (and the ts replay window) will fail. Added to main.cpp plan.

### 2026-09-24 — components/mqtt_auth
- New component REQUIRES mbedtls mqtt; exposed mqtt_auth_get_mode() /
  mqtt_auth_enabled() / mqtt_auth_result_str() / mqtt_auth_verify(event).
- Verify computes HMAC-SHA256 over topic+'\0'+payload (mbedtls_md_hmac),
  decodes the "hmac" user property hex, constant-time compares 32 bytes.
- Optional "ts" replay window when CONFIG_MQTT_HMAC_REPLAY_WINDOW_S > 0;
   fails closed if device clock is unsynced or ts missing/outside window.
- Fails closed (no key -> NO_KEY, no MQTT5 -> INVALID).

### TODO next
- main.cpp: SNTP start (GOT_IP), pre-MQTT clock wait, TLS + creds wiring,
  HMAC gate in MQTT_EVENT_DATA, legacy topic removal, firmware signature verify.
- firmware_pubkey.h + scripts (sign_update.py / verify_update.py) + keys/ gitignore.
- sdkconfig.defaults/prod, CMakeLists, Readme, docs/ota_signing.md.
- Build Dev + Prod.

### 2026-09-24 — main.cpp wiring
- Added SNTP (`esp_netif_sntp_init`, non-blocking, pool.ntp.org) started on
  IP_EVENT_STA_GOT_IP (cert verification + ts replay need a wall clock).
- Added `wait_for_clock(10)` head-start before mqtt5_app_start().
- mqtt5_app_start: `esp_crt_bundle_attach` + hostname check for mqtts://;
  optional CONFIG_MQTT_USERNAME/PASSWORD wired to credentials.
- Removed legacy CONFIG_COMMAND_TOPIC subscribe (cross-device control surface).
- MQTT_EVENT_DATA: config-guarded HMAC gate before topic dispatch
  (DISABLED/OPTIONAL/REQUIRED semantics).
- Added sha256_file() + verify_firmware_signature() (ECDSA P-256, DER) called
  in handle_firmware_update under CONFIG_OTA_SIGNATURE_VERIFY.

### 2026-09-24 — signing tooling + docs
- scripts/sign_update.py (load/create P-256 key, embed pubkey header, sign
  SHA-256 digest -> DER .sig), scripts/verify_update.py (CI verify).
- Generated keys/ (gitignored) + main/firmware_pubkey.h. Round-trip tested:
  sign OK, tampered image rejected (exit 1).
- sdkconfig.defaults: CONFIG_MQTT_TRANSPORT_SSL + CERTIFICATE_BUNDLE on.
- main/CMakeLists: REQUIRES +mqtt_auth mbedtls esp_netif. .gitignore keys/.
- Readme: config table + MQTT security section + MQTTX HMAC snippet.
- docs/ota_signing.md: full Tier A (hash-then-sign) process + Tier B.

### 2026-09-24 — Build verification
- Fix: `sizeof(*items)` in mqtt_auth.cpp broke `auto` deduction at init.
- Dev: BUILD OK (binary 0x3da9e0, 51% free in factory partition).
- Prod: BUILD OK (pre-existing partition-size packaging warning for factory,
  app targets ota_0 which fits).
- Config check: HMAC_MODE=DISABLED (default), HMAC_KEY="", REWIND=0,
  OTA_SIGNATURE_VERIFY=y, CERTIFICATE_BUNDLE=y, TRANSPORT_SSL=y, PROTOCOL_5=y,
  BROKER_URL="mqtts://broker.emqx.io:8883".
- Remaining for the user: generate/replace keys for production, sign real
  images, run on-device MQTTX + signed-OTA acceptance tests.