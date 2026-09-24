# TheLink — OTA via SD Card (session plan, progress & pending work)

Plan / status for adding firmware-over-MQTT updates using the shared
`esp32_factory_app` + `ota_0` layout. Two cooperating firmware images:

- **TheLink main app** (`TheLink/`) — current firmware in `ota_0`. Receives the
  MQTT `cmd/ota` command, downloads the image to SD, records an update intent in
  NVS, then reboots into the factory app.
- **esp32_factory_app** (`../esp32_factory_app/`, inside `factory` partition) —
  bootloader-side app that flashes `/sdcard/update.bin` into `ota_0`, backs up /
  restores the last-known-good image, and reports the outcome back.

---

## Plan (from session)

1. Redesign the partition table for OTA with a shared `esp32_factory_app`
   bootloader:
   - `otadata` @ 0xe000 (2 KB)
   - `factory` — bootloader app (esp32_factory_app), 2 MB @ 0x10000
   - `ota_0` — TheLink main app, 5 MB @ 0x210000
   - Keep a separate **dev** partition table (single `factory` app, no OTA) so
     day-to-day development stays simple.
2. Split build profiles so one switch selects dev (no OTA) vs prod (OTA):
   - Dev: `partitions_dev.csv`, builds into `build-dev`, plain `idf.py flash`.
   - Prod: `partitions.csv`, builds into `build`, flashed with
     `scripts/flash_all.py` (bootloader + partition table + both apps).
     `flash_all.py` also programs the `otadata` partition (offset 0xe000) so a
     first production flash boots straight into `ota_0` (TheLink) instead of
     the factory app: default state `NEW` (bootloader -> `PENDING_VERIFY`,
     TheLink confirms `VALID` on first boot, crash-back preserved); `--ota
     valid` and `--no-otadata` alternatives.
   - Give `esp32_factory_app` the same tooling in its own repo:
     `scripts/build.py` + `scripts/idf_env.py` (mirrors TheLink's, plus PATH /
     IDF_* env bootstrap so no ESP-IDF `export.bat` is needed).
3. Introduce an explicit update intent, shared via NVS, so the factory app only
   flashes `/sdcard/update.bin` when the main app actually requested an update
   (a stale `update.bin` must never clobber a working `ota_0`).
4. TheLink app:
   - Subscribe to `thelink/{id}/cmd/ota`; publish progress to
     `thelink/{id}/evt/ota` (`started`, `downloaded`, `rebooting`, `failed`,
     `update_success`, `update_restored`).
   - Download firmware to `/sdcard/update.bin` via the existing downloader,
     validate the image, record the NVS intent, switch boot partition to
     `factory`, show "Update in progress" on the e-paper, reboot.
   - On boot: confirm the running app as VALID (first-boot rollback test),
     clear stale intents, and publish any deferred outcome once MQTT connects.
5. esp32_factory_app:
   - Flash `update.bin` into `ota_0` only when the NVS intent says
     `UPDATE_REQUESTED` / `UPDATE_IN_PROGRESS`.
   - Snapshot the current `ota_0` to `/sdcard/boot_backup.bin` (CRC-verified)
     before flashing; restore it on flash failure or failed first-boot test
     (crash-back detection).
   - Boot the existing `ota_0` app when there is nothing to apply.

---

## Progress (done)

### TheLink main app (`TheLink/`) — uncommitted working-tree changes on `v2`
- `main/CMakeLists.txt`: added `app_update` (and `nvs`) component.
- `main/main.cpp`:
  - MQTT topics `thelink/{id}/cmd/ota` and `thelink/{id}/evt/ota`.
  - `handle_ota_command` — parses `{download, version}`, publishes `started`,
    deletes any existing `update.bin`, queues `DOWNLOAD_TARGET_FIRMWARE`
    download to `/sdcard/update.bin`.
  - `handle_firmware_update` — validates size vs `ota_0` and image magic
    (`0xE9`), publishes `downloaded`, shows e-paper "Update in progress",
    records NVS `UPDATE_REQUESTED`, boots into `factory`, publishes `rebooting`,
    reboots.
  - NVS handshake helpers (`ota` namespace, `state`/`reason` u8s).
  - `ota_handle_boot_state` — marks running app valid
    (`esp_ota_mark_app_valid_cancel_rollback`) when `PENDING_VERIFY`, clears
    stale `REQUESTED`/`IN_PROGRESS` states.
  - `ota_publish_pending_event` — deferred outcome → `evt/ota` on MQTT connect
    (`update_success` / `update_restored` / `failed` + reason), then resets to
    `NONE`.
- Partition / config:
  - `partitions.csv` → `otadata` + `factory`(2 MB) + `ota_0`(5 MB).
  - `partitions_dev.csv` → single 8 MB `factory`, no OTA.
  - `sdkconfig.defaults` → DIO, 8 MB flash, dev partition table by default.
  - `sdkconfig.dev` / `sdkconfig.prod` overlays (prod adds
    `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`).
  - `.gitignore` → ignore `build-dev/`.
- Tooling:
  - `scripts/idf_env.py` — locates ESP-IDF Python env / `idf.py` / esptool.
  - `scripts/build.py` — Dev/Prod profile switch (default Dev).
  - `scripts/flash_all.py` — flashes bootloader, partition table, factory app,
    main app for prod.
- `Readme.md` — IDF env setup, dev/prod build docs, OTA command/event docs.

### esp32_factory_app (`../esp32_factory_app/`) — uncommitted changes
- `main/update.cpp`:
  - `perform_firmware_update` — intent-gated SD→`ota_0` flash with 4 KB
    streaming, size/magic validation, `OTA_STATE_UPDATE_IN_PROGRESS` tracking,
    `esp_ota_end` validation, backup-before-flash, auto-restore on flash
    failure, removes `update.bin` on success/failure.
  - `backup_current_ota0` / `restore_backup` — CRC-verified snapshot to
    `/sdcard/boot_backup.bin` and CRC-checked restore into `ota_0`.
  - `boot_existing_link_app` — boots `ota_0` when no update is pending.
  - NVS helpers (`ota_state_set/get`) mirroring the main app.
- `main/main.cpp`:
  - Update if `UPDATE_REQUESTED` / `UPDATE_IN_PROGRESS`.
  - Crash-back restore when the bootloader reports a reverted `ota_0`.
  - Recover from `UPDATE_FAILED` / invalid `ota_0` via backup, else boot
    existing app. Idles otherwise.
- `sdkconfig.defaults`: test-boot pin GPIO 18 (low = force factory).

---

## Pending work

- Build & flash both binaries end-to-end and validate the happy path
  (Prod build → `flash_all.py` → send `cmd/ota` → watch `evt/ota` →
  app updates and reports `update_success`).
- Validate failure paths on hardware:
  - Corrupt / truncated `update.bin` → `failed` + backup restore.
  - Crash on first boot after update → rollback to backup (`update_restored`).
  - Missing SD card / no intent → factory app idles, `ota_0` untouched.
- Verify deferred outcome events survive a network-down reboot.
- Confirm `esp32_factory_app` README roadmap items are now done / update docs
  to describe intent-gated updates and backup/restore.
- Commit TheLink session changes on `v2` and the `esp32_factory_app` changes.
- Back-port / confirm the GPIO 18 (factory-return) bootloader pin documented in
  `esp32_factory_app` README matches the final production hardware. NOTE:
  `sdkconfig.defaults` currently sets `CONFIG_BOOTLOADER_NUM_PIN_APP_TEST=20`
  (README says GPIO 18) — reconcile the two.

---

## Execution log

### 2026-09-22 — flash_all.py programs otadata to first-boot into ota_0
- Hardware test revealed the first flash did NOT boot into ota_0: the factory
  app booted and logged `esp_ota_ops: not found otadata` while idling.
- Root cause (two compounding bugs):
  1. **Stale generated sdkconfig silently froze the old configuration.**
     ESP-IDF reads an existing `sdkconfig` before `SDKCONFIG_DEFAULTS` and only
     fills missing keys from the defaults. Both TheLink profiles shared the
     root `sdkconfig`, which had the dev/old partition-table settings — so the
     "Prod" build actually produced the *dev* table (no otadata) and a
     bootloader WITHOUT rollback. Confirmed by dumping the build binaries:
     `build/partition_table/partition-table.bin` was `nvs, phy_init, factory`
     (old layout), and the factory app's build used ESP-IDF's *default*
     single-app table (factory 1 MB) because its sdkconfig never configured a
     custom table at all.
  2. Resulting boot sequence matched the symptoms exactly:
     `bs->ota_info.offset == 0` (no otadata in runtime table) → bootloader
     returns FACTORY_INDEX (bootloader_utility.c:348-350); at runtime
     `esp_partition_find_first(DATA, DATA_OTA)` fails → `not found otadata`.
- Fixes:
  - `TheLink/scripts/build.py`: each profile now gets an isolated
    `-DSDKCONFIG=<build_dir>/sdkconfig` and a defaults-signature stamp; when
    the defaults files change, the generated sdkconfig/config files are
    removed so idf.py regenerates from scratch (menuconfig edits survive while
    defaults are unchanged).
  - `esp32_factory_app/scripts/build.py`: same `-DSDKCONFIG` isolation +
    stamp-based regeneration.
  - `esp32_factory_app/sdkconfig.defaults`: added the custom partitions.csv
    table + `CONFIG_ESPTOOLPY_FLASHMODE_DIO`/`FLASHSIZE_8MB` (the OTA table
    needs 8 MB; without it the build failed with "does not fit in configured
    flash size 2MB").
  - `TheLink/scripts/flash_all.py`: `check_partition_table()` parses the Prod
    partition-table binary and aborts unless it contains `otadata@0xe000`,
    `factory@0x10000` (2 MB) and `ota_0@0x210000` (5 MB) — prevents silently
    flashing a stale build dir again.
- ✅ Rebuilt all three; dumped binaries now show the correct OTA table
  (otadata/factory/ota_0) in BOTH TheLink `build` and the factory app, and
  TheLink `build/sdkconfig` has `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` +
  `partitions.csv`. Dev (`build-dev`) still the no-OTA table and is correctly
  rejected by `check_partition_table`.
- ⚠ Pending: re-flash on hardware (now with correct table + programmed
  otadata) and confirm TheLink boots first instead of the factory app.

### 2026-09-22 — otadata design & verification (first flash -> ota_0 planning)
- Question: a first `flash_all.py` flash boots the **factory** app because the
  bootloader defaults blank otadata + existing factory partition to
  `FACTORY_INDEX` (verified: `bootloader_utility_get_selected_boot_partition`,
  bootloader_utility.c:372-378). Can otadata be programmed to boot `ota_0`
  directly? Yes.
- Verified against ESP-IDF 5.4.1 source:
  - otadata layout: two 32-byte `esp_ota_select_entry_t` copies, one per 4 KB
    sector (slot 0 at partition offset 0, slot 1 at 0x1000).
  - struct = `{u32 ota_seq; u8 seq_label[20]; u32 ota_state; u32 crc}` LE.
  - `crc` covers the **4-byte ota_seq field only**:
    `esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4)` = reflected CRC-32, init
    register 0xFFFFFFFF, no final xor -> `zlib.crc32(seq_bytes, 0) ^ 0xFFFFFFFF`.
    Cross-checked against a manual bitwise implementation (both yield
    `0x66074786` for seq=1).
  - State semantics with rollback enabled: `NEW(0)` is flipped to
    `PENDING_VERIFY(1)` and booted (bootloader_utility.c:411-414);
    `VALID(2)` boots directly with no first-boot rollback; pre-programmed
    `PENDING_VERIFY` would be marked `ABORTED` at boot entry (lines 362-368)
    and fall back to factory — not used.
- `scripts/flash_all.py`:
  - Added `make_otadata(ota_seq=1, label, state)` -> 32-byte entry + full
    0x2000 image (slot 0 = entry, rest 0xFF so both sectors erase cleanly)
    and a `validate_otadata()` self-check.
  - New CLI: `--ota {new,valid}` (default `new`), `--no-otadata` (mutually
    exclusive). Writes generated image `%TEMP%/thelink_otadata.bin` at
    `0xe000`; prints the otadata line in the flash table.
  - Docstring updated with the new layout row.
- `esp32_factory_app/README.md` "Boot flow" now documents first-flash otadata
  behavior and the three `flash_all.py` options.
- Verified: `--help` output, byte layout, CRC matches reference implementation,
  slot-1/rest-of-image blank (0xFF).
- Not yet done: hardware proof that the first flash boots TheLink and confirms
  VALID (needs the board + `idf.py monitor`).

### 2026-09-22 — ported `build_env()` to TheLink; Dev+Prod build clean
- Ported the standalone ESP-IDF env bootstrap from
  `esp32_factory_app/scripts/idf_env.py` into `TheLink/scripts/idf_env.py`
  (identical behavior: PATH augmentation for ninja/cmake/git/toolchains, sets
  `IDF_PATH`/`IDF_TOOLS_PATH`/`IDF_PYTHON_ENV_PATH`/`ESP_ROM_ELF_DIR`,
  prefers `C:\Espressif` toolchains over stale `~/.espressif` ones).
- Wired `idf_env.build_env()` into `TheLink/scripts/build.py` (build +
  fullclean) and `TheLink/scripts/flash_all.py` (esptool call).
- ✅ `scripts/build.py -p Dev` — exit 0 (builds `build-dev`, no-OTA layout).
- ✅ `scripts/build.py -p Prod` — exit 0 (builds `build`, OTA layout,
  `--flash_size 8MB`).
- All three artifacts now build without running the ESP-IDF `export.bat`.
- Still open: hardware flash + failure-path validation, deferred-outcome test,
  factory README update, GPIO-18 pin reconciliation, commits.

### 2026-09-22 — factory-app build script + first clean build
- TheLink and esp32_factory_app working trees match the plan's intended state
  (TheLink on `v2`, factory app on `main`, all OTA changes uncommitted).
- Reproduced the build blocker: `scripts/build.py` (TheLink) and bare `idf.py`
  fail with exit 2 — `ninja`/`cmake`/toolchain not on PATH because the ESP-IDF
  export script is never run (`IDF_PYTHON_ENV_PATH` / `IDF_PATH` unset).
- Added `esp32_factory_app/scripts/idf_env.py` (copy of TheLink's) and extended
  it so scripts stand alone without `export.bat`:
  - Locates ESP-IDF via `IDF_TOOLS_PATH` / `~/.espressif` / `C:\Espressif` (in
    that preference order; old `~/.espressif` toolchains no longer shadow the
    newer `C:\Espressif` ones).
  - `build_env()` prepends ninja, cmake, git and the xtensa/riscv toolchain
    `bin` dirs to PATH and sets `IDF_PATH`, `IDF_TOOLS_PATH`,
    `IDF_PYTHON_ENV_PATH` and `ESP_ROM_ELF_DIR` (gdbinit generation needs the
    latter and crashed when it was unset).
- Added `esp32_factory_app/scripts/build.py` — single-profile wrapper around
  `idf.py` mirroring TheLink's script: `-B/-p/--clean`, forwards idf.py
  arguments, and auto-runs `set-target esp32s3` when the build dir is missing
  or a stale `sdkconfig` targets the wrong chip.
- Fixed compile errors in `esp32_factory_app/main/update.cpp` (pre-existing,
  blocking the build): `esp_rom_crc32_le()` takes `const uint8_t *`, but the
  buffers in `copy_partition_to_file()` and `file_crc32()` were `char *`.
  Changed both scratch buffers to `uint8_t *`.
- ✅ `python scripts/build.py` (esp32_factory_app) now builds cleanly (exit 0)
  — full toolchain + app compile + link succeed without running `export.bat`.
- Still open: TheLink Dev/Prod builds (same PATH/full-env issue — its
  `scripts/build.py` doesn't have the `build_env()` bootstrap above) and the
  hardware flash / failure-path validations.

### (older session)
- All code changes described under "Progress (done)" were implemented and are
  sitting uncommitted in both repos at the start of this session.