#pragma once

#include <string>

// Firmware update (OTA) subsystem: validates a downloaded update.bin on the
// SD card, shows the update screen, and hands the intent to the factory
// (bootloader) app via the shared NVS handshake. The factory app is the only
// entity allowed to flash.

namespace ota_ctrl {

// Registration: cmd/ota topic, FIRMWARE download target and connect-time
// publish of any pending OTA outcome. Call early in app_main.
void init(void);

// Boot-time handling of the OTA handshake (mark app VALID after an update,
// clear stale intents). Call right after NVS init.
void init_boot_state(void);

// MQTT command handler (registered on the ota topic).
void handle_command(const char *payload);

// Download completion handler (registered for DownloadTarget::FIRMWARE).
void firmware_downloaded(bool success, const std::string &filepath);

} // namespace ota_ctrl