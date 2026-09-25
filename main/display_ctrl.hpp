#pragma once

#include <string>

// E-paper display subsystem: renders an unpacked 200x200 I8 image from the SD
// card on the LVGL canvas. Owns the display task; download completions and
// MQTT commands arrive through this module and drive state.

namespace display_ctrl {

// MQTT handler / download-target registration. Call early in app_main.
void init(void);

// Spawn the display update task.
void start(void);

// MQTT command handler (registered on the display topic).
void handle_command(const char *payload);

// Download completion handler (registered for DownloadTarget::DISPLAY).
void notify_downloaded(bool success, const std::string &filepath);

// Boot kick: prime the task once if a display path was restored from config.
void boot_kick_if_active(void);

// Config.json integration.
std::string data_path_get(void);
void data_path_set(const std::string &path);

} // namespace display_ctrl