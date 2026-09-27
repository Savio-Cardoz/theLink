#pragma once

#include <string>

// Audio playback subsystem: streams PCM from the SD card (or the embedded
// boot sound) through the I2S codec. Owns the audio task; commands and
// download completions arrive through this module.

namespace audio_ctrl {

// MQTT handler / download-target registration. Call early in app_main.
void init(void);

// Spawn the audio playback task.
void start(void);

// MQTT command handler (registered on the audio topic).
void handle_command(const char *payload);

// Download completion handler (registered for DownloadTarget::AUDIO).
void notify_downloaded(bool success, const std::string &filepath);

} // namespace audio_ctrl