#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "mqtt_client.h"
#include "i_filesystem.hpp"

namespace app {

// Number of pixels on the RGB LED ring.
constexpr size_t LED_COUNT = 16;

// Routing target for the shared download queue.
enum class DownloadTarget {
    DISPLAY,
    AUDIO,
    FIRMWARE,
};

// Infrastructure handles (owned by app_main / mqtt_io). All dirty details of
// where a subsystem gets its resources live here so modules never reach into
// each other's globals.
IFileSystem *sdcard();
void set_sdcard(IFileSystem *fs);

esp_mqtt_client_handle_t mqtt();
void set_mqtt(esp_mqtt_client_handle_t client);

// Publish a payload on the connected client (no-op until connected).
bool mqtt_publish(const char *topic, const char *payload, int qos, int retain);

// Actions to run once MQTT connects. Subsystems self-register their
// connect-time work (state re-publish, deferred OTA outcome, provisioning LED
// hand-off) so the MQTT layer stays generic.
using ConnectCallback = std::function<void()>;
void register_on_connect(ConnectCallback cb);
void fire_on_connect();

} // namespace app