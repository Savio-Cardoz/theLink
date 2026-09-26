#pragma once

#include "cJSON.h"

// RGB notification LED subsystem: holds the authoritative led_state_t, renders
// it via RgbLedStrip, and keeps MQTT + config.json in sync.

namespace led_ctrl {

// Defaults + MQTT handler/on-connect registration. Call early in app_main
// (before any config load or MQTT connect).
void init(void);

// Spawn the LED rendering task.
void start(void);

// MQTT command handlers (registered on the rgb / notification topics).
void handle_rgb_command(const char *payload);
void handle_notification_command(const char *payload);

// (Re)publish the canonical LED state to evt/led (retained).
void publish_status(void);

// Current animation pattern as its string name (led_state.pattern, mapped via
// pattern_to_string). Note this is NOT led_state.pattern_name, which despite
// its name holds the notification message text. The returned pointer is a
// string literal, so it stays valid after the state lock is released.
const char *pattern_get(void);

// Serialize / restore the LED state for config.json ("led" object).
void status_serialize(cJSON *obj);
void status_apply(cJSON *obj);
void status_apply_legacy_str(const char *str); // "active" / "inactive"

} // namespace led_ctrl