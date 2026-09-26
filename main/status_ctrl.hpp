#pragma once

// Device status query: answers cmd/status with a snapshot of the state spread
// across the LED, display and firmware subsystems. Owns no state of its own —
// it only reads the accessors the owning modules expose.

namespace status_ctrl {

// MQTT handler registration. Call early in app_main, before MQTT connects.
void init(void);

// MQTT command handler (registered on the status topic).
void handle_status_command(const char *payload);

} // namespace status_ctrl
