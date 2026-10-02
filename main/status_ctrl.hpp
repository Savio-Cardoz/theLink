#pragma once

// Device status query: answers cmd/status with a snapshot of the state spread
// across the LED, display and firmware subsystems. Owns no state of its own —
// it only reads the accessors the owning modules expose.

namespace status_ctrl {

// MQTT handler registration. Call early in app_main, before MQTT connects.
void init(void);

// MQTT command handler (registered on the status topic).
void handle_status_command(const char *payload);

// Publish a full status snapshot. This is the only writer to evt/status:
// cmd/status calls it, and so does anything that changed a value the reply
// carries (a completed time sync, a reconnect), so subscribers are not left
// holding a snapshot taken before that change.
void publish(void);

} // namespace status_ctrl
