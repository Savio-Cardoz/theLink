#pragma once

#include <cstdint>

// Provisioning state of the notification LED. The LED task pulses at a
// different interval per phase; control returns to MQTT once the app is up.
typedef enum {
    LED_PROV_STATE_NONE = 0,
    LED_PROV_STATE_PROVISIONING,   // Provisioning service active      -> 0.5s pulse
    LED_PROV_STATE_BLE_CONNECTED,  // Provisioning BLE transport linked -> 1.5s pulse
    LED_PROV_STATE_WIFI_CONNECTED, // Wi-Fi station got an IP           -> 3s pulse
} led_prov_state_t;

// Hue used for all provisioning pulses (blue).
constexpr uint32_t PROV_PULSE_HUE = 240;

// Create the Wi-Fi event group and register the network/provisioning event
// handlers. Call once the default event loop exists and before Wi-Fi is
// initialized.
void provisioning_register_core_events(void);

// Spawn the provisioning task. Call only after the UI is initialized and its
// widgets are locked in, because the task can push a QR overlay.
void provisioning_start(void);

// Provisioning LED state exposed to the LED task (read) and to mqtt_io on
// connect (clear via app::register_on_connect).
void prov_set_led_state(led_prov_state_t state);
led_prov_state_t prov_get_led_state(void);

uint32_t prov_pulse_period_ms(led_prov_state_t state);