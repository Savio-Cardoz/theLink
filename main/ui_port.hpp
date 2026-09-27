#pragma once

// LVGL port for the e-paper display: mutex guard, flush callback, tick timer,
// the render loop task and the Wi-Fi icon overlay queue. Owns the LVGL
// mutex and the overlay event queue; everything else runs on the display
// subsystem or the provisioning module.

void ui_port_init(void);                 // lv_init, display, buffers, tick, mux, overlay queue

// Create the Wi-Fi status icon overlay. Call while holding the LVGL lock
// (ui_lock), after the screen has been set up.
void ui_create_wifi_icon(void);

bool ui_lock(int timeout_ms);            // true if acquired
void ui_unlock(void);

// Post a Wi-Fi status change to the overlay task (non-blocking).
void ui_notify_network_status(bool connected);

// Show a centred text label and force a refresh (e.g. firmware update).
void ui_show_update_screen(void);

// Task entry points (create with xTaskCreate/xTaskCreatePinnedToCore).
void example_lvgl_port_task(void *arg);
void ui_overlay_task(void *arg);