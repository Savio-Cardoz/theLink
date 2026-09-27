#pragma once

// Derive the device ID from the factory MAC and build every MQTT topic
// string. Call identity_init() once, early in app_main, before any
// topic-dependent code runs.

void identity_init(void);

const char *identity_device_id(void);            // "UUVVWWXXYYZZ"
const char *identity_topic_cmd_log(void);
const char *identity_topic_cmd_display(void);
const char *identity_topic_cmd_rgb(void);
const char *identity_topic_cmd_audio(void);
const char *identity_topic_cmd_notification(void);
const char *identity_topic_cmd_ota(void);
const char *identity_topic_cmd_status(void);
const char *identity_topic_evt_led(void);
const char *identity_topic_evt_ota(void);
const char *identity_topic_evt_status(void);