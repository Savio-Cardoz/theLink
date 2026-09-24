/*
 * SPDX-FileCopyrightText: 2026
 * SPDX-License-Identifier: Apache-2.0
 *
 * Config-guarded authenticity check for incoming MQTT commands.
 *
 * A publisher authenticates a command by attaching two MQTT 5 user
 * properties to the PUBLISH packet:
 *
 *   hmac : hex(HMAC-SHA256(key, topic + '\0' + payload))
 *   ts   : unix time in seconds (only checked when a replay window is set)
 *
 * The verification itself is optional: mqtt_auth_get_mode() reports how the
 * firmware was built (CONFIG_MQTT_HMAC_MODE_*), so tools that cannot compute
 * an HMAC (e.g. MQTTX with a plain JSON payload) keep working when the mode
 * is MQTT_AUTH_MODE_DISABLED.
 */
#pragma once

#include <cstdint>

#include "esp_err.h"
#include "mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verification policy baked into the build (Kconfig MQTT_HMAC_MODE).
 */
typedef enum {
    MQTT_AUTH_MODE_DISABLED = 0,  //!< No verification, everything is accepted.
    MQTT_AUTH_MODE_OPTIONAL = 1,  //!< Unsigned accepted, invalid tags dropped.
    MQTT_AUTH_MODE_REQUIRED = 2,  //!< Only valid tags are accepted.
} mqtt_auth_mode_t;

/**
 * @brief Outcome of verifying a single received message.
 */
typedef enum {
    MQTT_AUTH_PASS = 0,     //!< Valid HMAC tag (and ts inside the window).
    MQTT_AUTH_MISSING = 1,  //!< No "hmac" user property present.
    MQTT_AUTH_INVALID = 2,  //!< Malformed or non-matching HMAC tag.
    MQTT_AUTH_STALE = 3,    //!< "ts" missing or outside the replay window.
    MQTT_AUTH_NO_KEY = 4,   //!< Verification enabled but no key configured.
} mqtt_auth_result_t;

/**
 * @brief The verification mode compiled into this firmware.
 */
mqtt_auth_mode_t mqtt_auth_get_mode(void);

/**
 * @brief True when any verification is compiled in (mode != DISABLED).
 */
bool mqtt_auth_enabled(void);

/**
 * @brief Human-readable name of a verification result (for logging).
 */
const char *mqtt_auth_result_str(mqtt_auth_result_t result);

/**
 * @brief Verify the HMAC user property of a received MQTT message.
 *
 * Reads the MQTT 5 user properties of @p event and checks the "hmac"
 * property against HMAC-SHA256(CONFIG_MQTT_HMAC_KEY, topic + '\0' + payload).
 * When CONFIG_MQTT_HMAC_REPLAY_WINDOW_S > 0 the "ts" user property must also
 * be present and within the window of the device clock (the device clock is
 * kept in sync via SNTP).
 *
 * @param event  Event whose topic/payload/user properties are inspected.
 *               Only valid for the duration of the MQTT event callback.
 * @return MQTT_AUTH_PASS only when the message is authentic.
 */
mqtt_auth_result_t mqtt_auth_verify(esp_mqtt_event_handle_t event);

#ifdef __cplusplus
}
#endif
