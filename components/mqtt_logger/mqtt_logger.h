/*
 * SPDX-FileCopyrightText: 2026
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdarg>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Log level for MQTT transport.
 *        Matches esp_log_level_t values so they can be used interchangeably.
 */
typedef enum {
    MQTT_LOG_NONE  = 0,
    MQTT_LOG_ERROR = 1,
    MQTT_LOG_WARN  = 2,
    MQTT_LOG_INFO  = 3,
    MQTT_LOG_DEBUG = 4,
    MQTT_LOG_VERBOSE = 5,
} mqtt_log_level_t;

/**
 * @brief Initialize the MQTT logger.
 *
 * Call once after the MQTT client is connected. Installs an esp_log hook
 * that forwards log messages matching the current filter level to a FreeRTOS
 * queue. A dedicated background task publishes queued logs over MQTT.
 *
 * @param client          Handle to a running esp_mqtt_client.
 * @param device_id       Device identifier embedded in topic paths.
 * @param initial_level   Initial log level filter (MQTT_LOG_INFO recommended).
 * @param queue_depth     Max queued messages before oldest are dropped (0 = 32).
 * @return                ESP_OK on success.
 */
esp_err_t mqtt_logger_init(esp_mqtt_client_handle_t client,
                           const char *device_id,
                           mqtt_log_level_t initial_level,
                           uint16_t queue_depth);

/**
 * @brief Shut down the MQTT logger and remove the esp_log hook.
 */
void mqtt_logger_deinit(void);

/**
 * @brief Set the active log level filter.
 *
 * Only messages at this level or below are queued for MQTT publication.
 * Serial output is unaffected.
 */
void mqtt_logger_set_level(mqtt_log_level_t level);

/**
 * @brief Get the current log level filter.
 */
mqtt_log_level_t mqtt_logger_get_level(void);

/**
 * @brief Publish a log message directly (bypasses the queue).
 *
 * Useful for critical messages that must not be dropped.
 */
void mqtt_logger_publish_direct(mqtt_log_level_t level,
                                const char *tag,
                                const char *fmt, ...);

/**
 * @brief Handle an incoming MQTT command to control the logger.
 *
 * Expected JSON payloads:
 *   { "action": "set_level", "level": "debug" }
 *   { "action": "get_level" }
 *
 * @param payload  Raw JSON payload string (null-terminated).
 */
void mqtt_logger_handle_command(const char *payload);

#ifdef __cplusplus
}
#endif
