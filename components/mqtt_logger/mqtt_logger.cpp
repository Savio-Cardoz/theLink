/*
 * SPDX-FileCopyrightText: 2026
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mqtt_logger.h"

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>

#include "esp_log.h"
#include "cJSON.h"

static const char *TAG = "MQTT_LOG";

// ── Internal constants ───────────────────────────────────────────────
static constexpr size_t MAX_LOG_MSG_LEN   = 256;
static constexpr size_t MAX_TAG_LEN       = 32;
static constexpr size_t MAX_JSON_LOG_LEN  = 512;
static constexpr uint16_t DEFAULT_QUEUE_DEPTH = 32;

// ── Internal state ───────────────────────────────────────────────────
static esp_mqtt_client_handle_t s_client       = nullptr;
static QueueHandle_t           s_log_queue     = nullptr;
static TaskHandle_t            s_publish_task  = nullptr;
static mqtt_log_level_t        s_filter_level  = MQTT_LOG_INFO;
static char                    s_device_id[32] = {0};
static bool                    s_initialised   = false;

// Original vprintf function pointer (set by esp_log_set_vprintf).
static int (*s_orig_vprintf)(const char *fmt, va_list args) = nullptr;

// ── Queued log entry ─────────────────────────────────────────────────
struct log_entry_t {
    mqtt_log_level_t level;
    char tag[MAX_TAG_LEN];
    char message[MAX_LOG_MSG_LEN];
};

// ── Helpers ──────────────────────────────────────────────────────────

static mqtt_log_level_t level_char_to_enum(char c)
{
    switch (c) {
        case 'E': return MQTT_LOG_ERROR;
        case 'W': return MQTT_LOG_WARN;
        case 'I': return MQTT_LOG_INFO;
        case 'D': return MQTT_LOG_DEBUG;
        case 'V': return MQTT_LOG_VERBOSE;
        default:  return MQTT_LOG_INFO;
    }
}

static const char *level_to_string(mqtt_log_level_t level)
{
    switch (level) {
        case MQTT_LOG_ERROR:   return "error";
        case MQTT_LOG_WARN:    return "warn";
        case MQTT_LOG_INFO:    return "info";
        case MQTT_LOG_DEBUG:   return "debug";
        case MQTT_LOG_VERBOSE: return "verbose";
        default:               return "unknown";
    }
}

static mqtt_log_level_t string_to_level(const char *str)
{
    if (strcmp(str, "error")   == 0) return MQTT_LOG_ERROR;
    if (strcmp(str, "warn")    == 0) return MQTT_LOG_WARN;
    if (strcmp(str, "info")    == 0) return MQTT_LOG_INFO;
    if (strcmp(str, "debug")   == 0) return MQTT_LOG_DEBUG;
    if (strcmp(str, "verbose") == 0) return MQTT_LOG_VERBOSE;
    if (strcmp(str, "none")    == 0) return MQTT_LOG_NONE;
    return MQTT_LOG_INFO; // fallback
}

/**
 * @brief Strip ANSI escape sequences (e.g. "\033[0;31m") from the start
 *        of a formatted log string.
 *
 * ESP-IDF prepends color codes when CONFIG_LOG_COLORS is enabled.
 * Returns a pointer past any leading escape sequences.
 */
static const char *strip_ansi(const char *str)
{
    while (*str == '\033') {
        // ESC [ <params> m
        const char *m = strchr(str, 'm');
        if (m) {
            str = m + 1;
        } else {
            break;
        }
    }
    return str;
}

/**
 * @brief Parse an ESP-IDF formatted log line into level, tag, and message.
 *
 * Expected formats (after stripping ANSI):
 *   "I (12345) tag: message"
 *   "E (12345) tag: message"
 *
 * @return true if parsing succeeded.
 */
static bool parse_log_line(const char *raw,
                           mqtt_log_level_t &out_level,
                           char *out_tag, size_t tag_len,
                           char *out_msg, size_t msg_len)
{
    const char *s = strip_ansi(raw);

    // Level is the first character.
    if (s[0] == '\0' || (s[1] != ' ' && s[1] != '(')) {
        return false;
    }
    out_level = level_char_to_enum(s[0]);

    // Skip "X " to find "(timestamp) tag: message".
    const char *paren = strchr(s, '(');
    if (!paren) {
        return false;
    }

    // Find ") " which marks end of timestamp.
    const char *close_paren = strstr(paren, ") ");
    if (!close_paren) {
        return false;
    }

    const char *tag_start = close_paren + 2;

    // Tag ends at ": ".
    const char *colon = strstr(tag_start, ": ");
    if (!colon) {
        // No tag found — treat everything as the message.
        out_tag[0] = '\0';
        snprintf(out_msg, msg_len, "%s", tag_start);
        return true;
    }

    size_t tag_size = static_cast<size_t>(colon - tag_start);
    if (tag_size >= tag_len) {
        tag_size = tag_len - 1;
    }
    memcpy(out_tag, tag_start, tag_size);
    out_tag[tag_size] = '\0';

    const char *msg_start = colon + 2;
    snprintf(out_msg, msg_len, "%s", msg_start);

    return true;
}

/**
 * @brief Build a JSON log string for MQTT publication.
 *
 * Output format: {"device_id":"...","level":"...","tag":"...","msg":"..."}
 * Returns the number of bytes written (excluding null terminator), or 0 on error.
 */
static size_t build_log_json(char *buf, size_t buf_len,
                             mqtt_log_level_t level,
                             const char *tag,
                             const char *message)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return 0;
    }

    cJSON_AddStringToObject(root, "device_id", s_device_id);
    cJSON_AddStringToObject(root, "level", level_to_string(level));
    cJSON_AddStringToObject(root, "tag", tag);
    cJSON_AddStringToObject(root, "msg", message);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json) {
        return 0;
    }

    size_t len = strlen(json);
    if (len >= buf_len) {
        free(json);
        return 0;
    }

    memcpy(buf, json, len + 1);
    free(json);
    return len;
}

// ── Publish task ─────────────────────────────────────────────────────

static void mqtt_log_publish_task(void *arg)
{
    log_entry_t entry;

    for (;;) {
        if (xQueueReceive(s_log_queue, &entry, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        if (!s_client) {
            continue;
        }

        char json_buf[MAX_JSON_LOG_LEN];
        size_t json_len = build_log_json(json_buf, sizeof(json_buf),
                                         entry.level, entry.tag, entry.message);
        if (json_len == 0) {
            continue;
        }

        // Topic: thelink/{device_id}/evt/log
        char topic[64];
        snprintf(topic, sizeof(topic), "thelink/%s/evt/log", s_device_id);

        esp_mqtt_client_publish(s_client, topic, json_buf,
                                static_cast<int>(json_len), 0, 0);
    }
}

// ── esp_log hook ─────────────────────────────────────────────────────

/**
 * @brief Custom vprintf replacement installed via esp_log_set_vprintf.
 *
 * Intercepts formatted log output, parses level/tag/message, and queues
 * qualifying messages for MQTT publication. Serial output is preserved
 * by forwarding to the original vprintf.
 */
static int mqtt_log_vprintf(const char *fmt, va_list args)
{
    // Use va_copy because vs消耗 the va_list — we need two independent copies.
    va_list args_copy;
    va_copy(args_copy, args);

    // Always forward to serial output first.
    int ret = 0;
    if (s_orig_vprintf) {
        ret = s_orig_vprintf(fmt, args);
    }

    // Parse the formatted string using the copy.
    char formatted[MAX_LOG_MSG_LEN];
    vsnprintf(formatted, sizeof(formatted), fmt, args_copy);
    va_end(args_copy);

    mqtt_log_level_t level;
    char tag[MAX_TAG_LEN];
    char message[MAX_LOG_MSG_LEN];

    if (!parse_log_line(formatted, level, tag, sizeof(tag),
                        message, sizeof(message))) {
        return ret;
    }

    // Apply filter.
    if (level > s_filter_level || level == MQTT_LOG_NONE) {
        return ret;
    }

    // Queue for MQTT publication (non-blocking — drop if full).
    if (s_log_queue) {
        log_entry_t entry;
        entry.level = level;
        strncpy(entry.tag, tag, sizeof(entry.tag) - 1);
        entry.tag[sizeof(entry.tag) - 1] = '\0';
        strncpy(entry.message, message, sizeof(entry.message) - 1);
        entry.message[sizeof(entry.message) - 1] = '\0';

        if (xQueueSend(s_log_queue, &entry, 0) != pdTRUE) {
            // Queue full — drop silently. Could add a drop counter here.
        }
    }

    return ret;
}

// ── Public API ───────────────────────────────────────────────────────

esp_err_t mqtt_logger_init(esp_mqtt_client_handle_t client,
                           const char *device_id,
                           mqtt_log_level_t initial_level,
                           uint16_t queue_depth)
{
    if (s_initialised) {
        ESP_LOGW(TAG, "Already initialised");
        return ESP_ERR_INVALID_STATE;
    }

    if (!client || !device_id) {
        return ESP_ERR_INVALID_ARG;
    }

    s_client = client;
    strncpy(s_device_id, device_id, sizeof(s_device_id) - 1);
    s_device_id[sizeof(s_device_id) - 1] = '\0';
    s_filter_level = initial_level;

    uint16_t depth = (queue_depth > 0) ? queue_depth : DEFAULT_QUEUE_DEPTH;
    s_log_queue = xQueueCreate(depth, sizeof(log_entry_t));
    if (!s_log_queue) {
        ESP_LOGE(TAG, "Failed to create log queue");
        return ESP_ERR_NO_MEM;
    }

    // Install the esp_log hook.  Save the original vprintf so serial
    // output is preserved.
    s_orig_vprintf = esp_log_set_vprintf(mqtt_log_vprintf);

    // Spawn the publish task at a modest priority.
    BaseType_t ret = xTaskCreate(mqtt_log_publish_task, "mqtt_log", 4096,
                                 nullptr, 3, &s_publish_task);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create publish task");
        esp_log_set_vprintf(s_orig_vprintf);
        vQueueDelete(s_log_queue);
        s_log_queue = nullptr;
        return ESP_FAIL;
    }

    s_initialised = true;
    ESP_LOGI(TAG, "MQTT logger initialised (level=%s, queue=%d)",
             level_to_string(s_filter_level), depth);
    return ESP_OK;
}

void mqtt_logger_deinit(void)
{
    if (!s_initialised) {
        return;
    }

    // Remove the hook and restore original vprintf.
    esp_log_set_vprintf(s_orig_vprintf);
    s_orig_vprintf = nullptr;

    // Stop the publish task.
    if (s_publish_task) {
        vTaskDelete(s_publish_task);
        s_publish_task = nullptr;
    }

    // Drain and destroy the queue.
    if (s_log_queue) {
        vQueueDelete(s_log_queue);
        s_log_queue = nullptr;
    }

    s_client = nullptr;
    s_initialised = false;
}

void mqtt_logger_set_level(mqtt_log_level_t level)
{
    s_filter_level = level;
    ESP_LOGI(TAG, "MQTT log level set to %s", level_to_string(level));
}

mqtt_log_level_t mqtt_logger_get_level(void)
{
    return s_filter_level;
}

void mqtt_logger_publish_direct(mqtt_log_level_t level,
                                const char *tag,
                                const char *fmt, ...)
{
    if (!s_client || level > s_filter_level || level == MQTT_LOG_NONE) {
        return;
    }

    char message[MAX_LOG_MSG_LEN];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    char json_buf[MAX_JSON_LOG_LEN];
    size_t json_len = build_log_json(json_buf, sizeof(json_buf),
                                     level, tag ? tag : "", message);
    if (json_len == 0) {
        return;
    }

    char topic[64];
    snprintf(topic, sizeof(topic), "thelink/%s/evt/log", s_device_id);

    esp_mqtt_client_publish(s_client, topic, json_buf,
                            static_cast<int>(json_len), 0, 0);
}

void mqtt_logger_handle_command(const char *payload)
{
    if (!payload) {
        return;
    }

    cJSON *json = cJSON_Parse(payload);
    if (!json) {
        ESP_LOGW(TAG, "Invalid JSON in log command");
        return;
    }

    cJSON *action = cJSON_GetObjectItemCaseSensitive(json, "action");
    if (!cJSON_IsString(action)) {
        cJSON_Delete(json);
        return;
    }

    if (strcmp(action->valuestring, "set_level") == 0) {
        cJSON *level_json = cJSON_GetObjectItemCaseSensitive(json, "level");
        if (cJSON_IsString(level_json)) {
            mqtt_log_level_t new_level = string_to_level(level_json->valuestring);
            mqtt_logger_set_level(new_level);
        }
    } else if (strcmp(action->valuestring, "get_level") == 0) {
        // Publish current level as a status message.
        mqtt_logger_publish_direct(MQTT_LOG_INFO, TAG,
                                   "Current log level: %s",
                                   level_to_string(s_filter_level));
    }

    cJSON_Delete(json);
}
