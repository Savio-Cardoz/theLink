/*
 * SPDX-FileCopyrightText: 2026
 * SPDX-License-Identifier: Apache-2.0
 */
#include "mqtt_auth.h"

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

#include "esp_log.h"
#include "mbedtls/md.h"

static const char *TAG = "MQTT_AUTH";

#define HMAC_PROP_KEY "hmac"
#define TS_PROP_KEY   "ts"
#define HMAC_BYTES    32
#define HMAC_HEX_LEN  (HMAC_BYTES * 2)

/* Baseline: 2020-01-01. time() returning less than this means the system
 * clock was never synchronised (no SNTP), so a "ts" cannot be checked. */
#define CLOCK_MIN_EPOCH 1577836800LL

#ifndef CONFIG_MQTT_HMAC_KEY
#define CONFIG_MQTT_HMAC_KEY ""
#endif

#ifndef CONFIG_MQTT_HMAC_REPLAY_WINDOW_S
#define CONFIG_MQTT_HMAC_REPLAY_WINDOW_S 0
#endif

mqtt_auth_mode_t mqtt_auth_get_mode(void)
{
#if defined(CONFIG_MQTT_HMAC_MODE_REQUIRED)
    return MQTT_AUTH_MODE_REQUIRED;
#elif defined(CONFIG_MQTT_HMAC_MODE_OPTIONAL)
    return MQTT_AUTH_MODE_OPTIONAL;
#else
    return MQTT_AUTH_MODE_DISABLED;
#endif
}

bool mqtt_auth_enabled(void)
{
    return mqtt_auth_get_mode() != MQTT_AUTH_MODE_DISABLED;
}

const char *mqtt_auth_result_str(mqtt_auth_result_t result)
{
    switch (result) {
        case MQTT_AUTH_PASS:     return "ok";
        case MQTT_AUTH_MISSING:  return "missing hmac tag";
        case MQTT_AUTH_INVALID:  return "invalid hmac tag";
        case MQTT_AUTH_STALE:    return "stale/missing ts";
        case MQTT_AUTH_NO_KEY:   return "no hmac key configured";
        default:                 return "unknown";
    }
}

/* Constant-time byte comparison (lengths are equal by construction). */
static bool ct_eq(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode exactly outlen bytes (2*outlen hex chars) into out. */
static bool hex_decode_n(const char *hex, unsigned char *out, size_t outlen)
{
    if (hex == nullptr || strlen(hex) != outlen * 2) {
        return false;
    }
    for (size_t i = 0; i < outlen; ++i) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

#ifndef CONFIG_MQTT_PROTOCOL_5
/* Without MQTT 5 there are no user properties to read: verification is
 * impossible, so every message fails closed. */
static char *get_user_property_value(esp_mqtt_event_handle_t, const char *)
{
    return nullptr;
}
#else
/* Return a heap copy of the value of user property "key", or nullptr.
 * The MQTT5 library owns the event's list; only the copies are ours. */
static char *get_user_property_value(esp_mqtt_event_handle_t event, const char *key)
{
    if (event == nullptr || event->property == nullptr ||
        event->property->user_property == nullptr) {
        return nullptr;
    }

    uint8_t count = esp_mqtt5_client_get_user_property_count(event->property->user_property);
    if (count == 0) {
        return nullptr;
    }

    auto *items = (esp_mqtt5_user_property_item_t *)calloc(count, sizeof(esp_mqtt5_user_property_item_t));
    if (items == nullptr) {
        return nullptr;
    }

    uint8_t n = count;
    if (esp_mqtt5_client_get_user_property(event->property->user_property, items, &n) != ESP_OK) {
        free(items);
        return nullptr;
    }

    char *out = nullptr;
    for (uint8_t i = 0; i < n; ++i) {
        if (items[i].key != nullptr && items[i].value != nullptr &&
            strcmp(items[i].key, key) == 0) {
            out = strdup(items[i].value);
            break;
        }
    }

    for (uint8_t i = 0; i < n; ++i) {
        free((void *)items[i].key);
        free((void *)items[i].value);
    }
    free(items);
    return out;
}
#endif

mqtt_auth_result_t mqtt_auth_verify(esp_mqtt_event_handle_t event)
{
    if (event == nullptr || event->topic == nullptr || event->data == nullptr ||
        event->topic_len <= 0 || event->data_len < 0) {
        return MQTT_AUTH_INVALID;
    }

    const char *key = CONFIG_MQTT_HMAC_KEY;
    if (key[0] == '\0') {
        ESP_LOGE(TAG, "verification enabled but CONFIG_MQTT_HMAC_KEY is empty");
        return MQTT_AUTH_NO_KEY;
    }

    char *hmac_hex = get_user_property_value(event, HMAC_PROP_KEY);
    if (hmac_hex == nullptr) {
        return MQTT_AUTH_MISSING;
    }

    /* Canonical input: topic + 0x00 + payload (lengths are explicit, so the
     * payload needs no trailing NUL on the wire). */
    size_t tlen = (size_t)event->topic_len;
    size_t dlen = (size_t)event->data_len;
    std::vector<unsigned char> input(tlen + 1 + dlen);
    memcpy(input.data(), event->topic, tlen);
    input[tlen] = '\0';
    memcpy(input.data() + tlen + 1, event->data, dlen);

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr) {
        free(hmac_hex);
        return MQTT_AUTH_INVALID;
    }

    unsigned char expected[HMAC_BYTES];
    int rc = mbedtls_md_hmac(info,
                             (const unsigned char *)key, strlen(key),
                             input.data(), input.size(),
                             expected);
    if (rc != 0) {
        free(hmac_hex);
        return MQTT_AUTH_INVALID;
    }

    unsigned char received[HMAC_BYTES];
    bool well_formed = hex_decode_n(hmac_hex, received, sizeof(received));
    free(hmac_hex);
    if (!well_formed) {
        return MQTT_AUTH_INVALID;
    }

    if (!ct_eq(expected, received, sizeof(expected))) {
        ESP_LOGW(TAG, "HMAC mismatch on topic %.*s", (int)tlen, event->topic);
        return MQTT_AUTH_INVALID;
    }

    /* Optional replay protection: "ts" must be present and close enough to
     * the device clock (SNTP-synchronised) when a window is configured. */
    if (CONFIG_MQTT_HMAC_REPLAY_WINDOW_S > 0) {
        char *ts_str = get_user_property_value(event, TS_PROP_KEY);
        if (ts_str == nullptr) {
            return MQTT_AUTH_STALE;
        }
        char *end = nullptr;
        long long ts = strtoll(ts_str, &end, 10);
        bool numeric = (end != ts_str && end != nullptr && *end == '\0');
        free(ts_str);
        if (!numeric || ts <= 0) {
            return MQTT_AUTH_STALE;
        }

        long long now = (long long)time(NULL);
        if (now < CLOCK_MIN_EPOCH) {
            ESP_LOGW(TAG, "system clock not set; cannot check ts");
            return MQTT_AUTH_STALE;
        }
        long long diff = (now > ts) ? (now - ts) : (ts - now);
        if (diff > (long long)CONFIG_MQTT_HMAC_REPLAY_WINDOW_S) {
            ESP_LOGW(TAG, "ts outside replay window (diff=%llds)", diff);
            return MQTT_AUTH_STALE;
        }
    }

    return MQTT_AUTH_PASS;
}
