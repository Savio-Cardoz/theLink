#include <cstdio>
#include <cstdlib>
#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "cJSON.h"

#include "i2c_bsp.h"
#include "shtc3_bsp.h"
#include "user_config.h"

#include "app_common.hpp"
#include "identity.hpp"

#include "sensor_ctrl.hpp"

static const char *TAG = "app";

// Five minutes. The sensor is read on boot so a freshly flashed device has a
// value to report right away, then slowly from there.
#define SENSOR_SAMPLE_INTERVAL_MS 300000

// The SHTC3 shares the bus with the audio codec, which is still registering the
// ES8311 at this point in boot. Sweeping and sampling before that finishes
// measures a bus that is still coming up, so both wait it out first.
#define SENSOR_BUS_SETTLE_MS 2000

// A read can lose a single race with the codec's own register writes, so retry
// inside one cycle before giving up on it for the next five minutes.
#define SENSOR_READ_ATTEMPTS 3
#define SENSOR_READ_RETRY_MS 200

// 0x00-0x07 and 0x78-0x7F are reserved blocks: a device answering there is a
// wiring fault, not a device worth reporting.
#define SENSOR_SCAN_FIRST_ADDR 0x08
#define SENSOR_SCAN_LAST_ADDR 0x77
#define SENSOR_SCAN_MAX_FOUND 16

namespace
{

// The last reading that passed its CRC and range check. Guarded because the
// sampling task writes it while MQTT commands read it.
struct sensor_state_t
{
    std::mutex mutex;
    bool valid = false;
    float temperature_c = 0.0f;
    float humidity_pct = 0.0f;
    uint64_t sampled_at_ms = 0;
};

sensor_state_t g_state;

// One line naming every device that answered on the shared bus. This is the
// first thing to read when a unit does not report a temperature: an address
// missing from the list is a hardware problem, an address present but a read
// that still fails is one of ours.
void sensor_scan_bus()
{
    uint8_t found[SENSOR_SCAN_MAX_FOUND] = {0};
    size_t found_count = 0;

    const esp_err_t err = i2c_bsp_scan(ESP32_I2C_DEV_NUM, SENSOR_SCAN_FIRST_ADDR, SENSOR_SCAN_LAST_ADDR,
                                       found, sizeof(found), &found_count);
    if (err == ESP_ERR_INVALID_STATE)
    {
        ESP_LOGW(TAG, "I2C scan skipped, no master bus on port %d", ESP32_I2C_DEV_NUM);
        return;
    }

    char list[sizeof(found) * 5] = {0};
    size_t used = 0;
    for (size_t i = 0; i < found_count; i++)
    {
        used += snprintf(list + used, sizeof(list) - used, "%s0x%02X", (i == 0) ? "" : " ", found[i]);
    }

    if (err == ESP_ERR_TIMEOUT)
    {
        ESP_LOGW(TAG, "I2C scan on SDA %d / SCL %d: bus timed out, SDA held low or pull-ups missing (so far: %s)",
                 ESP32_I2C_SDA_PIN, ESP32_I2C_SCL_PIN, list);
        return;
    }
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "I2C scan on SDA %d / SCL %d failed: %s", ESP32_I2C_SDA_PIN, ESP32_I2C_SCL_PIN,
                 esp_err_to_name(err));
        return;
    }
    if (found_count == 0)
    {
        ESP_LOGW(TAG, "I2C scan on SDA %d / SCL %d: no device answered, check pull-ups and wiring",
                 ESP32_I2C_SDA_PIN, ESP32_I2C_SCL_PIN);
        return;
    }

    ESP_LOGI(TAG, "I2C scan on SDA %d / SCL %d: %s", ESP32_I2C_SDA_PIN, ESP32_I2C_SCL_PIN, list);
}

// Reads the sensor and, on success, refreshes the cache. A read that keeps
// failing is logged and otherwise ignored: the retained evt/sensor message is
// more useful stale than overwritten with nulls, and the next tick tries again.
void sensor_sample()
{
    float temperature_c = 0.0f;
    float humidity_pct = 0.0f;
    esp_err_t err = ESP_FAIL;

    for (int attempt = 1; attempt <= SENSOR_READ_ATTEMPTS; attempt++)
    {
        err = shtc3_read(&temperature_c, &humidity_pct);
        if (err == ESP_OK)
        {
            break;
        }
        if (attempt < SENSOR_READ_ATTEMPTS)
        {
            ESP_LOGW(TAG, "SHTC3 read failed (%s), retrying in %d ms", esp_err_to_name(err), SENSOR_READ_RETRY_MS);
            vTaskDelay(pdMS_TO_TICKS(SENSOR_READ_RETRY_MS));
        }
    }

    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "SHTC3 read failed after %d attempts: %s", SENSOR_READ_ATTEMPTS, esp_err_to_name(err));
        // shtc3_present() logs whether the sensor is still on the bus, which is
        // what separates a dead sensor from a measurement this module could not
        // complete.
        shtc3_present();
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.valid = true;
        g_state.temperature_c = temperature_c;
        g_state.humidity_pct = humidity_pct;
        g_state.sampled_at_ms = (uint64_t)(esp_timer_get_time() / 1000);
    }

    ESP_LOGI(TAG, "SHTC3: %.2f C, %.2f %%RH", temperature_c, humidity_pct);
    sensor_ctrl::publish_status();
}

// Fills `obj` with the cached reading, or nulls when nothing valid has been
// sampled. The caller must not hold g_state.mutex.
void sensor_fill(cJSON *obj)
{
    std::lock_guard<std::mutex> lock(g_state.mutex);

    if (!g_state.valid)
    {
        cJSON_AddNullToObject(obj, "temperature_c");
        cJSON_AddNullToObject(obj, "humidity_pct");
        return;
    }

    const uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);
    cJSON_AddNumberToObject(obj, "temperature_c", g_state.temperature_c);
    cJSON_AddNumberToObject(obj, "humidity_pct", g_state.humidity_pct);
    cJSON_AddNumberToObject(obj, "age_ms", (double)(now_ms - g_state.sampled_at_ms));
}

void sensor_task(void *arg)
{
    (void)arg;

    vTaskDelay(pdMS_TO_TICKS(SENSOR_BUS_SETTLE_MS));

    // Every boot, so a unit that stops reporting can be diagnosed from its log
    // alone rather than by attaching a debugger.
    sensor_scan_bus();

    for (;;)
    {
        sensor_sample();
        vTaskDelay(pdMS_TO_TICKS(SENSOR_SAMPLE_INTERVAL_MS));
    }
}

} // namespace

void sensor_ctrl::init()
{
    // Re-publish on every (re)connect so a dashboard that connects late, or
    // reconnects after a broker restart, gets the current reading.
    app::register_on_connect([]()
                              { sensor_ctrl::publish_status(); });
}

void sensor_ctrl::start()
{
    if (i2c_bsp_init(ESP32_I2C_DEV_NUM, ESP32_I2C_SDA_PIN, ESP32_I2C_SCL_PIN) != ESP_OK)
    {
        ESP_LOGE(TAG, "SHTC3: I2C bus setup failed, temperature/humidity disabled");
        return;
    }

    if (shtc3_init(i2c_bsp_bus(ESP32_I2C_DEV_NUM), I2C_SHTC3_DEV_Address) != ESP_OK)
    {
        ESP_LOGE(TAG, "SHTC3: cannot attach to I2C, temperature/humidity disabled");
        return;
    }

    // Presence is not checked here: the bus is milliseconds old and the audio
    // codec is about to start driving it. The sampling task sweeps the whole bus
    // once the rail has settled, which covers 0x70 anyway.
    xTaskCreate(sensor_task, "sensor", 4096, NULL, 3, NULL);
}

void sensor_ctrl::publish_status()
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr)
    {
        ESP_LOGE(TAG, "SHTC3: out of memory building evt/sensor");
        return;
    }

    sensor_fill(root);

    char *payload = cJSON_PrintUnformatted(root);
    if (payload != nullptr)
    {
        // Retained, so a subscriber that shows up later still gets the last
        // sample instead of waiting up to five minutes for the next one.
        app::mqtt_publish(identity_topic_evt_sensor(), payload, 1, 1);
        free(payload);
    }

    cJSON_Delete(root);
}

void sensor_ctrl::status_serialize(cJSON *root)
{
    cJSON *sensor = cJSON_CreateObject();
    if (sensor == nullptr)
    {
        ESP_LOGE(TAG, "SHTC3: out of memory building status");
        return;
    }

    sensor_fill(sensor);
    cJSON_AddItemToObject(root, "sensor", sensor);
}
