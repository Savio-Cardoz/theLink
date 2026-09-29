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

// Reads the sensor and, on success, refreshes the cache. A failed read is
// logged and otherwise ignored: the retained evt/sensor message is more useful
// stale than overwritten with nulls, and the next tick tries again.
void sensor_sample()
{
    float temperature_c = 0.0f;
    float humidity_pct = 0.0f;
    const esp_err_t err = shtc3_read(&temperature_c, &humidity_pct);

    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "SHTC3 read failed: %s", esp_err_to_name(err));
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

    // Informational only. The rail may still be settling this early, so the
    // sampling task keeps retrying rather than disabling the sensor outright.
    if (!shtc3_present())
    {
        ESP_LOGW(TAG, "SHTC3: nothing at 0x%02X yet, will keep retrying", I2C_SHTC3_DEV_Address);
    }

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
