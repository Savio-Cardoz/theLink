#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "shtc3_bsp.h"

static const char *TAG = "SHTC3";

// Two 16-bit words, each followed by a CRC-8 byte.
#define SHTC3_RAW_LEN 6
#define SHTC3_XFER_TIMEOUT_MS 100

// Datasheet section 6.2 range; anything outside means the transfer was not a
// real measurement.
#define SHTC3_TEMP_MIN_C (-40.0f)
#define SHTC3_TEMP_MAX_C (125.0f)
#define SHTC3_RH_MIN_PCT (0.0f)
#define SHTC3_RH_MAX_PCT (100.0f)

static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev;

// CRC-8, polynomial 0x31, initial value 0xFF (Dallas/Maxim), as used by every
// Sensirion sensor.
static uint8_t shtc3_crc8(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++)
        {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
        }
    }
    return crc;
}

esp_err_t shtc3_init(i2c_master_bus_handle_t bus, uint8_t dev_addr)
{
    if (bus == NULL)
    {
        ESP_LOGE(TAG, "I2C bus handle is NULL");
        return ESP_ERR_INVALID_ARG;
    }

    if (s_dev != NULL)
    {
        return ESP_OK;
    }

    i2c_device_config_t dev_config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = dev_addr,
        .scl_speed_hz = SHTC3_I2C_SPEED_HZ,
    };

    esp_err_t err = i2c_master_bus_add_device(bus, &dev_config, &s_dev);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to add device at 0x%02X: %s", dev_addr, esp_err_to_name(err));
        s_dev = NULL;
        return err;
    }

    s_bus = bus;
    ESP_LOGI(TAG, "SHTC3 attached at 0x%02X", dev_addr);
    return ESP_OK;
}

bool shtc3_present(void)
{
    if (s_bus == NULL)
    {
        return false;
    }
    // Address-only acknowledge, which does not disturb the sensor's state the
    // way a measurement command would.
    return i2c_master_probe(s_bus, SHTC3_DEFAULT_I2C_ADDR, SHTC3_XFER_TIMEOUT_MS) == ESP_OK;
}

esp_err_t shtc3_read(float *temperature_c, float *humidity_pct)
{
    if (s_dev == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }
    if (temperature_c == NULL || humidity_pct == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t cmd[2] = {
        (uint8_t)(SHTC3_CMD_MEASURE >> 8),
        (uint8_t)(SHTC3_CMD_MEASURE & 0xFF),
    };

    esp_err_t err = i2c_master_transmit(s_dev, cmd, sizeof(cmd), SHTC3_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        return err;
    }

    vTaskDelay(pdMS_TO_TICKS(SHTC3_MEASURE_WAIT_MS));

    uint8_t raw[SHTC3_RAW_LEN] = {0};
    err = i2c_master_receive(s_dev, raw, sizeof(raw), SHTC3_XFER_TIMEOUT_MS);
    if (err != ESP_OK)
    {
        return err;
    }

    if (shtc3_crc8(&raw[0], 2) != raw[2] || shtc3_crc8(&raw[3], 2) != raw[5])
    {
        ESP_LOGW(TAG, "CRC mismatch: %02x %02x %02x %02x %02x %02x",
                 raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
        return ESP_ERR_INVALID_RESPONSE;
    }

    const uint16_t raw_t = (uint16_t)((raw[0] << 8) | raw[1]);
    const uint16_t raw_rh = (uint16_t)((raw[3] << 8) | raw[4]);

    // Datasheet section 5.11: note the plain 2^16 denominator with no -1, and
    // the linear 100 %RH humidity mapping.
    const float temperature = -45.0f + 175.0f * (float)raw_t / 65536.0f;
    const float humidity = 100.0f * (float)raw_rh / 65536.0f;

    if (temperature < SHTC3_TEMP_MIN_C || temperature > SHTC3_TEMP_MAX_C ||
        humidity < SHTC3_RH_MIN_PCT || humidity > SHTC3_RH_MAX_PCT)
    {
        ESP_LOGW(TAG, "Reading out of range: %.2f C, %.2f %%RH", temperature, humidity);
        return ESP_ERR_INVALID_RESPONSE;
    }

    *temperature_c = temperature;
    *humidity_pct = humidity;
    return ESP_OK;
}

void shtc3_deinit(void)
{
    if (s_dev != NULL)
    {
        i2c_master_bus_rm_device(s_dev);
        s_dev = NULL;
    }
    s_bus = NULL;
}
