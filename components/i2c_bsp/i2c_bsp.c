#include <string.h>

#include "driver/i2c_master.h"
#include "esp_log.h"

#include "i2c_bsp.h"

static const char *TAG = "I2C_BSP";

// Tag of the ESP-IDF I2C driver, silenced while sweeping so an absent device
// does not print an error per address.
static const char *DRIVER_TAG = "i2c.master";

// Mirrors the bus setup in the audio board support (components/codec_board/
// codec_init.c) so that a bus installed here behaves identically for the codec
// and RTC that share it.
#define I2C_BSP_GLITCH_IGNORE_CNT 7

// A probe of a present device finishes in a few hundred microseconds, so this
// only ever gets spent when a device holds the bus down.
#define I2C_BSP_SCAN_TIMEOUT_MS 20

static i2c_master_bus_handle_t s_bus[I2C_BSP_MAX_PORTS];
static bool s_installed[I2C_BSP_MAX_PORTS];

esp_err_t i2c_bsp_init(uint8_t port, gpio_num_t sda, gpio_num_t scl)
{
    if (port >= I2C_BSP_MAX_PORTS)
    {
        ESP_LOGE(TAG, "I2C port %u out of range (max %d)", port, I2C_BSP_MAX_PORTS);
        return ESP_ERR_INVALID_ARG;
    }

    if (s_bus[port] != NULL)
    {
        return ESP_OK;
    }

    i2c_master_bus_config_t bus_config = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .i2c_port = (i2c_port_num_t)port,
        .sda_io_num = sda,
        .scl_io_num = scl,
        .glitch_ignore_cnt = I2C_BSP_GLITCH_IGNORE_CNT,
        .flags.enable_internal_pullup = true,
    };

    i2c_master_bus_handle_t bus = NULL;
    esp_err_t err = i2c_new_master_bus(&bus_config, &bus);
    if (err == ESP_ERR_INVALID_STATE)
    {
        // Somebody got here first, most likely the audio board support, which
        // installs the bus itself from the audio task. Adopt their bus rather
        // than fighting over it.
        if (i2c_master_get_bus_handle((i2c_port_num_t)port, &bus) == ESP_OK && bus != NULL)
        {
            s_bus[port] = bus;
            s_installed[port] = false;
            ESP_LOGI(TAG, "Adopting existing I2C master bus on port %u", port);
            return ESP_OK;
        }
    }
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to create I2C master bus on port %u: %s", port, esp_err_to_name(err));
        return err;
    }

    s_bus[port] = bus;
    s_installed[port] = true;
    ESP_LOGI(TAG, "I2C master bus %d up on SDA %d / SCL %d", port, sda, scl);
    return ESP_OK;
}

i2c_master_bus_handle_t i2c_bsp_bus(uint8_t port)
{
    if (port >= I2C_BSP_MAX_PORTS)
    {
        return NULL;
    }
    return s_bus[port];
}

void i2c_bsp_deinit(void)
{
    for (uint8_t port = 0; port < I2C_BSP_MAX_PORTS; port++)
    {
        if (!s_installed[port])
        {
            continue;
        }
        ESP_LOGI(TAG, "Deleting I2C master bus on port %u", port);
        i2c_del_master_bus(s_bus[port]);
        s_bus[port] = NULL;
        s_installed[port] = false;
    }
}

esp_err_t i2c_bsp_scan(uint8_t port, uint8_t first_addr, uint8_t last_addr,
                       uint8_t *found, size_t found_cap, size_t *found_count)
{
    if (port >= I2C_BSP_MAX_PORTS)
    {
        ESP_LOGE(TAG, "I2C port %u out of range (max %d)", port, I2C_BSP_MAX_PORTS);
        return ESP_ERR_INVALID_ARG;
    }
    if (first_addr > last_addr || last_addr > 0x7F)
    {
        ESP_LOGE(TAG, "I2C scan range 0x%02X..0x%02X is not a valid 7-bit range", first_addr, last_addr);
        return ESP_ERR_INVALID_ARG;
    }
    if (found == NULL || found_count == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_bus[port] == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    *found_count = 0;

    // The driver logs every address-only write that comes back NACKed, which on
    // a mostly empty bus is most of them. Mute it for the sweep only.
    const esp_log_level_t driver_level = esp_log_level_get(DRIVER_TAG);
    esp_log_level_set(DRIVER_TAG, ESP_LOG_NONE);

    esp_err_t ret = ESP_OK;
    for (unsigned addr = first_addr; addr <= last_addr; addr++)
    {
        const esp_err_t err = i2c_master_probe(s_bus[port], (uint16_t)addr, I2C_BSP_SCAN_TIMEOUT_MS);
        if (err == ESP_OK)
        {
            if (*found_count < found_cap)
            {
                found[(*found_count)++] = (uint8_t)addr;
            }
            continue;
        }
        if (err == ESP_ERR_TIMEOUT)
        {
            // Nothing that answers within 20 ms means the bus itself is stuck,
            // not that a single device is absent: sweeping on would only burn
            // 20 ms per address to reach the same conclusion.
            ret = ESP_ERR_TIMEOUT;
            break;
        }
    }

    esp_log_level_set(DRIVER_TAG, driver_level);
    return ret;
}
