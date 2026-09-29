#include <string.h>

#include "driver/i2c_master.h"

#include "esp_log.h"

#include "i2c_bsp.h"

static const char *TAG = "I2C_BSP";

// Mirrors the bus setup in the audio board support (components/codec_board/
// codec_init.c) so that a bus installed here behaves identically for the codec
// and RTC that share it.
#define I2C_BSP_GLITCH_IGNORE_CNT 7

static i2c_master_bus_handle_t s_bus[I2C_BSP_MAX_PORTS];
static bool s_installed[I2C_BSP_MAX_PORTS];

// Ask the I2C driver which bus is registered on a port. Since v5.4 the driver
// keeps this registry, which is what lets the audio board support find and
// adopt a bus installed elsewhere without patching it.
static i2c_master_bus_handle_t driver_bus(uint8_t port)
{
    i2c_master_bus_handle_t bus = NULL;
    if (i2c_master_get_bus_handle((i2c_port_num_t)port, &bus) == ESP_OK)
    {
        return bus;
    }
    return NULL;
}

esp_err_t i2c_bsp_init(uint8_t port, gpio_num_t sda, gpio_num_t scl)
{
    if (port >= I2C_BSP_MAX_PORTS) {
        ESP_LOGE(TAG, "I2C port %u out of range (max %d)", port, I2C_BSP_MAX_PORTS);
        return ESP_ERR_INVALID_ARG;
    }

    // Somebody got here first: adopt their bus rather than fighting over it.
    i2c_master_bus_handle_t existing = driver_bus(port);
    if (existing != NULL) {
        if (s_bus[port] != existing) {
            ESP_LOGI(TAG, "Adopting existing I2C master bus on port %u", port);
        }
        s_bus[port] = existing;
        s_installed[port] = false;
        return ESP_OK;
    }

    if (s_installed[port]) {
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
    if (err != ESP_OK) {
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
    if (port >= I2C_BSP_MAX_PORTS) {
        return NULL;
    }
    return s_bus[port];
}

void i2c_bsp_deinit(void)
{
    for (uint8_t port = 0; port < I2C_BSP_MAX_PORTS; port++) {
        if (!s_installed[port]) {
            continue;
        }
        ESP_LOGI(TAG, "Deleting I2C master bus on port %u", port);
        i2c_del_master_bus(s_bus[port]);
        s_bus[port] = NULL;
        s_installed[port] = false;
    }
}
