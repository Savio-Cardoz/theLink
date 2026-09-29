#ifndef I2C_BSP_H
#define I2C_BSP_H

#include <stdint.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Highest I2C port index this component will install a bus for.
#define I2C_BSP_MAX_PORTS (2)

// Install the board I2C master bus on `port` with the given SDA/SCL pins.
//
// Idempotent: if a bus is already registered on that port (for example by the
// audio codec board support) that handle is adopted as-is and ESP_OK is
// returned, so several modules may call this without coordinating.
//
// Pins are passed in by the caller rather than read from a board config so this
// component stays independent of the application layer. The bus parameters
// deliberately match the ones the audio board support uses, so sharing a single
// bus does not change I2C behaviour for the devices already on it.
esp_err_t i2c_bsp_init(uint8_t port, gpio_num_t sda, gpio_num_t scl);

// Handle for the bus on `port`, or NULL when i2c_bsp_init() has not installed
// one yet. Safe to call from any task once init has run.
i2c_master_bus_handle_t i2c_bsp_bus(uint8_t port);

// Tear down the bus installed by i2c_bsp_init(). Any device handle obtained
// from that bus becomes invalid, so callers must drop theirs first. Does
// nothing when this component never installed the bus.
void i2c_bsp_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // I2C_BSP_H
