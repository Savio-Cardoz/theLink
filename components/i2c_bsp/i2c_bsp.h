#ifndef I2C_BSP_H
#define I2C_BSP_H

#include <stddef.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
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

    // Walk the 7-bit addresses in [first_addr, last_addr], inclusive, and collect
    // the ones that acknowledge into `found`.
    //
    // A diagnostic, not a routine call: an address that answers tells you which
    // devices are really on the bus, an empty result or an early timeout tells you
    // the bus itself is at fault. Probes a quiet bus take well under a millisecond
    // each, so a full sweep costs a few milliseconds of bus time.
    //
    // A bus held low by a shorted or unpowered device makes every probe time out;
    // the sweep then stops at the first address and reports ESP_ERR_TIMEOUT so the
    // caller can say so instead of reporting an empty bus.
    //
    // Returns ESP_OK even when nothing answers, with *found_count left at 0.
    // Returns ESP_ERR_INVALID_ARG on a bad range or a NULL buffer, and
    // ESP_ERR_INVALID_STATE when i2c_bsp_init() has not installed a bus yet.
    esp_err_t i2c_bsp_scan(uint8_t port, uint8_t first_addr, uint8_t last_addr,
                           uint8_t *found, size_t found_cap, size_t *found_count);

#ifdef __cplusplus
}
#endif

#endif // I2C_BSP_H
