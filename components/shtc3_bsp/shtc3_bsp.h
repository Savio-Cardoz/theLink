#ifndef SHTC3_BSP_H
#define SHTC3_BSP_H

#include <stdbool.h>
#include <stdint.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Sensirion SHTC3: temperature + relative-humidity sensor. I2C address 0x70
// (see the SHTC3 datasheet, table 8). Every command and register is a 16-bit
// word sent most-significant byte first.
#define SHTC3_DEFAULT_I2C_ADDR 0x70

// Fast mode. The shared bus is clocked this slowly for the audio codec, so
// matching it keeps the codec's timing characteristics unchanged.
#define SHTC3_I2C_SPEED_HZ 100000

// Start a measurement, no clock stretching, no hold: the sensor finishes and
// drops back to sleep on its own, so we can read the result a fixed time later.
#define SHTC3_CMD_MEASURE 0x0066

// Maximum measurement time is 70 ms (8.3 ms typical); wait a little longer.
#define SHTC3_MEASURE_WAIT_MS 80

// Attach to an already-installed I2C master bus. The caller owns the bus and
// must keep it alive for as long as this device handle is used.
esp_err_t shtc3_init(i2c_master_bus_handle_t bus, uint8_t dev_addr);

// Whether a device acknowledges on the bus. Cheap presence check for logs and
// for deciding whether the module is worth enabling.
bool shtc3_present(void);

// One blocking measurement. Returns ESP_OK only when both CRC bytes verify and
// the decoded values fall inside the sensor's specified range, so a caller can
// never publish a reading that is really bus noise.
esp_err_t shtc3_read(float *temperature_c, float *humidity_pct);

void shtc3_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // SHTC3_BSP_H
