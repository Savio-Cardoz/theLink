#ifndef SHTC3_BSP_H
#define SHTC3_BSP_H

#include <stdbool.h>
#include <stdint.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
#endif

// Sensirion SHTC3: temperature + relative-humidity sensor. I2C address 0x70
// (see the SHTC3 datasheet, table 8). Every command and register is a 16-bit
// word sent most-significant byte first.
#define SHTC3_DEFAULT_I2C_ADDR 0x70

// Fast mode. The shared bus is clocked this slowly for the audio codec, so
// matching it keeps the codec's timing characteristics unchanged.
#define SHTC3_I2C_SPEED_HZ 100000

// Datasheet table 11, measurement commands: clock stretching disabled,
// temperature returned first, normal resolution. The temperature comes back in
// the first word and the humidity in the second, which is the order shtc3_read()
// decodes. Clock stretching is disabled on purpose, because the ESP32 I2C master
// does not support it: the sensor instead holds the reading for us and we come
// back for it once tMEAS has passed.
#define SHTC3_CMD_MEASURE 0x7866

// Datasheet tables 9 and 10, and the four-command measurement cycle of figure 7.
// While the sensor is asleep it NACKs everything except the wake-up command, so a
// measurement cycle is wake up, measure, read, sleep and none of the three can be
// left out. Section 5.2 notes the part powers up in idle state, so the wake-up
// before the very first command is belt and braces rather than strictly required.
#define SHTC3_CMD_WAKEUP 0x3517
#define SHTC3_CMD_SLEEP 0xB098

// Datasheet table 14. Reading the ID register is the only documented way to
// confirm a real SHTC3 answered rather than any device that happens to sit at
// 0x70, and it is what the Waveshare factory example reports.
#define SHTC3_CMD_READ_ID 0xEFC8

// Datasheet table 5: tMEAS is 10.8 ms typical and 12.1 ms worst case, the worst
// case measured at -40 C. Wait comfortably past that so the result is ready
// whichever way the temperature swings.
#define SHTC3_MEASURE_WAIT_MS 80

// Table 5 gives no explicit wake-up time, so this is the margin the Waveshare
// reference implementation uses and is far more than the sensor ever needs.
#define SHTC3_WAKEUP_WAIT_MS 50

    // Attach to an already-installed I2C master bus. The caller owns the bus and
    // must keep it alive for as long as this device handle is used.
    esp_err_t shtc3_init(i2c_master_bus_handle_t bus, uint8_t dev_addr);

    // Whether the sensor acknowledges at the address shtc3_init() attached it to.
    // Cheap presence check for logs and for deciding whether the module is worth
    // enabling. Logs the outcome either way: a silent false is what makes a broken
    // sensor look like a broken bus.
    bool shtc3_present(void);

    // One blocking measurement. Returns ESP_OK only when both CRC bytes verify and
    // the decoded values fall inside the sensor's specified range, so a caller can
    // never publish a reading that is really bus noise. Every failure is logged with
    // its stage, since the driver reports a NACK as ESP_ERR_INVALID_STATE.
    esp_err_t shtc3_read(float *temperature_c, float *humidity_pct);

    void shtc3_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // SHTC3_BSP_H
