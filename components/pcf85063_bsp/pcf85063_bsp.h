#ifndef PCF85063_BSP_H
#define PCF85063_BSP_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
#endif

// NXP PCF85063TP: tiny real-time clock/calendar on a 32.768 kHz crystal. I2C
// address 0x51 (PCF85063TP datasheet, section 8). Unlike its PCF85063A sibling
// the TP has no alarm or timer registers: the register space stops at 0x0A and
// auto-incrementing wraps back to 0x00 after it, so an address past 0x0A is a
// programming error rather than a silent alias of the control register.
#define PCF85063_DEFAULT_I2C_ADDR 0x51

// Fast mode. The shared bus is clocked this slowly for the audio codec, so
// matching it keeps the codec's timing characteristics unchanged. The part is
// rated for 400 kHz, so this is a deliberate under-use.
#define PCF85063_I2C_SPEED_HZ 100000

// Datasheet section 8.1: eleven registers, 00h through 0Ah. Time and date
// values are BCD.
#define PCF85063_REG_CONTROL_1 0x00
#define PCF85063_REG_CONTROL_2 0x01
#define PCF85063_REG_OFFSET 0x02
#define PCF85063_REG_SECONDS 0x04
#define PCF85063_REG_MINUTES 0x05
#define PCF85063_REG_HOURS 0x06
#define PCF85063_REG_DAYS 0x07
#define PCF85063_REG_WEEKDAYS 0x08
#define PCF85063_REG_MONTHS 0x09
#define PCF85063_REG_YEARS 0x0A

// Consecutive date/time registers, 0x04..0x0A. The device freezes its counters
// for the duration of a read or write of any of them (datasheet section 8.1), so
// the whole block is fetched in a single transaction to stay inside the one
// second window and to make a torn read across a minute boundary impossible.
#define PCF85063_DATETIME_FIRST_REG PCF85063_REG_SECONDS
#define PCF85063_DATETIME_REG_COUNT 7

// Control_1 (datasheet table 6).
#define PCF85063_CTRL1_STOP (1 << 5)   // divider held in reset while we write
#define PCF85063_CTRL1_EXT_TEST (1 << 7) // must be low to leave test mode

// Seconds (datasheet table 12). The OS bit is set by the power-on reset and by
// a stop of the oscillator, and stays set until software clears it, so it is the
// part's own statement that the stored time is not trustworthy.
#define PCF85063_SECONDS_OS 0x80

// Software reset pattern for Control_1 (datasheet section 8.2.1.3).
#define PCF85063_CTRL1_SWR 0x58

// Attach to an already-installed I2C master bus. The caller owns the bus and
// must keep it alive for as long as this device handle is used.
esp_err_t pcf85063_init(i2c_master_bus_handle_t bus, uint8_t dev_addr);

// Whether the RTC acknowledges at the address pcf85063_init() attached it to.
// Cheap presence check for logs and for deciding whether the module is worth
// enabling. Logs the outcome either way: a silent false is what makes a missing
// backup cell look like a working one.
bool pcf85063_present(void);

// Whether the stored time can be believed: the OS bit clear and a calendar that
// passes a range check. A part that has never been set, or whose backup rail
// dropped, reports false here rather than handing back the power-on default of
// 1 January 2000.
//
// Both of these describe the part's state, not this board's arrangement. The
// e-paper module runs the RTC from 3v3 and fits no backup source for it, so the
// registers are only meaningful within the current power cycle: they survive a
// reset, and they are back at the power-on default after an unplug. A true here
// therefore does not mean the time is still good now, only that this boot found
// something worth reading.
bool pcf85063_time_valid(void);

// Read the current UTC calendar into `out`. tm_year is the usual years-since-1900;
// the part stores a two-digit year, so the century is assumed to be 20xx, which
// covers every date this device can reach.
esp_err_t pcf85063_read(struct tm *out);

// Store a UTC calendar. Holds the divider in reset for the write so no tick is
// lost between the byte writes, and leaves the clock running afterwards.
esp_err_t pcf85063_write(const struct tm *t);

void pcf85063_deinit(void);

#ifdef __cplusplus
}
#endif

#endif // PCF85063_BSP_H
