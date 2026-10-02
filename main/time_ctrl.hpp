#ifndef TIME_CTRL_HPP
#define TIME_CTRL_HPP

#include <cstdint>

#include "cJSON.h"

// Wall-clock time for the unit: the system clock itself, where it came from, and
// the optional timezone used to render it as local time.
//
// SNTP is the authority. The PCF85063 on the e-paper module is read at boot only
// to see whether it already holds a usable time, and is rewritten from SNTP on
// every correction. What that buys is narrower than it looks: the part is powered
// from the board's 3v3 rail and this board fits no backup source for it, so it
// keeps time across a device restart (an OTA, a crash, a watchdog reset) but not
// across a power cycle. After an unplug the registers are back at the power-on
// default and the seed is skipped, which leaves SNTP as the only way to a
// timestamp. The vendor's own example drives the VBAT enable on GPIO 17 for
// exactly this reason; theLink does not, so nothing here depends on it.
//
// There is no location detection on this device: the timezone is declared, via a
// cmd/timezone command or the CONFIG_THELINK_TZ default, in the POSIX form the C
// library actually understands. IANA names such as "Asia/Kolkata" are not
// supported, because newlib ships no timezone database to resolve them against.
namespace time_ctrl
{

    // Register the cmd/timezone handler and the on-connect republish. Touches no
    // hardware, so it is safe to call alongside the other init() functions early
    // in app_main.
    void init(void);

    // Attach the RTC, seed the system clock from it if it holds a plausible time,
    // and start listening for the Wi-Fi address that begins SNTP.
    //
    // Call after esp_event_loop_create_default() and after the I2C bus exists,
    // which in practice means next to sensor_ctrl::start().
    void start(void);

    // MQTT handler for {"tz": "IST-5:30"}.
    void handle_timezone_command(const char *payload);

    // Add the "time" object to an outgoing status payload.
    void status_serialize(cJSON *root);

    // Serialize / restore the declared timezone for config.json.
    void config_serialize(cJSON *obj);
    void config_apply(cJSON *obj);

} // namespace time_ctrl

#endif // TIME_CTRL_HPP
