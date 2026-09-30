#ifndef SENSOR_CTRL_HPP
#define SENSOR_CTRL_HPP

#include "cJSON.h"

// On-board SHTC3 temperature and humidity sensor.
//
// The sensor lives on the same I2C segment as the audio codec and its rail comes
// up with the audio subsystem, so a dedicated task waits for the bus to settle,
// sweeps it once for the boot log, and only then starts sampling periodically.
// It keeps the latest valid reading, publishes it to evt/sensor, and lets
// status_ctrl fold it into evt/status without anyone having to ask for a
// synchronous reading.
namespace sensor_ctrl
{

    // Subscribe to the MQTT connect event so the retained evt/sensor message is
    // re-published after every broker reconnect. Touches no hardware, so it is safe
    // to call alongside the other init() functions early in app_main.
    void init(void);

    // Install the shared I2C bus, attach the SHTC3 and spawn the sampling task.
    //
    // Run this from app_main before audio_ctrl::start(): the audio board support
    // creates the I2C bus itself when it finds none, so the first caller wins, and
    // doing it here keeps that decision single-threaded.
    void start(void);

    // Publish the cached reading to evt/sensor (QoS 1, retained). No-op until the
    // first successful sample.
    void publish_status(void);

    // Add the "sensor" object to an outgoing status payload.
    void status_serialize(cJSON *root);

} // namespace sensor_ctrl

#endif // SENSOR_CTRL_HPP
