#pragma once

#include <functional>
#include <string>

#include "esp_err.h"
#include "mqtt_client.h"

using MqttCmdHandler = std::function<void(const char *)>;

// Register a topic -> command handler pair. Subscriptions are derived from
// the registered topics when the client connects, so controllers self-register
// at init and the MQTT layer stays free of subsystem knowledge.
void mqtt_register_cmd(const std::string &topic, MqttCmdHandler handler);

// Build the MQTT5 client and start it. Call after Wi-Fi is up; retry until it
// succeeds. On failure the half-built client is destroyed and app::set_mqtt()
// is cleared, so nothing publishes into a task-less client.
esp_err_t mqtt_io_start(void);
