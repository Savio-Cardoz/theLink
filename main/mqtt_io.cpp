#include <cstdlib>
#include <cstring>
#include <inttypes.h>
#include <map>
#include <functional>

#include "esp_log.h"
#include "mqtt_client.h"

#include "app_common.hpp"
#include "identity.hpp"
#include "mqtt_logger.h"

#include "mqtt_io.hpp"

static const char *TAG = "app";

static std::map<std::string, MqttCmdHandler> s_cmd_dispatch;

void mqtt_register_cmd(const std::string &topic, MqttCmdHandler handler)
{
	s_cmd_dispatch[topic] = std::move(handler);
}

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 */
static void mqtt5_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
	ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32, base, event_id);
	esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
	esp_mqtt_client_handle_t client = event->client;
	int msg_id;

	ESP_LOGD(TAG, "free heap size is %" PRIu32 ", minimum %" PRIu32, esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
	switch ((esp_mqtt_event_id_t)event_id)
	{
	case MQTT_EVENT_CONNECTED:
		ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
		app::set_mqtt(client);

		// Subscribe to per-device command topics
		for (auto &kv : s_cmd_dispatch)
		{
			msg_id = esp_mqtt_client_subscribe(client, kv.first.c_str(), 1);
			ESP_LOGI(TAG, "subscribed to %s, msg_id=%d", kv.first.c_str(), msg_id);
		}

		// Initialise MQTT logger
		mqtt_logger_init(client, identity_device_id(), MQTT_LOG_INFO, 16);

		// App is fully up: hand the notification LED back to MQTT control and
		// let subsystems publish their connect-time state (LED status, deferred
		// OTA outcome, ...).
		app::fire_on_connect();
		break;
	case MQTT_EVENT_DISCONNECTED:
		ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
		break;
	case MQTT_EVENT_SUBSCRIBED:
		ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_UNSUBSCRIBED:
		ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_PUBLISHED:
		ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_DATA:
	{
		ESP_LOGD(TAG, "MQTT_EVENT_DATA");
		ESP_LOGD(TAG, "TOPIC=%.*s", event->topic_len, event->topic);

		// Ensure the payload is null-terminated for parsing
		char *payload = (char *)malloc(event->data_len + 1);
		if (payload == NULL)
		{
			ESP_LOGE(TAG, "Failed to allocate memory for payload");
			return;
		}

		memcpy(payload, event->data, event->data_len);
		payload[event->data_len] = '\0';

		// ── Topic-based dispatch via lookup table ────────────────────────
		std::string topic(event->topic, event->topic_len);
		auto it = s_cmd_dispatch.find(topic);
		if (it != s_cmd_dispatch.end())
		{
			it->second(payload);
		}
		else
		{
			ESP_LOGW(TAG, "No handler for topic: %.*s", event->topic_len, event->topic);
		}

		free(payload);
	}
	break;
	case MQTT_EVENT_ERROR:
		ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
		ESP_LOGI(TAG, "MQTT5 return code is %d", event->error_handle->connect_return_code);
		break;
	case MQTT_EVENT_BEFORE_CONNECT:
	case MQTT_EVENT_DELETED:
	case MQTT_EVENT_ANY:
	case MQTT_USER_EVENT:
	default:
		ESP_LOGI(TAG, "Other event id:%d", event->event_id);
		break;
	}
}

void mqtt_io_start(void)
{
	mqtt_register_cmd(identity_topic_cmd_log(), mqtt_logger_handle_command);

	esp_mqtt_client_config_t mqtt5_cfg = {};
	mqtt5_cfg.broker.address.uri = CONFIG_BROKER_URL;
	mqtt5_cfg.session.protocol_ver = MQTT_PROTOCOL_V_5;

	esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt5_cfg);
	app::set_mqtt(client);

	esp_mqtt_client_register_event(client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt5_event_handler, NULL);
	esp_mqtt_client_start(client);
}