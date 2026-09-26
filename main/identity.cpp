#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"

#include "identity.hpp"

#define DEVICE_ID_MAX_LEN  32
#define MQTT_TOPIC_MAX_LEN 64

static char s_device_id[DEVICE_ID_MAX_LEN];
static char s_mqtt_cmd_log_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_display_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_rgb_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_audio_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_notification_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_ota_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_cmd_status_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_evt_led_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_evt_ota_topic[MQTT_TOPIC_MAX_LEN];
static char s_mqtt_evt_status_topic[MQTT_TOPIC_MAX_LEN];

void identity_init(void)
{
	uint8_t mac[6];
	esp_efuse_mac_get_default(mac);

	// Device ID: "UUVVWWXXYYZZ"
	snprintf(s_device_id, sizeof(s_device_id), "%02X%02X%02X%02X%02X%02X",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	// Topic paths
	snprintf(s_mqtt_cmd_log_topic, sizeof(s_mqtt_cmd_log_topic),
			 "thelink/%s/cmd/log", s_device_id);
	snprintf(s_mqtt_cmd_display_topic, sizeof(s_mqtt_cmd_display_topic),
			 "thelink/%s/cmd/display", s_device_id);
	snprintf(s_mqtt_cmd_rgb_topic, sizeof(s_mqtt_cmd_rgb_topic),
			 "thelink/%s/cmd/rgb", s_device_id);
	snprintf(s_mqtt_cmd_audio_topic, sizeof(s_mqtt_cmd_audio_topic),
			 "thelink/%s/cmd/audio", s_device_id);
	snprintf(s_mqtt_cmd_notification_topic, sizeof(s_mqtt_cmd_notification_topic),
			 "thelink/%s/cmd/notification", s_device_id);
	snprintf(s_mqtt_cmd_ota_topic, sizeof(s_mqtt_cmd_ota_topic),
			 "thelink/%s/cmd/ota", s_device_id);
	snprintf(s_mqtt_cmd_status_topic, sizeof(s_mqtt_cmd_status_topic),
			 "thelink/%s/cmd/status", s_device_id);
	snprintf(s_mqtt_evt_led_topic, sizeof(s_mqtt_evt_led_topic),
			 "thelink/%s/evt/led", s_device_id);
	snprintf(s_mqtt_evt_ota_topic, sizeof(s_mqtt_evt_ota_topic),
			 "thelink/%s/evt/ota", s_device_id);
	snprintf(s_mqtt_evt_status_topic, sizeof(s_mqtt_evt_status_topic),
			 "thelink/%s/evt/status", s_device_id);

	ESP_LOGI("DEVICE", "Device ID: %s", s_device_id);
	ESP_LOGI("DEVICE", "Log cmd topic: %s", s_mqtt_cmd_log_topic);
	ESP_LOGI("DEVICE", "Display cmd topic: %s", s_mqtt_cmd_display_topic);
	ESP_LOGI("DEVICE", "RGB cmd topic: %s", s_mqtt_cmd_rgb_topic);
	ESP_LOGI("DEVICE", "Audio cmd topic: %s", s_mqtt_cmd_audio_topic);
	ESP_LOGI("DEVICE", "Notification cmd topic: %s", s_mqtt_cmd_notification_topic);
	ESP_LOGI("DEVICE", "OTA cmd topic: %s", s_mqtt_cmd_ota_topic);
	ESP_LOGI("DEVICE", "Status cmd topic: %s", s_mqtt_cmd_status_topic);
	ESP_LOGI("DEVICE", "LED evt topic: %s", s_mqtt_evt_led_topic);
	ESP_LOGI("DEVICE", "OTA evt topic: %s", s_mqtt_evt_ota_topic);
	ESP_LOGI("DEVICE", "Status evt topic: %s", s_mqtt_evt_status_topic);
}

const char *identity_device_id(void)
{
	return s_device_id;
}

const char *identity_topic_cmd_log(void)
{
	return s_mqtt_cmd_log_topic;
}

const char *identity_topic_cmd_display(void)
{
	return s_mqtt_cmd_display_topic;
}

const char *identity_topic_cmd_rgb(void)
{
	return s_mqtt_cmd_rgb_topic;
}

const char *identity_topic_cmd_audio(void)
{
	return s_mqtt_cmd_audio_topic;
}

const char *identity_topic_cmd_notification(void)
{
	return s_mqtt_cmd_notification_topic;
}

const char *identity_topic_cmd_ota(void)
{
	return s_mqtt_cmd_ota_topic;
}

const char *identity_topic_cmd_status(void)
{
	return s_mqtt_cmd_status_topic;
}

const char *identity_topic_evt_led(void)
{
	return s_mqtt_evt_led_topic;
}

const char *identity_topic_evt_ota(void)
{
	return s_mqtt_evt_ota_topic;
}

const char *identity_topic_evt_status(void)
{
	return s_mqtt_evt_status_topic;
}