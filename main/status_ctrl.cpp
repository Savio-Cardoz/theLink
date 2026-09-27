#include <cstdlib>
#include <string>

#include "esp_log.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "cJSON.h"

#include "app_common.hpp"
#include "display_ctrl.hpp"
#include "identity.hpp"
#include "led_ctrl.hpp"
#include "mqtt_io.hpp"

#include "status_ctrl.hpp"

static const char *TAG = "app";

static void publish_status(void)
{
	const esp_app_desc_t *desc = esp_app_get_description();

	cJSON *root = cJSON_CreateObject();
	if (root == nullptr)
	{
		return;
	}

	// ── The three fields the status command exists for ────────────────
	cJSON_AddStringToObject(root, "version", desc->version);
	cJSON_AddStringToObject(root, "rgb_pattern", led_ctrl::pattern_get());

	// Null (not "") when nothing has been rendered onto the e-paper yet.
	std::string image = display_ctrl::rendered_path_get();
	if (image.empty())
	{
		cJSON_AddNullToObject(root, "image");
	}
	else
	{
		cJSON_AddStringToObject(root, "image", image.c_str());
	}

	// ── Supporting device information ─────────────────────────────────
	cJSON_AddStringToObject(root, "device_id", identity_device_id());

	const esp_partition_t *running = esp_ota_get_running_partition();
	if (running != nullptr)
	{
		cJSON_AddStringToObject(root, "partition", running->label);
	}
	else
	{
		cJSON_AddNullToObject(root, "partition");
	}

	cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000));
	cJSON_AddNumberToObject(root, "free_heap", (double)esp_get_free_heap_size());
	cJSON_AddNumberToObject(root, "min_free_heap", (double)esp_get_minimum_free_heap_size());

	// Only present when the image was built with CONFIG_APP_COMPILE_TIME_DATE;
	// both fields are empty strings otherwise.
	if (desc->date[0] != '\0' || desc->time[0] != '\0')
	{
		cJSON *build = cJSON_CreateObject();
		cJSON_AddStringToObject(build, "date", desc->date);
		cJSON_AddStringToObject(build, "time", desc->time);
		cJSON_AddStringToObject(build, "idf", desc->idf_ver);
		cJSON_AddItemToObject(root, "build", build);
	}

	// A reply to a request, not cached state: do not retain.
	char *payload = cJSON_Print(root);
	if (payload != nullptr)
	{
		app::mqtt_publish(identity_topic_evt_status(), payload, 1, 0);
		free(payload);
	}
	cJSON_Delete(root);
}

// Payload is intentionally ignored: the command is a bare query, so an empty
// body (or even a malformed one) still yields a status snapshot.
void status_ctrl::handle_status_command(const char *payload)
{
	(void)payload;
	ESP_LOGI(TAG, "Status command received");
	publish_status();
}

void status_ctrl::init(void)
{
	mqtt_register_cmd(identity_topic_cmd_status(), status_ctrl::handle_status_command);
}
