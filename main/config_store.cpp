#include <cstdio>
#include <cstdlib>

#include "esp_log.h"

#include "cJSON.h"

#include "config_store.hpp"
#include "display_ctrl.hpp"
#include "led_ctrl.hpp"

static const char *TAG = "CONFIG";

void config_store_save(void)
{
	// Create the root JSON object structure
	cJSON *root = cJSON_CreateObject();

	// Add display path string
	{
		cJSON_AddStringToObject(root, "display", display_ctrl::data_path_get().c_str());
	}

	// Add LED pattern state as a structured object
	{
		cJSON *led = cJSON_CreateObject();
		led_ctrl::status_serialize(led);
		cJSON_AddItemToObject(root, "led", led);
	}

	char *json_str = cJSON_Print(root);
	if (json_str != NULL)
	{
		FILE *f = fopen("/sdcard/config.json", "w");
		if (f != NULL)
		{
			fputs(json_str, f);
			fclose(f);
			ESP_LOGI(TAG, "Configuration saved successfully to SD Card.");
		}
		else
		{
			ESP_LOGE(TAG, "Failed to open config.json for writing!");
		}
		free(json_str); // Always free memory allocated by cJSON_Print
	}
	cJSON_Delete(root);
}

void config_store_load(void)
{
	FILE *f = fopen("/sdcard/config.json", "r");
	if (f == NULL)
	{
		ESP_LOGW(TAG, "No config.json found on SD Card. Using defaults.");
		return;
	}

	// Determine file size to allocate buffer space cleanly
	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *json_buf = (char *)malloc(file_size + 1);
	if (json_buf != NULL)
	{
		fread(json_buf, 1, file_size, f);
		json_buf[file_size] = '\0';
		fclose(f);

		cJSON *json = cJSON_Parse(json_buf);
		if (json != NULL)
		{
			// Parse and apply Display Path parameters
			cJSON *display_item = cJSON_GetObjectItemCaseSensitive(json, "display");
			if (cJSON_IsString(display_item) && (display_item->valuestring != NULL))
			{
				display_ctrl::data_path_set(std::string(display_item->valuestring));
				ESP_LOGI(TAG, "Restored display state path: %s", display_item->valuestring);
			}

			// Parse and apply LED notification parameters
			cJSON *led_item = cJSON_GetObjectItemCaseSensitive(json, "led");
			if (led_item != nullptr)
			{
				if (cJSON_IsString(led_item) && led_item->valuestring != NULL)
				{
					// Legacy format: "active" / "inactive"
					led_ctrl::status_apply_legacy_str(led_item->valuestring);
				}
				else if (cJSON_IsObject(led_item))
				{
					led_ctrl::status_apply(led_item);
				}
			}

			cJSON_Delete(json);
		}
		free(json_buf);
	}
	else
	{
		fclose(f);
		ESP_LOGE(TAG, "Heap allocation failed for reading config JSON text buffer.");
	}
}