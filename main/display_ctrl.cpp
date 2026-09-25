#include <cstdio>
#include <cstring>
#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_heap_caps.h"

#include "cJSON.h"

#include "lvgl.h"
#include "user_app.h"

#include "assert.h"

#include "app_common.hpp"
#include "config_store.hpp"
#include "download_mgr.hpp"
#include "identity.hpp"
#include "mqtt_io.hpp"
#include "ui_port.hpp"

#include "display_ctrl.hpp"

extern lv_obj_t *dynamic_epd_image;

static const char *TAG = "app";

struct display_state_t {
	std::mutex mutex;
	bool active;
	std::string data_path;
	uint32_t cmd_id;
};

static display_state_t s_state;
static TaskHandle_t s_display_task_handle = NULL;

static void display_update_task(void *arg)
{
	// 1. Allocate a persistent 80,000-byte raw RGB565 canvas in external PSRAM
	const size_t RGB565_SIZE = 80000;
	static uint8_t *sd_pixel_buffer = (uint8_t *)heap_caps_malloc(RGB565_SIZE, MALLOC_CAP_SPIRAM);
	assert(sd_pixel_buffer != NULL);
	memset(sd_pixel_buffer, 0xFF, RGB565_SIZE); // Default to a pure white canvas

	// 2. Set up our static descriptor wrapper pointing to our unpacked canvas area
	static lv_image_dsc_t sd_dynamic_bmp;
	sd_dynamic_bmp.header.magic = LV_IMAGE_HEADER_MAGIC;
	sd_dynamic_bmp.header.cf = LV_COLOR_FORMAT_RGB565;
	sd_dynamic_bmp.header.flags = 0;
	sd_dynamic_bmp.header.w = 200;
	sd_dynamic_bmp.header.h = 200;
	sd_dynamic_bmp.header.stride = 400;
	sd_dynamic_bmp.header.reserved_2 = 0;
	sd_dynamic_bmp.data_size = RGB565_SIZE;
	sd_dynamic_bmp.data = sd_pixel_buffer;

	for (;;)
	{
		/* Block indefinitely until notified by the download manager task  */
		xTaskNotifyWait(0, 0, NULL, portMAX_DELAY);

		bool should_update = false;
		std::string file_path;
		{
			std::lock_guard<std::mutex> lock(s_state.mutex);
			if (s_state.active)
			{
				should_update = true;
				file_path = s_state.data_path;
				s_state.active = false;
			}
		}

		if (should_update)
		{
			ESP_LOGI(TAG, "Unpacking 41KB I8 Asset from SD Card: %s", file_path.c_str());

			FILE *f = fopen(file_path.c_str(), "rb");
			if (f != NULL)
			{
				// Step A: Skip the 12-byte LVGL header (we already know it's a 200x200 I8 file)
				fseek(f, 12, SEEK_SET);

				// Step B: Read the 1,024-byte Color Palette Table (256 colors * 4 bytes/color)
				uint8_t palette[1024];
				fread(palette, 1, 1024, f);

				// Step C: Allocate temporary scratchpad memory to read the 40,000 pixel indices
				uint8_t *indices = (uint8_t *)heap_caps_malloc(40000, MALLOC_CAP_SPIRAM);
				if (indices != NULL)
				{
					fread(indices, 1, 40000, f);
					fclose(f); // Close file handle immediately
					f = NULL;

					// Step D: Translate the 8-bit index values to standard 16-bit RGB565 pixels
					uint16_t *rgb565_dest = (uint16_t *)sd_pixel_buffer;
					for (int i = 0; i < 40000; i++)
					{
						uint8_t idx = indices[i];

						// Extract individual Blue, Green, Red bytes from the 32-bit palette entry
						uint8_t b = palette[idx * 4 + 0];
						uint8_t g = palette[idx * 4 + 1];
						uint8_t r = palette[idx * 4 + 2];

						// Pack them into standard 16-bit RGB565 bit arrangements
						rgb565_dest[i] = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
					}
					free(indices); // Clean up index scratchpad array

					ESP_LOGI(TAG, "Unpacking complete. Pushing canvas to widget container...");

					// 3. Lock the UI thread before updating live graphics elements
					if (ui_lock(-1))
					{
						if (dynamic_epd_image != NULL)
						{
							// Force reset and apply our unpacked memory canvas resource
							lv_image_set_src(dynamic_epd_image, NULL);
							lv_image_set_src(dynamic_epd_image, &sd_dynamic_bmp);

							// Unhide and target the layout boundaries for a refresh cycle
							lv_obj_clear_flag(dynamic_epd_image, LV_OBJ_FLAG_HIDDEN);
							lv_obj_invalidate(dynamic_epd_image);
						}
						else
						{
							ESP_LOGE(TAG, "Widget Error: global variable 'dynamic_epd_image' is NULL! ");
						}

						ui_unlock(); // Release the thread mutex lock
					}
				}
				else
				{
					ESP_LOGE(TAG, "Memory Allocation Error: Scratchpad index buffer failed.");
				}

				if (f != NULL) fclose(f);
			}
			else
			{
				ESP_LOGE(TAG, "File System Error: Unable to open file path: %s ", file_path.c_str());
			}
		}
		vTaskDelay(pdMS_TO_TICKS(10));
	}
}

void display_ctrl::handle_command(const char *payload)
{
	ESP_LOGI(TAG, "Display command received");

	cJSON *json = cJSON_Parse(payload);
	if (!json) {
		ESP_LOGE(TAG, "Display: invalid JSON");
		return;
	}

	cJSON *download = cJSON_GetObjectItemCaseSensitive(json, "download");
	cJSON *filename = cJSON_GetObjectItemCaseSensitive(json, "filename");

	if (!cJSON_IsString(download) || !cJSON_IsString(filename)) {
		ESP_LOGW(TAG, "Display command missing 'download' or 'filename'");
		cJSON_Delete(json);
		return;
	}

	ESP_LOGI(TAG, "Display download: %s -> %s", download->valuestring, filename->valuestring);
	download::log_heap_info("handle_display_command");

	// Enqueue download if URL is present
	if (download->valuestring[0] == 'h') {
		if (!download::enqueue(download->valuestring, filename->valuestring, app::DownloadTarget::DISPLAY)) {
			ESP_LOGE(TAG, "Display: download queue full, dropping command");
		}
	}

	// Set display state
	{
		std::lock_guard<std::mutex> lock(s_state.mutex);
		s_state.active = true;
		s_state.data_path = "/sdcard/" + std::string(filename->valuestring);
	}

	cJSON_Delete(json);
}

void display_ctrl::notify_downloaded(bool success, const std::string &filepath)
{
	if (!success)
	{
		ESP_LOGE(TAG, "Failed to get file: %s", filepath.c_str());
		return;
	}

	ESP_LOGI(TAG, "Updating display state with new data path: %s", filepath.c_str());
	{
		std::lock_guard<std::mutex> lock(s_state.mutex);
		s_state.data_path = filepath;
		s_state.active = true;
	}
	config_store_save();
	if (s_display_task_handle != NULL)
	{
		ESP_LOGI(TAG, "Notifying display task of new data path: %s", filepath.c_str());
		xTaskNotifyGive(s_display_task_handle);
	}
}

std::string display_ctrl::data_path_get(void)
{
	std::lock_guard<std::mutex> lock(s_state.mutex);
	return s_state.data_path;
}

void display_ctrl::data_path_set(const std::string &path)
{
	std::lock_guard<std::mutex> lock(s_state.mutex);
	s_state.data_path = path;
	s_state.active = true;
}

void display_ctrl::boot_kick_if_active(void)
{
	bool active;
	{
		std::lock_guard<std::mutex> lock(s_state.mutex);
		active = s_state.active;
	}
	if (active && s_display_task_handle != NULL)
	{
		ESP_LOGI(TAG, "Boot configuration detected! Priming display loop...");
		xTaskNotifyGive(s_display_task_handle);
	}
}

void display_ctrl::init(void)
{
	mqtt_register_cmd(identity_topic_cmd_display(), display_ctrl::handle_command);
	download::set_target_handler(app::DownloadTarget::DISPLAY, display_ctrl::notify_downloaded);
}

void display_ctrl::start(void)
{
	xTaskCreate(display_update_task, "display_update", 4096, NULL, 4, &s_display_task_handle);
}