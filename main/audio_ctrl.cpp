#include <cstdio>
#include <cstring>
#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"

#include "cJSON.h"

#include "audio_bsp.h"
#include "codec_init.h"

#include "app_common.hpp"
#include "download_mgr.hpp"
#include "identity.hpp"
#include "mqtt_io.hpp"

#include "audio_ctrl.hpp"

static const char *TAG = "app";

struct audio_state_t {
	std::mutex mutex;
	bool active;
	char filename[64];
	uint8_t volume;
	uint32_t cmd_id;
};

static audio_state_t s_state;
static TaskHandle_t s_audio_task_handle = NULL;

static void audio_playback_task(void *arg)
{
	ESP_LOGI(TAG, "Audio playback task started");

	audio_bsp_init();
	esp_codec_dev_sample_info_t fs = {};
	fs.sample_rate = 16000;
	fs.channel = 2;
	fs.bits_per_sample = 16;
	esp_codec_dev_handle_t playback = get_playback_handle();

	for (;;)
	{
		xTaskNotifyWait(0, 0, NULL, portMAX_DELAY);

		bool should_play = false;
		char filename[64] = {0};
		uint8_t volume = 80;
		{
			std::lock_guard<std::mutex> lock(s_state.mutex);
			if (s_state.active)
			{
				should_play = true;
				strncpy(filename, s_state.filename, sizeof(filename) - 1);
				volume = s_state.volume;
				s_state.active = false;
			}
		}

		if (!should_play)
			continue;

		ESP_LOGI(TAG, "Audio play: %s (vol=%d)", filename, volume);
		esp_codec_dev_set_out_vol(playback, (float)volume);

		if (strcmp(filename, "boot") == 0)
		{
			extern const uint8_t music_pcm_start[] asm("_binary_canon_pcm_start");
			extern const uint8_t music_pcm_end[]   asm("_binary_canon_pcm_end");
			size_t pcm_size = music_pcm_end - music_pcm_start;
			uint8_t *pcm_ptr = (uint8_t *)music_pcm_start;

			if (esp_codec_dev_open(playback, &fs) == ESP_CODEC_DEV_OK)
			{
				size_t written = 0;
				while (written < pcm_size)
				{
					esp_codec_dev_write(playback, pcm_ptr + written, 256);
					written += 256;
				}
			}
			esp_codec_dev_close(playback);
			ESP_LOGI(TAG, "Boot sound playback complete");
		}
		else
		{
			std::string file_path = "/sdcard/" + std::string(filename);
			FILE *f = fopen(file_path.c_str(), "rb");
			if (f == NULL)
			{
				ESP_LOGE(TAG, "Audio: cannot open %s", file_path.c_str());
				continue;
			}

			if (esp_codec_dev_open(playback, &fs) == ESP_CODEC_DEV_OK)
			{
				uint8_t buf[1024];
				size_t bytes_read;
				while ((bytes_read = fread(buf, 1, sizeof(buf), f)) > 0)
				{
					esp_codec_dev_write(playback, buf, bytes_read);
				}
			}
			esp_codec_dev_close(playback);
			fclose(f);
			ESP_LOGI(TAG, "Audio file playback complete: %s", file_path.c_str());
		}
	}
}

void audio_ctrl::handle_command(const char *payload)
{
	ESP_LOGI(TAG, "Audio command received");

	cJSON *json = cJSON_Parse(payload);
	if (!json) {
		ESP_LOGE(TAG, "Audio: invalid JSON");
		return;
	}

	cJSON *download = cJSON_GetObjectItemCaseSensitive(json, "download");
	cJSON *filename = cJSON_GetObjectItemCaseSensitive(json, "filename");
	cJSON *volume = cJSON_GetObjectItemCaseSensitive(json, "volume");

	if (!cJSON_IsString(download) || !cJSON_IsString(filename)) {
		ESP_LOGW(TAG, "Audio command missing 'download' or 'filename'");
		cJSON_Delete(json);
		return;
	}

	ESP_LOGI(TAG, "Audio download: %s -> %s", download->valuestring, filename->valuestring);

	if (cJSON_IsNumber(volume)) {
		std::lock_guard<std::mutex> lock(s_state.mutex);
		s_state.volume = (uint8_t)volume->valueint;
	}

	// Enqueue download if URL is present
	if (download->valuestring[0] == 'h') {
		if (!download::enqueue(download->valuestring, filename->valuestring, app::DownloadTarget::AUDIO)) {
			ESP_LOGE(TAG, "Audio: download queue full, dropping command");
		}
	} else {
		// No download URL — file already on SD card, play directly
		std::lock_guard<std::mutex> lock(s_state.mutex);
		strncpy(s_state.filename, filename->valuestring, sizeof(s_state.filename) - 1);
		s_state.filename[sizeof(s_state.filename) - 1] = '\0';
		s_state.active = true;

		if (s_audio_task_handle != NULL) {
			xTaskNotifyGive(s_audio_task_handle);
		}
	}

	cJSON_Delete(json);
}

void audio_ctrl::notify_downloaded(bool success, const std::string &filepath)
{
	if (!success)
	{
		ESP_LOGE(TAG, "Failed to get file: %s", filepath.c_str());
		return;
	}

	ESP_LOGI(TAG, "Updating audio state with new file: %s", filepath.c_str());
	std::string filename = filepath;
	size_t slash = filename.rfind('/');
	if (slash != std::string::npos)
	{
		filename = filename.substr(slash + 1);
	}
	{
		std::lock_guard<std::mutex> lock(s_state.mutex);
		strncpy(s_state.filename, filename.c_str(), sizeof(s_state.filename) - 1);
		s_state.filename[sizeof(s_state.filename) - 1] = '\0';
		s_state.active = true;
	}
	if (s_audio_task_handle != NULL)
	{
		ESP_LOGI(TAG, "Notifying audio task of new file: %s", s_state.filename);
		xTaskNotifyGive(s_audio_task_handle);
	}
}

void audio_ctrl::init(void)
{
	mqtt_register_cmd(identity_topic_cmd_audio(), audio_ctrl::handle_command);
	download::set_target_handler(app::DownloadTarget::AUDIO, audio_ctrl::notify_downloaded);
}

void audio_ctrl::start(void)
{
	xTaskCreate(audio_playback_task, "audio_play", 8192, NULL, 4, &s_audio_task_handle);
}