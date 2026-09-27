#include <cstring>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_log.h"
#include "esp_heap_caps.h"

#include "app_common.hpp"
#include "data_downloader.hpp"

#include "download_mgr.hpp"

#define MAX_URL_LEN 256
#define MAX_FILE_LEN 64

static const char *TAG = "app";

// The structure passed through the FreeRTOS Queue
struct DownloadCommand_t
{
	char url[MAX_URL_LEN];
	char filename[MAX_FILE_LEN];
	app::DownloadTarget target;
};

static QueueHandle_t download_cmd_queue = NULL;

using namespace app;

static download::DoneCallback s_target_handlers[3]; // indexed by DownloadTarget

void download::log_heap_info(const char *context)
{
	uint32_t total_free = esp_get_free_heap_size();
	uint32_t total_min = esp_get_minimum_free_heap_size();
	uint32_t int_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
	uint32_t int_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
	ESP_LOGI(TAG, "[HEAP] %s: total_free=%" PRIu32 ", total_min=%" PRIu32 " | INTERNAL free=%" PRIu32 ", largest_blk=%" PRIu32,
			 context, total_free, total_min, int_free, int_largest);
}

static void notify_download_handler(DownloadTarget target, bool success, const std::string &filepath)
{
	if (!success)
	{
		ESP_LOGE(TAG, "Failed to get file: %s", filepath.c_str());
		return;
	}

	size_t idx = static_cast<size_t>(target);
	if (idx < 3 && s_target_handlers[idx])
	{
		s_target_handlers[idx](success, filepath);
	}
}

static void download_orchestrator_task(void *arg)
{
	ESP_LOGI(TAG, "Download Orchestrator Task Started");

	AsyncDownloader downloader;
	DownloadCommand_t incoming_cmd;

	for (;;)
	{
		// Block indefinitely until a command arrives in the queue
		if (xQueueReceive(download_cmd_queue, &incoming_cmd, portMAX_DELAY) == pdTRUE)
		{
			ESP_LOGI(TAG, "Orchestrator received request: URL=%s, Target=%s",
					 incoming_cmd.url, incoming_cmd.filename);

			// Convert standard C arrays to std::string for the C++ class
			std::string urlStr(incoming_cmd.url);
			std::string fileStr("/sdcard/" + std::string(incoming_cmd.filename));

			IFileSystem *sdcard = app::sdcard();
			if (sdcard == nullptr || !sdcard->isMounted())
			{
				ESP_LOGE(TAG, "Cannot get %s: SD card is unavailable", incoming_cmd.filename);
				continue;
			}

			app::DownloadTarget dl_target = incoming_cmd.target;
			if (sdcard->fileExists(incoming_cmd.filename))
			{
				ESP_LOGI(TAG, "File already available at: %s", fileStr.c_str());
				notify_download_handler(dl_target, true, fileStr);
				continue;
			}

			download::log_heap_info("orchestrator before startDownload");
			ESP_LOGI(TAG, "%s not found. Starting download", fileStr.c_str());
			if (!downloader.startDownload(urlStr, fileStr, [dl_target](bool success, const std::string &filepath)
				{
					notify_download_handler(dl_target, success, filepath);
				}))
			{
				ESP_LOGE(TAG, "Failed to start download for file: %s", fileStr.c_str());
			}

			// Note: startDownload spawns its own FreeRTOS tasks and returns immediately.
			// If you only want one download at a time, you may need to add logic here
			// to wait until the downloader signals completion before accepting the next queue item.
		}
	}
}

void download::start(void)
{
	download_cmd_queue = xQueueCreate(5, sizeof(DownloadCommand_t));
	if (download_cmd_queue == NULL)
	{
		ESP_LOGE(TAG, "Failed to create download queue!");
		abort();
	}

	xTaskCreate(download_orchestrator_task,
				"DlOrchestrator",
				4096,
				NULL,
				3, // Priority (lower than network, higher than idle)
				NULL);
}

bool download::enqueue(const char *url, const char *filename, DownloadTarget target)
{
	if (download_cmd_queue == nullptr)
	{
		return false;
	}

	DownloadCommand_t cmd;
	memset(&cmd, 0, sizeof(cmd));
	strncpy(cmd.url, url, MAX_URL_LEN - 1);
	strncpy(cmd.filename, filename, MAX_FILE_LEN - 1);
	cmd.target = target;

	return xQueueSend(download_cmd_queue, &cmd, 0) == pdPASS;
}

void download::set_target_handler(DownloadTarget target, DoneCallback cb)
{
	size_t idx = static_cast<size_t>(target);
	if (idx < 3)
	{
		s_target_handlers[idx] = std::move(cb);
	}
}