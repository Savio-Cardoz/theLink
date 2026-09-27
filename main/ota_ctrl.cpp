#include <cstdio>
#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "nvs.h"

#include "cJSON.h"
#include "mqtt_logger.h"

#include "app_common.hpp"
#include "download_mgr.hpp"
#include "identity.hpp"
#include "mqtt_io.hpp"
#include "ui_port.hpp"

#include "ota_ctrl.hpp"

static const char *TAG = "app";

// ── OTA intent handshake (shared NVS namespace with esp32_factory_app) ──
//
// The factory (bootloader) app must NEVER flash /sdcard/update.bin on its
// own: it only flashes when this state says UPDATE_REQUESTED. The same
// namespace is used to pass the outcome of an update cycle back to this app.

#define OTA_NVS_NAMESPACE "ota"

typedef enum {
	OTA_STATE_NONE = 0,             // No cycle in progress
	OTA_STATE_UPDATE_REQUESTED = 1, // App asked factory to flash update.bin
	OTA_STATE_UPDATE_IN_PROGRESS = 2, // Factory is flashing
	OTA_STATE_UPDATE_DONE = 3,      // Factory flashed new app successfully
	OTA_STATE_UPDATE_FAILED = 4,    // Factory refused / aborted
	OTA_STATE_UPDATE_RESTORED = 5,  // Backup restored after failed test
} ota_state_t;

typedef enum {
	OTA_REASON_NONE = 0,
	OTA_REASON_BAD_FILE = 1,
	OTA_REASON_FLASH_FAILED = 2,
	OTA_REASON_BACKUP_FAILED = 3,
	OTA_REASON_NO_BACKUP = 4,
} ota_fail_reason_t;

static esp_err_t ota_nvs_state_set(uint8_t state, uint8_t reason)
{
	nvs_handle_t h;
	esp_err_t err = nvs_open(OTA_NVS_NAMESPACE, NVS_READWRITE, &h);
	if (err != ESP_OK)
	{
		return err;
	}
	err = nvs_set_u8(h, "state", state);
	if (err == ESP_OK)
	{
		err = nvs_set_u8(h, "reason", reason);
	}
	if (err == ESP_OK)
	{
		err = nvs_commit(h);
	}
	nvs_close(h);
	return err;
}

static esp_err_t ota_nvs_state_get(uint8_t *state, uint8_t *reason)
{
	*state = OTA_STATE_NONE;
	*reason = OTA_REASON_NONE;

	nvs_handle_t h;
	esp_err_t err = nvs_open(OTA_NVS_NAMESPACE, NVS_READONLY, &h);
	if (err == ESP_ERR_NVS_NOT_FOUND)
	{
		return ESP_OK;
	}
	if (err != ESP_OK)
	{
		return err;
	}
	if (nvs_get_u8(h, "state", state) == ESP_OK)
	{
		/* read ok */
	}
	if (nvs_get_u8(h, "reason", reason) == ESP_OK)
	{
		/* read ok */
	}
	nvs_close(h);
	return ESP_OK;
}

static void publish_ota_event(const char *status, const char *detail)
{
	cJSON *root = cJSON_CreateObject();
	if (root == nullptr)
	{
		return;
	}
	cJSON_AddStringToObject(root, "status", status);
	if (detail != nullptr)
	{
		cJSON_AddStringToObject(root, "detail", detail);
	}

	char *payload = cJSON_Print(root);
	if (payload != nullptr)
	{
		app::mqtt_publish(identity_topic_evt_ota(), payload, 1, 0);
		free(payload);
	}
	cJSON_Delete(root);
}

// Publish the pending OTA outcome (DONE / RESTORED / FAILED) once MQTT is up,
// then clear the handshake back to NONE. Returns true if an event was sent.
static bool ota_publish_pending_event(void)
{
	uint8_t state = OTA_STATE_NONE;
	uint8_t reason = OTA_REASON_NONE;
	ota_nvs_state_get(&state, &reason);

	if (state == OTA_STATE_NONE)
	{
		return false;
	}

	const char *status = nullptr;
	const char *detail = nullptr;
	switch (state)
	{
	case OTA_STATE_UPDATE_DONE:
		status = "update_success";
		detail = "new firmware validated";
		break;
	case OTA_STATE_UPDATE_RESTORED:
		status = "update_restored";
		detail = "previous firmware restored after failed test";
		break;
	case OTA_STATE_UPDATE_FAILED:
		status = "failed";
		switch (reason)
		{
		case OTA_REASON_BAD_FILE: detail = "invalid update.bin"; break;
		case OTA_REASON_FLASH_FAILED: detail = "flash failed"; break;
		case OTA_REASON_BACKUP_FAILED: detail = "backup failed"; break;
		case OTA_REASON_NO_BACKUP: detail = "no backup available"; break;
		default: detail = "update failed"; break;
		}
		break;
	case OTA_STATE_UPDATE_REQUESTED:
	case OTA_STATE_UPDATE_IN_PROGRESS:
	default:
		status = "failed";
		detail = "update aborted before completion";
		break;
	}

	ota_nvs_state_set(OTA_STATE_NONE, OTA_REASON_NONE);
	publish_ota_event(status, detail);
	return true;
}

static void handle_firmware_update(const std::string &filepath)
{
	ESP_LOGI(TAG, "Firmware update download complete: %s", filepath.c_str());

	// Locate the partition the bootloader app will flash (ota_0).
	const esp_partition_t *ota0 = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, nullptr);
	if (ota0 == nullptr)
	{
		ESP_LOGE(TAG, "Firmware update: ota_0 partition not found!");
		publish_ota_event("failed", "ota_0 partition missing");
		return;
	}

	// Quick sanity check before committing to the update.
	FILE *f = fopen(filepath.c_str(), "rb");
	if (f == nullptr)
	{
		ESP_LOGE(TAG, "Firmware update: cannot open %s", filepath.c_str());
		publish_ota_event("failed", "cannot open update file");
		return;
	}
	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fclose(f);

	if (file_size <= 0 || (size_t)file_size > ota0->size)
	{
		ESP_LOGE(TAG, "Firmware update: bad file size %ld (ota_0 max %u)", file_size, (unsigned)ota0->size);
		publish_ota_event("failed", "bad update file size");
		return;
	}

	// ESP-IDF app images start with the magic byte 0xE9.
	f = fopen(filepath.c_str(), "rb");
	if (f != nullptr)
	{
		uint8_t magic = 0;
		if (fread(&magic, 1, 1, f) != 1 || magic != 0xE9)
		{
			ESP_LOGE(TAG, "Firmware update: not a valid ESP-IDF app image (magic 0x%02X)", magic);
			fclose(f);
			publish_ota_event("failed", "invalid firmware image");
			return;
		}
		fclose(f);
	}

	ESP_LOGI(TAG, "Firmware update validated (%ld bytes). Showing update screen.", file_size);
	publish_ota_event("downloaded", filepath.c_str());

	ui_show_update_screen();

	// Give the e-paper time to finish the full refresh before rebooting.
	vTaskDelay(pdMS_TO_TICKS(4000));

	// Point the ROM bootloader at the factory (bootloader) app.
	const esp_partition_t *bootloader_part = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, nullptr);
	if (bootloader_part == nullptr)
	{
		ESP_LOGE(TAG, "Firmware update: factory partition not found!");
		publish_ota_event("failed", "factory partition missing");
		return;
	}

	// Record the update intent in NVS so the factory app flashes ONLY when an
	// update was actually requested (never a stale /sdcard/update.bin).
	esp_err_t nvs_err = ota_nvs_state_set(OTA_STATE_UPDATE_REQUESTED, OTA_REASON_NONE);
	if (nvs_err != ESP_OK)
	{
		ESP_LOGE(TAG, "Firmware update: failed to record update intent (%s)", esp_err_to_name(nvs_err));
		publish_ota_event("failed", "cannot record update intent");
		return;
	}

	esp_err_t err = esp_ota_set_boot_partition(bootloader_part);
	if (err != ESP_OK)
	{
		ESP_LOGE(TAG, "Firmware update: esp_ota_set_boot_partition failed (%s)", esp_err_to_name(err));
		publish_ota_event("failed", esp_err_to_name(err));
		return;
	}

	ESP_LOGI(TAG, "Firmware update: boot partition set to factory. Rebooting into bootloader.");
	mqtt_logger_publish_direct(MQTT_LOG_INFO, TAG, "Firmware update ready. Rebooting into bootloader.");
	publish_ota_event("rebooting", "bootloader");

	vTaskDelay(pdMS_TO_TICKS(500));
	esp_restart();
}

void ota_ctrl::handle_command(const char *payload)
{
	ESP_LOGI(TAG, "OTA command received");

	cJSON *json = cJSON_Parse(payload);
	if (!json) {
		ESP_LOGE(TAG, "OTA: invalid JSON");
		return;
	}

	cJSON *download = cJSON_GetObjectItemCaseSensitive(json, "download");
	cJSON *version = cJSON_GetObjectItemCaseSensitive(json, "version");

	if (!cJSON_IsString(download) || download->valuestring == NULL) {
		ESP_LOGW(TAG, "OTA command missing valid 'download' URL");
		cJSON_Delete(json);
		return;
	}

	ESP_LOGI(TAG, "OTA firmware: %s (version=%s)",
			 download->valuestring,
			 (cJSON_IsString(version) && version->valuestring != NULL) ? version->valuestring : "?");

	publish_ota_event("started", download->valuestring);

	// Reuse the bootloader app's fixed filename on the SD card.
	IFileSystem *sdcard = app::sdcard();
	if (sdcard != nullptr && sdcard->isMounted() && sdcard->fileExists("update.bin"))
	{
		sdcard->deleteFile("update.bin");
	}

	if (!download::enqueue(download->valuestring, "update.bin", app::DownloadTarget::FIRMWARE)) {
		ESP_LOGE(TAG, "OTA: download queue full, dropping command");
		publish_ota_event("failed", "queue full");
	}

	cJSON_Delete(json);
}

void ota_ctrl::firmware_downloaded(bool success, const std::string &filepath)
{
	if (!success)
	{
		ESP_LOGE(TAG, "Failed to get file: %s", filepath.c_str());
		return;
	}
	handle_firmware_update(filepath);
}

void ota_ctrl::init_boot_state(void)
{
	// Only relevant when an otadata partition exists (Prod layout).
	if (esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, nullptr) == nullptr)
	{
		return; // Dev build: no OTA, nothing to do.
	}

	uint8_t state = OTA_STATE_NONE;
	uint8_t reason = OTA_REASON_NONE;
	ota_nvs_state_get(&state, &reason);

	const esp_partition_t *running_part = esp_ota_get_running_partition();
	if (running_part != nullptr &&
		running_part->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MIN &&
		running_part->subtype <= ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
	{
		esp_ota_img_states_t running_state = ESP_OTA_IMG_UNDEFINED;
		if (esp_ota_get_state_partition(running_part, &running_state) == ESP_OK &&
			running_state == ESP_OTA_IMG_PENDING_VERIFY)
		{
			ESP_LOGI(TAG, "OTA first boot detected (PENDING_VERIFY) - confirming app is valid.");
			esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
			if (err != ESP_OK)
			{
				ESP_LOGE(TAG, "esp_ota_mark_app_valid_cancel_rollback failed (%s)", esp_err_to_name(err));
			}
		}
	}

	// A request that never reached the factory app must not linger: a later
	// boot into factory could otherwise flash a stale update.bin.
	if (state == OTA_STATE_UPDATE_REQUESTED || state == OTA_STATE_UPDATE_IN_PROGRESS)
	{
		ESP_LOGW(TAG, "OTA state %d was never completed by the factory app - clearing.", state);
		ota_nvs_state_set(OTA_STATE_NONE, OTA_REASON_NONE);
	}
}

void ota_ctrl::init(void)
{
	mqtt_register_cmd(identity_topic_cmd_ota(), ota_ctrl::handle_command);
	download::set_target_handler(app::DownloadTarget::FIRMWARE, ota_ctrl::firmware_downloaded);

	// Report any OTA cycle that completed while the network was down.
	app::register_on_connect([]()
		{
			ota_publish_pending_event();
		});
}