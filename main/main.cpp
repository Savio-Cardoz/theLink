

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "user_app.h"
#include "lvgl.h"
#include "user_config.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_err.h"

// Wifi provisioning includes
#include <string.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <nvs_flash.h>
#include <network_provisioning/manager.h>
#include <network_provisioning/scheme_ble.h>
#include "qrcode.h"

#include "mqtt_client.h"

#include "freertos/queue.h"
#include "cJSON.h" // Strongly recommended for parsing the MQTT payload
// External reference to the class we built in the previous step
// Make sure you include the header where AsyncDownloader is defined
#include "data_downloader.hpp"

#include "sdcard_manager.hpp"
#include "user_config.h"

#define MAX_URL_LEN 256
#define MAX_FILE_LEN 64

// The structure passed through the FreeRTOS Queue
typedef struct
{
	char url[MAX_URL_LEN];
	char filename[MAX_FILE_LEN];
} DownloadCommand_t;

typedef struct instructions_struct
{
	bool active;
	std::string data_path;
	uint32_t run_interval;
	bool repeat;
	std::string message;
} instructions_t;

instructions_t display_instructions;
instructions_t rgb_instructions;
instructions_t audio_instructions;
instructions_t notification_instructions;

TaskHandle_t display_task_handle = NULL;
TaskHandle_t rgb_task_handle = NULL;
TaskHandle_t audio_task_handle = NULL;
TaskHandle_t notification_task_handle = NULL;

// Global Handle for the Queue
static QueueHandle_t download_cmd_queue = NULL;

extern lv_obj_t *dynamic_epd_image;

static const char *TAG = "app";

// Wifi provisioning definitions
#if CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
#define PROV_SEC2_USERNAME "wifiprov"
#define PROV_SEC2_PWD "abcd1234"

/* This salt,verifier has been generated for username = "wifiprov" and password = "abcd1234"
 * IMPORTANT NOTE: For production cases, this must be unique to every device
 * and should come from device manufacturing partition.*/
static const char sec2_salt[] = {
	0x03, 0x6e, 0xe0, 0xc7, 0xbc, 0xb9, 0xed, 0xa8, 0x4c, 0x9e, 0xac, 0x97, 0xd9, 0x3d, 0xec, 0xf4};

static const char sec2_verifier[] = {
	0x7c, 0x7c, 0x85, 0x47, 0x65, 0x08, 0x94, 0x6d, 0xd6, 0x36, 0xaf, 0x37, 0xd7, 0xe8, 0x91, 0x43,
	0x78, 0xcf, 0xfd, 0x61, 0x6c, 0x59, 0xd2, 0xf8, 0x39, 0x08, 0x12, 0x72, 0x38, 0xde, 0x9e, 0x24,
	0xa4, 0x70, 0x26, 0x1c, 0xdf, 0xa9, 0x03, 0xc2, 0xb2, 0x70, 0xe7, 0xb1, 0x32, 0x24, 0xda, 0x11,
	0x1d, 0x97, 0x18, 0xdc, 0x60, 0x72, 0x08, 0xcc, 0x9a, 0xc9, 0x0c, 0x48, 0x27, 0xe2, 0xae, 0x89,
	0xaa, 0x16, 0x25, 0xb8, 0x04, 0xd2, 0x1a, 0x9b, 0x3a, 0x8f, 0x37, 0xf6, 0xe4, 0x3a, 0x71, 0x2e,
	0xe1, 0x27, 0x86, 0x6e, 0xad, 0xce, 0x28, 0xff, 0x54, 0x46, 0x60, 0x1f, 0xb9, 0x96, 0x87, 0xdc,
	0x57, 0x40, 0xa7, 0xd4, 0x6c, 0xc9, 0x77, 0x54, 0xdc, 0x16, 0x82, 0xf0, 0xed, 0x35, 0x6a, 0xc4,
	0x70, 0xad, 0x3d, 0x90, 0xb5, 0x81, 0x94, 0x70, 0xd7, 0xbc, 0x65, 0xb2, 0xd5, 0x18, 0xe0, 0x2e,
	0xc3, 0xa5, 0xf9, 0x68, 0xdd, 0x64, 0x7b, 0xb8, 0xb7, 0x3c, 0x9c, 0xfc, 0x00, 0xd8, 0x71, 0x7e,
	0xb7, 0x9a, 0x7c, 0xb1, 0xb7, 0xc2, 0xc3, 0x18, 0x34, 0x29, 0x32, 0x43, 0x3e, 0x00, 0x99, 0xe9,
	0x82, 0x94, 0xe3, 0xd8, 0x2a, 0xb0, 0x96, 0x29, 0xb7, 0xdf, 0x0e, 0x5f, 0x08, 0x33, 0x40, 0x76,
	0x52, 0x91, 0x32, 0x00, 0x9f, 0x97, 0x2c, 0x89, 0x6c, 0x39, 0x1e, 0xc8, 0x28, 0x05, 0x44, 0x17,
	0x3f, 0x68, 0x02, 0x8a, 0x9f, 0x44, 0x61, 0xd1, 0xf5, 0xa1, 0x7e, 0x5a, 0x70, 0xd2, 0xc7, 0x23,
	0x81, 0xcb, 0x38, 0x68, 0xe4, 0x2c, 0x20, 0xbc, 0x40, 0x57, 0x76, 0x17, 0xbd, 0x08, 0xb8, 0x96,
	0xbc, 0x26, 0xeb, 0x32, 0x46, 0x69, 0x35, 0x05, 0x8c, 0x15, 0x70, 0xd9, 0x1b, 0xe9, 0xbe, 0xcc,
	0xa9, 0x38, 0xa6, 0x67, 0xf0, 0xad, 0x50, 0x13, 0x19, 0x72, 0x64, 0xbf, 0x52, 0xc2, 0x34, 0xe2,
	0x1b, 0x11, 0x79, 0x74, 0x72, 0xbd, 0x34, 0x5b, 0xb1, 0xe2, 0xfd, 0x66, 0x73, 0xfe, 0x71, 0x64,
	0x74, 0xd0, 0x4e, 0xbc, 0x51, 0x24, 0x19, 0x40, 0x87, 0x0e, 0x92, 0x40, 0xe6, 0x21, 0xe7, 0x2d,
	0x4e, 0x37, 0x76, 0x2f, 0x2e, 0xe2, 0x68, 0xc7, 0x89, 0xe8, 0x32, 0x13, 0x42, 0x06, 0x84, 0x84,
	0x53, 0x4a, 0xb3, 0x0c, 0x1b, 0x4c, 0x8d, 0x1c, 0x51, 0x97, 0x19, 0xab, 0xae, 0x77, 0xff, 0xdb,
	0xec, 0xf0, 0x10, 0x95, 0x34, 0x33, 0x6b, 0xcb, 0x3e, 0x84, 0x0f, 0xb9, 0xd8, 0x5f, 0xb8, 0xa0,
	0xb8, 0x55, 0x53, 0x3e, 0x70, 0xf7, 0x18, 0xf5, 0xce, 0x7b, 0x4e, 0xbf, 0x27, 0xce, 0xce, 0xa8,
	0xb3, 0xbe, 0x40, 0xc5, 0xc5, 0x32, 0x29, 0x3e, 0x71, 0x64, 0x9e, 0xde, 0x8c, 0xf6, 0x75, 0xa1,
	0xe6, 0xf6, 0x53, 0xc8, 0x31, 0xa8, 0x78, 0xde, 0x50, 0x40, 0xf7, 0x62, 0xde, 0x36, 0xb2, 0xba};

#endif

static void log_error_if_nonzero(const char *message, int error_code)
{
	if (error_code != 0)
	{
		ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
	}
}

static esp_err_t example_get_sec2_salt(const char **salt, uint16_t *salt_len)
{
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
	ESP_LOGI(TAG, "Development mode: using hard coded salt");
	*salt = sec2_salt;
	*salt_len = sizeof(sec2_salt);
	return ESP_OK;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
	ESP_LOGE(TAG, "Not implemented!");
	return ESP_FAIL;
#endif
}

static esp_err_t example_get_sec2_verifier(const char **verifier, uint16_t *verifier_len)
{
#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
	ESP_LOGI(TAG, "Development mode: using hard coded verifier");
	*verifier = sec2_verifier;
	*verifier_len = sizeof(sec2_verifier);
	return ESP_OK;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
	/* This code needs to be updated with appropriate implementation to provide verifier */
	ESP_LOGE(TAG, "Not implemented!");
	return ESP_FAIL;
#endif
}
#endif

static SemaphoreHandle_t lvgl_mux = NULL;

#define BYTES_PER_PIXEL (LV_COLOR_FORMAT_GET_SIZE(LV_COLOR_FORMAT_RGB565))
#define BUFF_SIZE (EPD_WIDTH * EPD_HEIGHT * BYTES_PER_PIXEL)

/*lvgl tset unlock*/
static bool example_lvgl_lock(int timeout_ms);
static void example_lvgl_unlock(void);
static void example_lvgl_port_task(void *arg);
static void wifi_prov_task(void *arg);
#if 0
static void example_lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *color_p)
{
	uint16_t *buffer = (uint16_t *)color_p;
	// driver->EPD_Clear();
	for (int y = area->y1; y <= area->y2; y++)
	{
		for (int x = area->x1; x <= area->x2; x++)
		{
			uint8_t color = (*buffer < 0x7fff) ? DRIVER_COLOR_BLACK : DRIVER_COLOR_WHITE;
			driver->EPD_DrawColorPixel(x, y, color);
			buffer++;
		}
	}
	driver->EPD_DisplayPart();
	lv_disp_flush_ready(disp);
}
#endif

static void example_lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *color_p)
{
	uint16_t *buffer = (uint16_t *)color_p;

	// Telemetry log to verify the background task is executing this callback
	ESP_LOGI("FLUSH", "Rendering frame area: x1=%d, y1=%d to x2=%d, y2=%d",
			 area->x1, area->y1, area->x2, area->y2);

	// REMOVED: driver->EPD_Clear(); // Do not wipe the screen inside the rendering engine!

	int black_pixels = 0;
	int white_pixels = 0;

	for (int y = area->y1; y <= area->y2; y++)
	{
		for (int x = area->x1; x <= area->x2; x++)
		{
			uint16_t rgb565 = *buffer;

			// Extract color channels and scale them up to standard 8-bit values (0-255)
			uint8_t r = ((rgb565 >> 11) & 0x1F) << 3;
			uint8_t g = ((rgb565 >> 5) & 0x3F) << 2;
			uint8_t b = (rgb565 & 0x1F) << 3;

			// Calculate true human relative luminance (Grayscale brightness)
			uint8_t brightness = (r * 77 + g * 150 + b * 29) >> 8;

			// Map to black or white based on the midpoint threshold (128)
			uint8_t color;
			if (brightness < 128)
			{
				color = DRIVER_COLOR_BLACK;
				black_pixels++;
			}
			else
			{
				color = DRIVER_COLOR_WHITE;
				white_pixels++;
			}

			driver->EPD_DrawColorPixel(x, y, color);
			buffer++;
		}
	}

	// Log the pixel distribution so you know if the image is rendering dark or light elements
	ESP_LOGI("FLUSH", "Canvas Stats -> Packed Black: %d, Packed White: %d", black_pixels, white_pixels);

	// Push the final packed frame to the physical e-paper panel
	driver->EPD_DisplayPart();

	// Notify LVGL that the flush cycle is complete
	lv_disp_flush_ready(disp);
}

static void example_increase_lvgl_tick(void *arg)
{
	lv_tick_inc(EXAMPLE_LVGL_TICK_PERIOD_MS);
}

/* Signal Wi-Fi events on this event-group */
const int WIFI_CONNECTED_EVENT = BIT0;
static EventGroupHandle_t wifi_event_group;

#define PROV_QR_VERSION "v1"
#define PROV_TRANSPORT_SOFTAP "softap"
#define PROV_TRANSPORT_BLE "ble"
#define QRCODE_BASE_URL "https://espressif.github.io/esp-jumpstart/qrcode.html"

/* Event handler for catching system events */

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
			std::string fileStr(incoming_cmd.filename);

			// Trigger the download
			bool success = downloader.startDownload(urlStr, fileStr);

			if (!success)
			{
				ESP_LOGE(TAG, "Failed to start download. Is one already active?");
			}

			// Note: startDownload spawns its own FreeRTOS tasks and returns immediately.
			// If you only want one download at a time, you may need to add logic here
			// to wait until the downloader signals completion before accepting the next queue item.
		}
	}
}
static void event_handler(void *arg, esp_event_base_t event_base,
						  int32_t event_id, void *event_data)
{
	if (event_base == NETWORK_PROV_EVENT)
	{
		switch (event_id)
		{
		case NETWORK_PROV_START:
			ESP_LOGI(TAG, "Provisioning started");
			break;
		case NETWORK_PROV_WIFI_CRED_RECV:
		{
			wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *)event_data;
			ESP_LOGI(TAG, "Received Wi-Fi credentials"
						  "\n\tSSID     : %s\n\tPassword : %s",
					 (const char *)wifi_sta_cfg->ssid,
					 (const char *)wifi_sta_cfg->password);
			break;
		}
		case NETWORK_PROV_WIFI_CRED_FAIL:
		{
			network_prov_wifi_sta_fail_reason_t *reason = (network_prov_wifi_sta_fail_reason_t *)event_data;
			ESP_LOGE(TAG, "Provisioning failed!\n\tReason : %s"
						  "\n\tPlease reset to factory and retry provisioning",
					 (*reason == NETWORK_PROV_WIFI_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed" : "Wi-Fi access-point not found");
#ifdef CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE
			/* Reset the state machine on provisioning failure.
			 * This is enabled by the CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE configuration.
			 * It allows the provisioning manager to retry the provisioning process
			 * based on the number of attempts specified in wifi_conn_attempts. After attempting
			 * the maximum number of retries, the provisioning manager will reset the state machine
			 * and the provisioning process will be terminated.
			 */
			network_prov_mgr_reset_wifi_sm_state_on_failure();
#endif
			break;
		}
		case NETWORK_PROV_WIFI_CRED_SUCCESS:
			ESP_LOGI(TAG, "Provisioning successful");
			break;
		case NETWORK_PROV_END:
		{
			/* De-initialize manager once provisioning is finished */
			esp_err_t err = network_prov_mgr_deinit();
			if (err != ESP_OK)
			{
				ESP_LOGE(TAG, "Failed to de-initialize provisioning manager: %s", esp_err_to_name(err));
			}
			break;
		}
		default:
			break;
		}
	}
	else if (event_base == WIFI_EVENT)
	{
		switch (event_id)
		{
		case WIFI_EVENT_STA_START:
			esp_wifi_connect();
			break;
		case WIFI_EVENT_STA_DISCONNECTED:
			ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
			esp_wifi_connect();
			break;
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
		case WIFI_EVENT_AP_STACONNECTED:
			ESP_LOGI(TAG, "SoftAP transport: Connected!");
			break;
		case WIFI_EVENT_AP_STADISCONNECTED:
			ESP_LOGI(TAG, "SoftAP transport: Disconnected!");
			break;
#endif
		default:
			break;
		}
	}
	else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
	{
		ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
		ESP_LOGI(TAG, "Connected with IP Address:" IPSTR, IP2STR(&event->ip_info.ip));
		/* Signal main application to continue execution */
		xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_EVENT);
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
	}
	else if (event_base == PROTOCOMM_TRANSPORT_BLE_EVENT)
	{
		switch (event_id)
		{
		case PROTOCOMM_TRANSPORT_BLE_CONNECTED:
			ESP_LOGI(TAG, "BLE transport: Connected!");
			break;
		case PROTOCOMM_TRANSPORT_BLE_DISCONNECTED:
			ESP_LOGI(TAG, "BLE transport: Disconnected!");
			break;
		default:
			break;
		}
#endif
	}
	else if (event_base == PROTOCOMM_SECURITY_SESSION_EVENT)
	{
		switch (event_id)
		{
		case PROTOCOMM_SECURITY_SESSION_SETUP_OK:
			ESP_LOGI(TAG, "Secured session established!");
			break;
		case PROTOCOMM_SECURITY_SESSION_INVALID_SECURITY_PARAMS:
			ESP_LOGE(TAG, "Received invalid security parameters for establishing secure session!");
			break;
		case PROTOCOMM_SECURITY_SESSION_CREDENTIALS_MISMATCH:
			ESP_LOGE(TAG, "Received incorrect username and/or PoP for establishing secure session!");
			break;
		default:
			break;
		}
	}
}

/*
 * @brief Event handler registered to receive MQTT events
 *
 *  This function is called by the MQTT client event loop.
 *
 * @param handler_args user data registered to the event.
 * @param base Event base for the handler(always MQTT Base in this example).
 * @param event_id The id for the received event.
 * @param event_data The data for the event, esp_mqtt_event_handle_t.
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
		msg_id = esp_mqtt_client_subscribe(client, CONFIG_COMMAND_TOPIC, 2);
		ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d", msg_id);
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
		ESP_LOGI(TAG, "MQTT_EVENT_DATA");
		ESP_LOGI(TAG, "TOPIC=%.*s", event->topic_len, event->topic);
		ESP_LOGI(TAG, "DATA=%.*s", event->data_len, event->data);

		// Ensure the payload is null-terminated for parsing
		char *payload = (char *)malloc(event->data_len + 1);
		if (payload == NULL)
		{
			ESP_LOGE(TAG, "Failed to allocate memory for payload");
			return;
		}

		memcpy(payload, event->data, event->data_len);
		payload[event->data_len] = '\0';

		/* Parse JSON and pass to be processed based on command */
		cJSON *json = cJSON_Parse(payload);
		if (json == NULL)
		{
			ESP_LOGE(TAG, "Failed to parse JSON payload");
			free(payload);
			return;
		}

		// cJSON *command_item = cJSON_GetObjectItemCaseSensitive(json, "command");
		// if (!cJSON_IsString(command_item) || (command_item->valuestring == NULL))
		// {
		// 	ESP_LOGE(TAG, "Invalid or missing 'command' field in JSON");
		// 	cJSON_Delete(json);
		// 	free(payload);
		// 	return;
		// }

		cJSON *module_item = cJSON_GetObjectItemCaseSensitive(json, "module");
		if (cJSON_IsString(module_item) && strcmp(module_item->valuestring, "display") == 0)
		{
			ESP_LOGI(TAG, "Received display download command");
			display_instructions.active = true;
			display_instructions.data_path = "/sdcard/landing.png"; // Example path, adjust as needed
		}
		else if (cJSON_IsString(module_item) && strcmp(module_item->valuestring, "rgb") == 0)
		{
			ESP_LOGI(TAG, "Received RGB download command");
		}
		else if (cJSON_IsString(module_item) && strcmp(module_item->valuestring, "audio") == 0)
		{
			ESP_LOGI(TAG, "Received audio download command");
		}
		else if (cJSON_IsString(module_item) && strcmp(module_item->valuestring, "notification") == 0)
		{
			ESP_LOGI(TAG, "Received notification download command");
			cJSON *message_item = cJSON_GetObjectItemCaseSensitive(json, "message");
			if (cJSON_IsString(message_item) && strcmp(message_item->valuestring, "active_red") == 0)
			{
				ESP_LOGI(TAG, "Notification message: %s", message_item->valuestring);
				notification_instructions.active = true;
				notification_instructions.message = message_item->valuestring;
			}
			else
			{
				ESP_LOGW(TAG, "No valid 'message' field found for notification command");
			}
		}

		// cJSON *url_item = cJSON_GetObjectItemCaseSensitive(json, "url");
		// cJSON *file_item = cJSON_GetObjectItemCaseSensitive(json, "file");

		// if (cJSON_IsString(url_item) && cJSON_IsString(file_item))
		// {
		// 	DownloadCommand_t cmd;
		// 	memset(&cmd, 0, sizeof(DownloadCommand_t));

		// 	// strncpy(cmd.url, url_item->valuestring, MAX_URL_LEN - 1);
		// 	// strncpy(cmd.filename, file_item->valuestring, MAX_FILE_LEN - 1);

		// 	strncpy(cmd.url, "http://80.225.207.106/esp32_images/updates.json", MAX_URL_LEN - 1);
		// 	strncpy(cmd.filename, "/sdcard/updates.json", MAX_FILE_LEN - 1);

		// 	// Push to queue without blocking (timeout = 0)
		// 	if (xQueueSend(download_cmd_queue, &cmd, 0) != pdPASS)
		// 	{
		// 		ESP_LOGE(TAG, "Download queue is full! Dropping command.");
		// 	}
		// 	else
		// 	{
		// 		ESP_LOGI(TAG, "Download command enqueued successfully.");
		// 	}
		// }
		cJSON_Delete(json);
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

static void mqtt5_app_start(void)
{
	esp_mqtt_client_config_t mqtt5_cfg = {};
	mqtt5_cfg.broker.address.uri = CONFIG_BROKER_URL;
	// mqtt5_cfg.credentials.username = "123";
	// mqtt5_cfg.credentials.authentication.password = "456";
	mqtt5_cfg.session.last_will.topic = "/topic/will";
	mqtt5_cfg.session.last_will.msg = "i will leave";
	mqtt5_cfg.session.last_will.msg_len = 12;
	mqtt5_cfg.session.last_will.qos = 1;
	mqtt5_cfg.session.last_will.retain = true;
	mqtt5_cfg.session.protocol_ver = MQTT_PROTOCOL_V_5;

	esp_mqtt_client_handle_t client = esp_mqtt_client_init(&mqtt5_cfg);

	/* Set connection properties and user properties */
	// esp_mqtt5_client_set_user_property(&connect_property.user_property, user_property_arr, USE_PROPERTY_ARR_SIZE);
	// esp_mqtt5_client_set_user_property(&connect_property.will_user_property, user_property_arr, USE_PROPERTY_ARR_SIZE);
	// esp_mqtt5_client_set_connect_property(client, &connect_property);

	/* If you call esp_mqtt5_client_set_user_property to set user properties, DO NOT forget to delete them.
	 * esp_mqtt5_client_set_connect_property will malloc buffer to store the user_property and you can delete it after
	 */
	// esp_mqtt5_client_delete_user_property(connect_property.user_property);
	// esp_mqtt5_client_delete_user_property(connect_property.will_user_property);

	/* The last argument may be used to pass data to the event handler, in this example mqtt_event_handler */
	esp_mqtt_client_register_event(client, (esp_mqtt_event_id_t)ESP_EVENT_ANY_ID, mqtt5_event_handler, NULL);
	esp_mqtt_client_start(client);
}

static void wifi_init_sta(void)
{
	/* Start Wi-Fi in station mode */
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
}

static void get_device_service_name(char *service_name, size_t max)
{
	uint8_t eth_mac[6];
	const char *ssid_prefix = "PROV_";
	esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
	snprintf(service_name, max, "%s%02X%02X%02X",
			 ssid_prefix, eth_mac[3], eth_mac[4], eth_mac[5]);
}

/* Handler for the optional provisioning endpoint registered by the application.
 * The data format can be chosen by applications. Here, we are using plain ascii text.
 * Applications can choose to use other formats like protobuf, JSON, XML, etc.
 * Note that memory for the response buffer must be allocated using heap as this buffer
 * gets freed by the protocomm layer once it has been sent by the transport layer.
 */
esp_err_t custom_prov_data_handler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen,
								   uint8_t **outbuf, ssize_t *outlen, void *priv_data)
{
	if (inbuf)
	{
		ESP_LOGI(TAG, "Received data: %.*s", inlen, (char *)inbuf);
	}
	char response[] = "SUCCESS";
	*outbuf = (uint8_t *)strdup(response);
	if (*outbuf == NULL)
	{
		ESP_LOGE(TAG, "System out of memory");
		return ESP_ERR_NO_MEM;
	}
	*outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

	return ESP_OK;
}

static void wifi_prov_print_qr(const char *name, const char *username, const char *pop, const char *transport)
{
	if (!name || !transport)
	{
		ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
		return;
	}
	char payload[150] = {0};
	if (pop)
	{
#if CONFIG_EXAMPLE_PROV_SECURITY_VERSION_1
		snprintf(payload, sizeof(payload), "{\"ver\":\"%s\",\"name\":\"%s\""
										   ",\"pop\":\"%s\",\"transport\":\"%s\"}",
				 PROV_QR_VERSION, name, pop, transport);
#elif CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
		snprintf(payload, sizeof(payload), "{\"ver\":\"%s\",\"name\":\"%s\""
										   ",\"username\":\"%s\",\"pop\":\"%s\",\"transport\":\"%s\"}",
				 PROV_QR_VERSION, name, username, pop, transport);
#endif
	}
	else
	{
		snprintf(payload, sizeof(payload), "{\"ver\":\"%s\",\"name\":\"%s\""
										   ",\"transport\":\"%s\",\"network\":\"wifi\"}",
				 PROV_QR_VERSION, name, transport);
	}
	// TODO: Add the network protocol type to the QR code payload
#ifdef CONFIG_EXAMPLE_PROV_SHOW_QR
	ESP_LOGI(TAG, "Scan this QR code from the provisioning application for Provisioning.");
	esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
	esp_qrcode_generate(&cfg, payload);
#endif /* CONFIG_EXAMPLE_PROV_SHOW_QR */
	ESP_LOGI(TAG, "If QR code is not visible, copy paste the below URL in a browser.\n%s?data=%s", QRCODE_BASE_URL, payload);
}

#ifdef CONFIG_EXAMPLE_PROV_ENABLE_APP_CALLBACK
void wifi_prov_app_callback(void *user_data, wifi_prov_cb_event_t event, void *event_data)
{
	/**
	 * This is blocking callback, any configurations that needs to be set when a particular
	 * provisioning event is triggered can be set here.
	 */
	switch (event)
	{
	case WIFI_PROV_SET_STA_CONFIG:
	{
		/**
		 * Wi-Fi configurations can be set here before the Wi-Fi is enabled in
		 * STA mode.
		 */
		wifi_config_t *wifi_config = (wifi_config_t *)event_data;
		(void)wifi_config;
		break;
	}
	default:
		break;
	}
}

const wifi_prov_event_handler_t wifi_prov_event_handler = {
	.event_cb = wifi_prov_app_callback,
	.user_data = NULL,
};
#endif /* EXAMPLE_PROV_ENABLE_APP_CALLBACK */

void led_test_task(void *arg)
{
	gpio_config_t gpio_conf = {};
	gpio_conf.intr_type = GPIO_INTR_DISABLE;
	gpio_conf.mode = GPIO_MODE_OUTPUT;
	gpio_conf.pin_bit_mask = 0x1ULL << 3;
	gpio_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
	gpio_conf.pull_up_en = GPIO_PULLUP_ENABLE;

	ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_config(&gpio_conf));
	for (;;)
	{
		if (notification_instructions.active)
		{
			ESP_LOGI(TAG, "Activating red notification LED");
			for (int i = 0; i < 10; i++)
			{
				gpio_set_level((gpio_num_t)3, 0);
				vTaskDelay(pdMS_TO_TICKS(100));
				gpio_set_level((gpio_num_t)3, 1);
				vTaskDelay(pdMS_TO_TICKS(100));
			}
			notification_instructions.active = false; // Reset the flag after notification
		}
		else
		{
			vTaskDelay(pdMS_TO_TICKS(1000)); // Sleep for a while when not active
		}
	}
}

void display_update_task(void *arg)
{
	for (;;)
	{
		// 1. Check if the downloader has signaled a new image is ready
		if (display_instructions.active)
		{
			ESP_LOGI(TAG, "New image ready for display: %s", display_instructions.data_path.c_str());

			// 2. Lock the UI thread before touching LVGL
			if (example_lvgl_lock(-1))
			{
				if (dynamic_epd_image != NULL)
				{
					// 3. Format the path for LVGL (Prepend the LVGL Drive Letter 'A:')
					// Example: "/sdcard/new_image.png" becomes "A:/sdcard/new_image.png"
					std::string lvgl_path = "A:" + display_instructions.data_path;

					// 4. Set the new image source
					lv_image_set_src(dynamic_epd_image, lvgl_path.c_str());

					// 5. Unhide the widget if it was hidden at startup
					lv_obj_clear_flag(dynamic_epd_image, LV_OBJ_FLAG_HIDDEN);
				}

				// 6. Release the UI lock
				example_lvgl_unlock();
			}

			// 7. Reset the instruction flag so we don't reload it endlessly
			display_instructions.active = false;
		}

		// Sleep for 500ms before checking again (prevents CPU hogging)
		vTaskDelay(pdMS_TO_TICKS(500));
	}
}

extern "C" void app_main(void)
{
	user_app_init();

	SDCardConfig sd_config;
	sd_config.mountPoint = "/sdcard";
	sd_config.maxOpenFiles = 5;
	sd_config.allocationUnitSize = 16 * 1024;
	sd_config.pinCmd = SDMMC_CMD_PIN;
	sd_config.pinClk = SDMMC_CLK_PIN;
	sd_config.pinD0 = SDMMC_D0_PIN;

	IFileSystem *sdcard = new SDCardManager(sd_config);
	std::string fileContent;

	if (sdcard->mount())
	{
		ESP_LOGI(TAG, "SD card mounted successfully. You can now perform file operations.");
		// Use Posix style file reading as an example
		FILE *file = fopen("/sdcard/hello.txt", "r");
		if (file)
		{
			char buffer[128];
			while (fgets(buffer, sizeof(buffer), file))
			{
				fileContent += buffer;
			}
			fclose(file);
			ESP_LOGI(TAG, "Content of hello.txt:\n%s", fileContent.c_str());
		}
		else
		{
			ESP_LOGE(TAG, "Failed to open file on SD card.");
		}
	}
	else
	{
		ESP_LOGE(TAG, "Failed to mount SD card. Check the connections and try again.");
	}

	lv_init();
	lv_display_t *disp = lv_display_create(EPD_WIDTH, EPD_HEIGHT); /* 以水平和垂直分辨率（像素）进行基本初始化 */
	lv_display_set_flush_cb(disp, example_lvgl_flush_cb);
	uint8_t *buffer_1 = NULL;
	buffer_1 = (uint8_t *)heap_caps_malloc(BUFF_SIZE, MALLOC_CAP_SPIRAM);
	assert(buffer_1);
	lv_display_set_buffers(disp, buffer_1, NULL, BUFF_SIZE, LV_DISPLAY_RENDER_MODE_FULL);

	ESP_LOGI(TAG, "Install LVGL tick timer");
	esp_timer_create_args_t lvgl_tick_timer_args = {};
	lvgl_tick_timer_args.callback = &example_increase_lvgl_tick;
	lvgl_tick_timer_args.name = "lvgl_tick";
	esp_timer_handle_t lvgl_tick_timer = NULL;
	ESP_ERROR_CHECK(esp_timer_create(&lvgl_tick_timer_args, &lvgl_tick_timer));
	ESP_ERROR_CHECK(esp_timer_start_periodic(lvgl_tick_timer, EXAMPLE_LVGL_TICK_PERIOD_MS * 1000));

	lvgl_mux = xSemaphoreCreateMutex();
	assert(lvgl_mux);

	/* Initialize NVS partition */
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
	{
		/* NVS partition was truncated
		 * and needs to be erased */
		ESP_ERROR_CHECK(nvs_flash_erase());

		/* Retry nvs_flash_init */
		ESP_ERROR_CHECK(nvs_flash_init());
	}

	/* Initialize TCP/IP */
	ESP_ERROR_CHECK(esp_netif_init());

	/* Initialize the event loop */
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	wifi_event_group = xEventGroupCreate();

	/* Register our event handler for Wi-Fi, IP and Provisioning related events */
	ESP_ERROR_CHECK(esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
	ESP_ERROR_CHECK(esp_event_handler_register(PROTOCOMM_TRANSPORT_BLE_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
#endif
	ESP_ERROR_CHECK(esp_event_handler_register(PROTOCOMM_SECURITY_SESSION_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
	ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

	/* Initialize Wi-Fi including netif with default config */
	esp_netif_create_default_wifi_sta();
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
	esp_netif_create_default_wifi_ap();
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	xTaskCreate(wifi_prov_task, "wifi_prov", 4096, NULL, 5, NULL);
	xTaskCreatePinnedToCore(example_lvgl_port_task, "LVGL", 20 * 1024, NULL, 4, NULL, 1);
	xTaskCreate(led_test_task, "led_test", 4096, NULL, 5, &notification_task_handle);
	xTaskCreate(display_update_task, "display_update", 4096, NULL, 4, &display_task_handle);

	if (example_lvgl_lock(-1))
	{
		user_ui_init();
		example_lvgl_unlock();
	}
}

static bool example_lvgl_lock(int timeout_ms)
{
	const TickType_t timeout_ticks = (timeout_ms == -1) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
	return xSemaphoreTake(lvgl_mux, timeout_ticks) == pdTRUE;
}

static void example_lvgl_unlock(void)
{
	assert(lvgl_mux && "bsp_display_start must be called first");
	xSemaphoreGive(lvgl_mux);
}

static void example_lvgl_port_task(void *arg)
{
	uint32_t task_delay_ms = EXAMPLE_LVGL_TASK_MAX_DELAY_MS;
	for (;;)
	{
		if (example_lvgl_lock(-1))
		{
			task_delay_ms = lv_timer_handler();
			// Release the mutex
			example_lvgl_unlock();
		}
		if (task_delay_ms > EXAMPLE_LVGL_TASK_MAX_DELAY_MS)
		{
			task_delay_ms = EXAMPLE_LVGL_TASK_MAX_DELAY_MS;
		}
		else if (task_delay_ms < EXAMPLE_LVGL_TASK_MIN_DELAY_MS)
		{
			task_delay_ms = EXAMPLE_LVGL_TASK_MIN_DELAY_MS;
		}
		vTaskDelay(pdMS_TO_TICKS(task_delay_ms));
	}
}

static void wifi_prov_task(void *arg)
{
	/* Configuration for the provisioning manager */
	network_prov_mgr_config_t config = {
	/* What is the Provisioning Scheme that we want ?
	 * network_prov_scheme_softap or network_prov_scheme_ble */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		.scheme = network_prov_scheme_ble,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
		.scheme = network_prov_scheme_softap,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
#ifdef CONFIG_EXAMPLE_PROV_ENABLE_APP_CALLBACK
		.app_event_handler = wifi_prov_event_handler,
#endif /* EXAMPLE_PROV_ENABLE_APP_CALLBACK */

	/* Any default scheme specific event handler that you would
	 * like to choose. Since our example application requires
	 * neither BT nor BLE, we can choose to release the associated
	 * memory once provisioning is complete, or not needed
	 * (in case when device is already provisioned). Choosing
	 * appropriate scheme specific event handler allows the manager
	 * to take care of this automatically. This can be set to
	 * NETWORK_PROV_EVENT_HANDLER_NONE when using network_prov_scheme_softap*/
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		.scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
		.scheme_event_handler = NETWORK_PROV_EVENT_HANDLER_NONE,
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
#ifdef CONFIG_EXAMPLE_RESET_PROV_MGR_ON_FAILURE
		.network_prov_wifi_conn_cfg = {
			.wifi_conn_attempts = CONFIG_EXAMPLE_PROV_MGR_CONNECTION_CNT}
#endif
	};

	/* Initialize provisioning manager with the
	 * configuration parameters set above */
	ESP_ERROR_CHECK(network_prov_mgr_init(config));

	bool provisioned = false;
#ifdef CONFIG_EXAMPLE_RESET_PROVISIONED
	network_prov_mgr_reset_wifi_provisioning();
#else
	/* Let's find out if the device is provisioned */
	ESP_ERROR_CHECK(network_prov_mgr_is_wifi_provisioned(&provisioned));

#endif
	/* If device is not yet provisioned start provisioning service */
	if (!provisioned)
	{
		ESP_LOGI(TAG, "Starting provisioning");

		/* What is the Device Service Name that we want
		 * This translates to :
		 *     - Wi-Fi SSID when scheme is network_prov_scheme_softap
		 *     - device name when scheme is network_prov_scheme_ble
		 */
		char service_name[12];
		get_device_service_name(service_name, sizeof(service_name));

#ifdef CONFIG_EXAMPLE_PROV_SECURITY_VERSION_1
		/* What is the security level that we want (0, 1, 2):
		 *      - NETWORK_PROV_SECURITY_0 is simply plain text communication.
		 *      - NETWORK_PROV_SECURITY_1 is secure communication which consists of secure handshake
		 *          using X25519 key exchange and proof of possession (pop) and AES-CTR
		 *          for encryption/decryption of messages.
		 *      - NETWORK_PROV_SECURITY_2 SRP6a based authentication and key exchange
		 *        + AES-GCM encryption/decryption of messages
		 */
		network_prov_security_t security = NETWORK_PROV_SECURITY_1;

		/* Do we want a proof-of-possession (ignored if Security 0 is selected):
		 *      - this should be a string with length > 0
		 *      - NULL if not used
		 */
		const char *pop = "abcd1234";

		/* This is the structure for passing security parameters
		 * for the protocomm security 1.
		 */
		network_prov_security1_params_t *sec_params = pop;

		const char *username = NULL;

#elif CONFIG_EXAMPLE_PROV_SECURITY_VERSION_2
		network_prov_security_t security = NETWORK_PROV_SECURITY_2;
		/* The username must be the same one, which has been used in the generation of salt and verifier */

#if CONFIG_EXAMPLE_PROV_SEC2_DEV_MODE
		/* This pop field represents the password that will be used to generate salt and verifier.
		 * The field is present here in order to generate the QR code containing password.
		 * In production this password field shall not be stored on the device */
		const char *username = PROV_SEC2_USERNAME;
		const char *pop = PROV_SEC2_PWD;
#elif CONFIG_EXAMPLE_PROV_SEC2_PROD_MODE
		/* The username and password shall not be embedded in the firmware,
		 * they should be provided to the user by other means.
		 * e.g. QR code sticker */
		const char *username = NULL;
		const char *pop = NULL;
#endif
		/* This is the structure for passing security parameters
		 * for the protocomm security 2.
		 * If dynamically allocated, sec2_params pointer and its content
		 * must be valid till NETWORK_PROV_END event is triggered.
		 */
		network_prov_security2_params_t sec2_params = {};

		ESP_ERROR_CHECK(example_get_sec2_salt(&sec2_params.salt, &sec2_params.salt_len));
		ESP_ERROR_CHECK(example_get_sec2_verifier(&sec2_params.verifier, &sec2_params.verifier_len));

		network_prov_security2_params_t *sec_params = &sec2_params;
#endif
		/* What is the service key (could be NULL)
		 * This translates to :
		 *     - Wi-Fi password when scheme is network_prov_scheme_softap
		 *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
		 *     - simply ignored when scheme is network_prov_scheme_ble
		 */
		const char *service_key = NULL;

#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		/* This step is only useful when scheme is network_prov_scheme_ble. This will
		 * set a custom 128 bit UUID which will be included in the BLE advertisement
		 * and will correspond to the primary GATT service that provides provisioning
		 * endpoints as GATT characteristics. Each GATT characteristic will be
		 * formed using the primary service UUID as base, with different auto assigned
		 * 12th and 13th bytes (assume counting starts from 0th byte). The client side
		 * applications must identify the endpoints by reading the User Characteristic
		 * Description descriptor (0x2901) for each characteristic, which contains the
		 * endpoint name of the characteristic */
		uint8_t custom_service_uuid[] = {
			/* LSB <---------------------------------------
			 * ---------------------------------------> MSB */
			0xb4,
			0xdf,
			0x5a,
			0x1c,
			0x3f,
			0x6b,
			0xf4,
			0xbf,
			0xea,
			0x4a,
			0x82,
			0x03,
			0x04,
			0x90,
			0x1a,
			0x02,
		};

		/* If your build fails with linker errors at this point, then you may have
		 * forgotten to enable the BT stack or BTDM BLE settings in the SDK (e.g. see
		 * the sdkconfig.defaults in the example project) */
		network_prov_scheme_ble_set_service_uuid(custom_service_uuid);
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */

		/* An optional endpoint that applications can create if they expect to
		 * get some additional custom data during provisioning workflow.
		 * The endpoint name can be anything of your choice.
		 * This call must be made before starting the provisioning.
		 */
		network_prov_mgr_endpoint_create("custom-data");

		/* Do not stop and de-init provisioning even after success,
		 * so that we can restart it later. */
#ifdef CONFIG_EXAMPLE_REPROVISIONING
		network_prov_mgr_disable_auto_stop(1000);
#endif
		/* Start provisioning service */
		ESP_ERROR_CHECK(network_prov_mgr_start_provisioning(security, (const void *)sec_params, service_name, service_key));

		/* The handler for the optional endpoint created above.
		 * This call must be made after starting the provisioning, and only if the endpoint
		 * has already been created above.
		 */
		network_prov_mgr_endpoint_register("custom-data", custom_prov_data_handler, NULL);

		/* Uncomment the following to wait for the provisioning to finish and then release
		 * the resources of the manager. Since in this case de-initialization is triggered
		 * by the default event loop handler, we don't need to call the following */
		// network_prov_mgr_wait();
		// network_prov_mgr_deinit();
		/* Print QR code for provisioning */
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_BLE
		wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_BLE);
#else  /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */
		wifi_prov_print_qr(service_name, username, pop, PROV_TRANSPORT_SOFTAP);
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_BLE */
	}
	else
	{
		ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

		/* We don't need the manager as device is already provisioned,
		 * so let's release it's resources */
		ESP_ERROR_CHECK(network_prov_mgr_deinit());

		ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
		/* Start Wi-Fi station */
		wifi_init_sta();
	}

	/* Wait for Wi-Fi connection */
	xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, true, true, portMAX_DELAY);

	/* Start main application now */
#if CONFIG_EXAMPLE_REPROVISIONING
	while (1)
	{
		for (int i = 0; i < 10; i++)
		{
			ESP_LOGI(TAG, "Hello World!");
			vTaskDelay(1000 / portTICK_PERIOD_MS);
		}

		/* Resetting provisioning state machine to enable re-provisioning */
		network_prov_mgr_reset_wifi_sm_state_for_reprovision();

		/* Wait for Wi-Fi connection */
		xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_EVENT, true, true, portMAX_DELAY);
	}
#else

	// 1. Create the Queue (holds up to 5 commands)
	download_cmd_queue = xQueueCreate(5, sizeof(DownloadCommand_t));
	if (download_cmd_queue == NULL)
	{
		ESP_LOGE(TAG, "Failed to create download queue!");
		abort();
	}

	// 2. Spawn the Orchestrator Task
	xTaskCreate(download_orchestrator_task,
				"DlOrchestrator",
				4096,
				NULL,
				3, // Priority (lower than network, higher than idle)
				NULL);

	mqtt5_app_start();

	while (1)
	{
		ESP_LOGI(TAG, "Hello World!");
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
#endif
}
