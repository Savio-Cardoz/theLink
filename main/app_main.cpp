#include <string>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "driver/gpio.h"

#include "user_config.h"
#include "user_app.h"
#include "sdcard_manager.hpp"

#include "app_common.hpp"
#include "audio_ctrl.hpp"
#include "config_store.hpp"
#include "display_ctrl.hpp"
#include "download_mgr.hpp"
#include "identity.hpp"
#include "led_ctrl.hpp"
#include "ota_ctrl.hpp"
#include "provisioning.hpp"
#include "sensor_ctrl.hpp"
#include "status_ctrl.hpp"
#include "time_ctrl.hpp"
#include "ui_port.hpp"

static const char *TAG = "app";

#define RESET_BUTTON_GPIO   GPIO_NUM_3  // Factory-reset / re-provision button
#define BUTTON_PRESSED_LEVEL 0           // Active-low configuration

/**
 * @brief Checks if the reset button is being held down at boot.
 * @return true if pressed, false otherwise.
 */
static bool check_reset_button_at_boot(void)
{
	gpio_config_t io_conf = {};
	io_conf.intr_type = GPIO_INTR_DISABLE;
	io_conf.mode = GPIO_MODE_INPUT;
	io_conf.pin_bit_mask = (1ULL << RESET_BUTTON_GPIO);
	io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
	io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
	gpio_config(&io_conf);

	// Allow the lines to settle and give the user a tiny 200ms window
	// to make sure they are intentionally holding the button down
	vTaskDelay(pdMS_TO_TICKS(200));

	if (gpio_get_level(RESET_BUTTON_GPIO) == BUTTON_PRESSED_LEVEL)
	{
		ESP_LOGW("RESET", "Reset button detected down at power-up! Holding for confirmation...");
		// Optional: Wait an extra second to avoid accidental triggers
		vTaskDelay(pdMS_TO_TICKS(1000));
		return (gpio_get_level(RESET_BUTTON_GPIO) == BUTTON_PRESSED_LEVEL);
	}

	return false;
}

/**
 * @brief Starts the subsystems that have nothing to do with provisioning.
 *
 * Deliberately NOT called at boot. While the provisioning BLE transport is up
 * the BT controller has taken ~90 KB of internal RAM out of a pool that
 * esp_wifi_init() had already cut by ~37 KB, leaving only a few hundred bytes
 * of contiguous DMA-capable memory. Measured on the ESP32-S3 during a
 * prov-scan session:
 *
 *   after network_prov_mgr_start_provisioning  BTCAP largest_blk = 22528
 *   BLE connected (pre-keygen)                 BTCAP largest_blk =  544
 *   session established (pre prov-scan)        BTCAP largest_blk =  336
 *
 * At 336 contiguous bytes the station cannot allocate the RX buffers needed to
 * accept an association response, so Wi-Fi association fails with
 * "Wi-Fi station authentication failed" even though the credentials are right.
 * The same exhaustion makes AES-GCM response encryption (esp_aes) and the BT
 * controller's own allocations fail, which is why the SSID list never arrives.
 *
 * These tasks are deferred until the station has an IP, so they never compete
 * with BTDM. Ordering below is load-bearing:
 *   - sensor_ctrl claims the shared I2C bus, so it must go first;
 *   - audio_ctrl and time_ctrl both attach to that same bus.
 */
static void start_deferred_subsystems(void)
{
	// Must run before audio_ctrl::start(): the codec board support installs the
	// I2C bus itself when it finds none, so the first caller wins. Claiming it
	// here, off the app_main boot path, keeps that single-threaded.
	sensor_ctrl::start();
	audio_ctrl::start();

	// Must run after config_store_load() and after the event loop exists, so the
	// timezone it restores is not overwritten by the compiled-in default. The RTC
	// is on the same bus sensor_ctrl just claimed, so it comes second.
	time_ctrl::start();
}

extern "C" void app_main(void)
{

	// Derive device ID from the factory-programmed base MAC address.
	// Must run before MQTT or any topic-dependent code.
	identity_init();

	// Sensible defaults + MQTT/download/on-connect registrations so every
	// subsystem is wired before the provisioning task can bring up Wi-Fi.
	led_ctrl::init();
	display_ctrl::init();
	audio_ctrl::init();
	ota_ctrl::init();
	status_ctrl::init();
	sensor_ctrl::init();
	time_ctrl::init();

	user_app_init();
	user_app_display_init();

	download::log_heap_info("after user_app_init");

	bool dynamic_factory_reset = check_reset_button_at_boot();

	if (dynamic_factory_reset)
	{
		ESP_LOGW(TAG, "=================================================");
		ESP_LOGW(TAG, "FACTORY RESET TRIGGERED! Wiping system profiles...");
		ESP_LOGW(TAG, "=================================================");

		// This completely wipes the default NVS partition where credentials live
		ESP_ERROR_CHECK(nvs_flash_erase());
	}

	SDCardConfig sd_config;
	sd_config.mountPoint = SD_MOUNT_POINT;
	sd_config.maxOpenFiles = 5;
	sd_config.allocationUnitSize = 16 * 1024;
	sd_config.pinCmd = SDMMC_CMD_PIN;
	sd_config.pinClk = SDMMC_CLK_PIN;
	sd_config.pinD0 = SDMMC_D0_PIN;

	IFileSystem *sdcard = new SDCardManager(sd_config);
	app::set_sdcard(sdcard);

	if (sdcard->mount())
	{
		ESP_LOGI(TAG, "SD card mounted successfully. You can now perform file operations.");
		config_store_load();
	}
	else
	{
		ESP_LOGE(TAG, "Failed to mount SD card. Check the connections and try again.");
	}

	download::log_heap_info("after SD mount + config_store_load");

	/* Epaper display initialization */
	ui_port_init();

	download::log_heap_info("after ui_port_init");

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

	/* Handle OTA cycle results from the factory app (mark VALID, clear stale intents) */
	ota_ctrl::init_boot_state();

	/* Initialize TCP/IP */
	ESP_ERROR_CHECK(esp_netif_init());

	/*
	 * The probes from here to display_ctrl::start() bracket the single largest
	 * internal-memory drop on boot (~74 KB observed on the ESP32-S3). Without
	 * them that whole window is unaccounted for and there is no way to tell
	 * Wi-Fi driver static buffers from LVGL. esp_wifi_init() is the prime
	 * suspect: the static RX/TX/mgmt buffers it allocates are never freed
	 * until esp_wifi_deinit(), and BLE provisioning then has to share what
	 * is left with the AES DMA descriptors and the BT controller.
	 */
	download::log_heap_info("after esp_netif_init");

	/* Initialize the event loop */
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	download::log_heap_info("after esp_event_loop_create_default");

	/* Register our event handler for Wi-Fi, IP and Provisioning related events */
	provisioning_register_core_events();

	/* Initialize Wi-Fi including netif with default config */
	esp_netif_create_default_wifi_sta();
#ifdef CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP
	esp_netif_create_default_wifi_ap();
#endif /* CONFIG_EXAMPLE_PROV_TRANSPORT_SOFTAP */

	download::log_heap_info("after esp_netif_create_default_wifi_sta");

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));

	download::log_heap_info("after esp_wifi_init");

	// 1. Initialize the UI and create widgets FIRST while holding the lock.
	//    MUST run before the provisioning task spawns: user_ui_init() calls
	//    lv_obj_clean(lv_screen_active()), which would delete the QR widget
	//    pushed by wifi_prov_task if the ordering were reversed.
	if (ui_lock(-1))
	{
		user_ui_init(); // <--- Instantiates 'dynamic_epd_image' safely!

		ui_create_wifi_icon();

		ui_unlock();
	}

	// 2. Start the display/LED feedback before provisioning: the QR overlay the
	//    user scans is drawn on this stack, and the LED pulses report provisioning
	//    progress, so both are provisioning-related and stay up.
	xTaskCreatePinnedToCore(example_lvgl_port_task, "LVGL", 8192, NULL, 4, NULL, 1);
	led_ctrl::start();
	download::log_heap_info("after led_ctrl::start");
	display_ctrl::start();
	xTaskCreate(ui_overlay_task, "ui_overlay", 4096, NULL, 4, NULL);
	download::log_heap_info("after display_ctrl::start");
	display_ctrl::boot_kick_if_active();

	// 3. Now start provisioning (WiFi/BLE) after display is ready. Audio,
	//    sensors and the RTC are started by start_deferred_subsystems() once the
	//    station has an IP -- see the comment on that function.
	provisioning_set_post_provision_hook(start_deferred_subsystems);
	provisioning_start();
	download::log_heap_info("after provisioning_start");
}