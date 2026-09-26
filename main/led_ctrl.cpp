#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <mutex>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include <math.h>
#include <string.h>

#include "rgb_led_strip.h"
#include "user_config.h"

#include "app_common.hpp"
#include "config_store.hpp"
#include "identity.hpp"
#include "mqtt_io.hpp"
#include "rgb_color.hpp"
#include "provisioning.hpp"

#include "led_ctrl.hpp"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define RMT_LED_STRIP_GPIO_NUM gpio_num_t(RGB_LED_STRIP_PIN) // GPIO pin for the RGB LED strip

static const char *TAG = "app";

// ── LED state ───────────────────────────────────────────────────────

struct led_state_t {
	bool active;
	std::mutex mutex;
	rgb_pattern_t pattern;
	char pattern_name[32];
	uint16_t hue;             // base hue [0, 359]
	uint8_t saturation;       // [0, 100]
	uint8_t value;            // [0, 100]
	uint8_t brightness;       // global brightness scale [0, 100]
	uint32_t speed_ms;        // animation frame period [5, 5000] ms
	uint32_t duration_ms;     // auto-off deadline span; 0 = no auto-off
	uint64_t set_at_ms;       // esp_timer epoch (ms) when colour state was set
	bool has_pixels;          // per-pixel overrides active
	std::array<int32_t, app::LED_COUNT> pixels; // -1 = skip, else 0xRRGGBB
	uint32_t cmd_id;
};

static led_state_t led_state;
static uint32_t s_led_cmd_seq = 0;

static void led_state_init_defaults(void)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);
	led_state.active = false;
	led_state.pattern = rgb_pattern_t::SOLID_COLOR;
	led_state.pattern_name[0] = '\0';
	led_state.hue = 0;
	led_state.saturation = 100;
	led_state.value = 100;
	led_state.brightness = 100;
	led_state.speed_ms = 20;
	led_state.duration_ms = 0;
	led_state.set_at_ms = 0;
	led_state.has_pixels = false;
	led_state.pixels.fill(-1);
	led_state.cmd_id = 0;
}

static void set_notification_state(bool state)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);
	led_state.active = state;
}

static void set_notification_message(const std::string &message)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);
	strncpy(led_state.pattern_name, message.c_str(), sizeof(led_state.pattern_name) - 1);
	led_state.pattern_name[sizeof(led_state.pattern_name) - 1] = '\0';
	led_state.pattern = pattern_from_string(message);
}

// ── Publish canonical state ─────────────────────────────────────────

void led_ctrl::publish_status(void)
{
	cJSON *root = cJSON_CreateObject();
	if (root == nullptr)
	{
		return;
	}

	{
		std::lock_guard<std::mutex> lock(led_state.mutex);

		cJSON_AddBoolToObject(root, "active", led_state.active);
		cJSON_AddStringToObject(root, "pattern", pattern_to_string(led_state.pattern));

		cJSON *color = cJSON_CreateObject();
		cJSON_AddNumberToObject(color, "h", led_state.hue);
		cJSON_AddNumberToObject(color, "s", led_state.saturation);
		cJSON_AddNumberToObject(color, "v", led_state.value);
		cJSON_AddItemToObject(root, "color", color);

		cJSON_AddNumberToObject(root, "brightness", led_state.brightness);
		cJSON_AddNumberToObject(root, "speed", led_state.speed_ms);
		cJSON_AddNumberToObject(root, "cmd_id", led_state.cmd_id);

		if (led_state.has_pixels)
		{
			cJSON *pixels = cJSON_CreateArray();
			for (size_t i = 0; i < app::LED_COUNT; i++)
			{
				int32_t px = led_state.pixels[i];
				if (px < 0)
				{
					cJSON_AddItemToArray(pixels, cJSON_CreateNull());
				}
				else
				{
					char hex[10];
					snprintf(hex, sizeof(hex), "#%06X", (unsigned)px);
					cJSON_AddItemToArray(pixels, cJSON_CreateString(hex));
				}
			}
			cJSON_AddItemToObject(root, "pixels", pixels);
		}
	}

	char *payload = cJSON_Print(root);
	if (payload != nullptr)
	{
		app::mqtt_publish(identity_topic_evt_led(), payload, 1, 1);
		free(payload);
	}
	cJSON_Delete(root);
}

const char *led_ctrl::pattern_get(void)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);
	return pattern_to_string(led_state.pattern);
}

// ── Config.json integration ─────────────────────────────────────────

void led_ctrl::status_serialize(cJSON *led)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);

	cJSON_AddBoolToObject(led, "active", led_state.active);
	cJSON_AddStringToObject(led, "pattern", pattern_to_string(led_state.pattern));

	cJSON *color = cJSON_CreateObject();
	cJSON_AddNumberToObject(color, "h", led_state.hue);
	cJSON_AddNumberToObject(color, "s", led_state.saturation);
	cJSON_AddNumberToObject(color, "v", led_state.value);
	cJSON_AddItemToObject(led, "color", color);

	cJSON_AddNumberToObject(led, "brightness", led_state.brightness);
	cJSON_AddNumberToObject(led, "speed", led_state.speed_ms);

	if (led_state.has_pixels)
	{
		cJSON *pixels = cJSON_CreateArray();
		for (size_t i = 0; i < app::LED_COUNT; i++)
		{
			int32_t px = led_state.pixels[i];
			if (px < 0)
			{
				cJSON_AddItemToArray(pixels, cJSON_CreateNull());
			}
			else
			{
				char hex[10];
				snprintf(hex, sizeof(hex), "#%06X", (unsigned)px);
				cJSON_AddItemToArray(pixels, cJSON_CreateString(hex));
			}
		}
		cJSON_AddItemToObject(led, "pixels", pixels);
	}
}

void led_ctrl::status_apply_legacy_str(const char *str)
{
	set_notification_state(strcmp(str, "active") == 0);
	ESP_LOGI("CONFIG", "Restored notification LED state: %s", str);
}

void led_ctrl::status_apply(cJSON *led)
{
	std::lock_guard<std::mutex> lock(led_state.mutex);

	cJSON *a = cJSON_GetObjectItemCaseSensitive(led, "active");
	if (cJSON_IsBool(a))
	{
		led_state.active = cJSON_IsTrue(a);
	}

	cJSON *p = cJSON_GetObjectItemCaseSensitive(led, "pattern");
	if (cJSON_IsString(p) && p->valuestring != NULL)
	{
		led_state.pattern = pattern_from_string(p->valuestring);
		strncpy(led_state.pattern_name, p->valuestring, sizeof(led_state.pattern_name) - 1);
		led_state.pattern_name[sizeof(led_state.pattern_name) - 1] = '\0';
	}

	cJSON *c = cJSON_GetObjectItemCaseSensitive(led, "color");
	if (c != nullptr && !cJSON_IsNull(c))
	{
		led_color_t col = parse_led_color(c);
		if (col.valid)
		{
			led_state.hue = static_cast<uint16_t>(col.h);
			led_state.saturation = static_cast<uint8_t>(col.s);
			led_state.value = static_cast<uint8_t>(col.v);
		}
	}

	cJSON *b = cJSON_GetObjectItemCaseSensitive(led, "brightness");
	if (cJSON_IsNumber(b))
	{
		led_state.brightness = static_cast<uint8_t>(clamp_u(b->valueint, 0, 100));
	}

	cJSON *sp = cJSON_GetObjectItemCaseSensitive(led, "speed");
	if (cJSON_IsNumber(sp))
	{
		led_state.speed_ms = clamp_u(sp->valueint, 5, 5000);
	}

	cJSON *pix = cJSON_GetObjectItemCaseSensitive(led, "pixels");
	if (cJSON_IsArray(pix))
	{
		led_state.pixels.fill(-1);
		int wrote = 0;
		int n = cJSON_GetArraySize(pix);
		for (int i = 0; i < n && i < (int)app::LED_COUNT; i++)
		{
			cJSON *entry = cJSON_GetArrayItem(pix, i);
			if (cJSON_IsNull(entry))
			{
				continue;
			}
			led_color_t col = parse_led_color(entry);
			if (col.valid)
			{
				led_state.pixels[i] = ((int32_t)col.r << 16) | ((int32_t)col.g << 8) | (int32_t)col.b;
				wrote++;
			}
		}
		led_state.has_pixels = (wrote > 0);
	}

	ESP_LOGI("CONFIG", "Restored notification LED state object (active=%d, pattern=%s)",
			 led_state.active, pattern_to_string(led_state.pattern));
}

// ── MQTT command handlers ───────────────────────────────────────────

void led_ctrl::handle_notification_command(const char *payload)
{
	ESP_LOGI(TAG, "Notification command received");

	cJSON *json = cJSON_Parse(payload);
	if (!json) {
		ESP_LOGE(TAG, "Notification: invalid JSON");
		return;
	}

	cJSON *message = cJSON_GetObjectItemCaseSensitive(json, "message");
	if (cJSON_IsString(message) && message->valuestring != NULL) {
		ESP_LOGI(TAG, "Notification message: %s", message->valuestring);
		set_notification_message(std::string(message->valuestring));
		set_notification_state(true);
	} else {
		ESP_LOGW(TAG, "Notification command missing valid 'message' field");
	}

	cJSON_Delete(json);
}

void led_ctrl::handle_rgb_command(const char *payload)
{
	ESP_LOGI(TAG, "RGB command received");

	cJSON *json = cJSON_Parse(payload);
	if (!json) {
		ESP_LOGE(TAG, "RGB: invalid JSON");
		return;
	}

	bool has_any = false;
	bool persist = true;

	cJSON *enable = cJSON_GetObjectItemCaseSensitive(json, "enable");
	cJSON *pattern = cJSON_GetObjectItemCaseSensitive(json, "pattern");
	cJSON *color = cJSON_GetObjectItemCaseSensitive(json, "color");
	cJSON *brightness = cJSON_GetObjectItemCaseSensitive(json, "brightness");
	cJSON *speed = cJSON_GetObjectItemCaseSensitive(json, "speed");
	cJSON *duration = cJSON_GetObjectItemCaseSensitive(json, "duration");
	cJSON *pixels = cJSON_GetObjectItemCaseSensitive(json, "pixels");
	cJSON *persist_item = cJSON_GetObjectItemCaseSensitive(json, "persist");

	if (cJSON_IsBool(persist_item))
	{
		persist = cJSON_IsTrue(persist_item);
	}

	{
		std::lock_guard<std::mutex> lock(led_state.mutex);

		if (cJSON_IsBool(enable))
		{
			led_state.active = cJSON_IsTrue(enable);
			has_any = true;
		}

		if (cJSON_IsString(pattern) && pattern->valuestring != NULL)
		{
			led_state.pattern = pattern_from_string(pattern->valuestring);
			strncpy(led_state.pattern_name, pattern->valuestring, sizeof(led_state.pattern_name) - 1);
			led_state.pattern_name[sizeof(led_state.pattern_name) - 1] = '\0';
			has_any = true;
			if (!cJSON_IsBool(enable))
			{
				led_state.active = true;
			}
		}

		if (color != nullptr && !cJSON_IsNull(color))
		{
			led_color_t c = parse_led_color(color);
			if (c.valid)
			{
				led_state.hue = static_cast<uint16_t>(c.h);
				led_state.saturation = static_cast<uint8_t>(c.s);
				led_state.value = static_cast<uint8_t>(c.v);
				has_any = true;
			}
			else
			{
				ESP_LOGW(TAG, "RGB: invalid 'color' value");
			}
		}

		if (cJSON_IsNumber(brightness))
		{
			led_state.brightness = static_cast<uint8_t>(clamp_u(brightness->valueint, 0, 100));
			has_any = true;
		}

		if (cJSON_IsNumber(speed))
		{
			led_state.speed_ms = clamp_u(speed->valueint, 5, 5000);
			has_any = true;
		}

		if (cJSON_IsNumber(duration))
		{
			if (duration->valueint <= 0)
			{
				led_state.duration_ms = 0;
			}
			else
			{
				led_state.duration_ms = clamp_u(duration->valueint, 1, 3600) * 1000U;
			}
			led_state.set_at_ms = esp_timer_get_time() / 1000;
			has_any = true;
		}

		if (cJSON_IsArray(pixels))
		{
			int n = cJSON_GetArraySize(pixels);
			if (n > 0)
			{
				led_state.pixels.fill(-1);
				int wrote = 0;
				for (int i = 0; i < n && i < (int)app::LED_COUNT; i++)
				{
					cJSON *entry = cJSON_GetArrayItem(pixels, i);
					if (cJSON_IsNull(entry))
					{
						continue;
					}
					led_color_t c = parse_led_color(entry);
					if (c.valid)
					{
						led_state.pixels[i] = ((int32_t)c.r << 16) | ((int32_t)c.g << 8) | (int32_t)c.b;
						wrote++;
					}
				}
				led_state.has_pixels = (wrote > 0);
				has_any = true;
			}
		}

		if (has_any)
		{
			led_state.cmd_id = ++s_led_cmd_seq;
		}
	}

	if (!has_any)
	{
		ESP_LOGW(TAG, "RGB command missing valid fields");
		cJSON_Delete(json);
		return;
	}

	if (persist)
	{
		config_store_save();
	}
	led_ctrl::publish_status();

	cJSON_Delete(json);
}

// ── LED rendering task ──────────────────────────────────────────────

static void led_test_task(void *arg)
{
	RgbLedStrip<app::LED_COUNT> led_strip(RMT_LED_STRIP_GPIO_NUM);
	uint32_t phase = 0;
	uint64_t last_frame_ms = esp_timer_get_time() / 1000;
	uint32_t prov_pulse_ms = 0;

	for (;;)
	{
		const uint64_t now_ms = esp_timer_get_time() / 1000;

		// Provisioning pulsing takes priority over MQTT-driven LED control.
		const led_prov_state_t prov_state = prov_get_led_state();
		if (prov_state != led_prov_state_t::LED_PROV_STATE_NONE)
		{
			const uint32_t period_ms = prov_pulse_period_ms(prov_state);
			if (period_ms > 0)
			{
				// Soft breathing pulse peaking in the middle of each interval.
				prov_pulse_ms = (prov_pulse_ms + 50) % period_ms;
				const float frac = (float)prov_pulse_ms / (float)period_ms;
				const float brightness = 0.5f - 0.5f * cosf(2.0f * (float)M_PI * frac);
				led_strip.runPattern(rgb_pattern_t::SOLID_COLOR, PROV_PULSE_HUE, 100, (uint32_t)(100.0f * brightness));
			}

			vTaskDelay(pdMS_TO_TICKS(50));
			continue;
		}

		prov_pulse_ms = 0;

		// Auto-off once the configured duration has elapsed.
		bool expired = false;
		{
			std::lock_guard<std::mutex> lock(led_state.mutex);
			if (led_state.active && led_state.duration_ms > 0 &&
				now_ms >= led_state.set_at_ms + led_state.duration_ms)
			{
				led_state.active = false;
				expired = true;
			}
		}
		if (expired)
		{
			ESP_LOGI(TAG, "LED auto-off after duration");
			led_ctrl::publish_status();
		}

		bool active;
		rgb_pattern_t pattern;
		uint16_t hue;
		uint8_t saturation, value, brightness;
		bool has_pixels;
		std::array<int32_t, app::LED_COUNT> pixels;
		uint32_t speed_ms;
		{
			std::lock_guard<std::mutex> lock(led_state.mutex);
			active = led_state.active;
			pattern = led_state.pattern;
			hue = led_state.hue;
			saturation = led_state.saturation;
			value = led_state.value;
			brightness = led_state.brightness;
			has_pixels = led_state.has_pixels;
			pixels = led_state.pixels;
			speed_ms = led_state.speed_ms;
		}

		led_strip.setBrightness(brightness);

		if (!active || pattern == rgb_pattern_t::OFF)
		{
			led_strip.clear();
			phase = 0;
			last_frame_ms = now_ms;
			vTaskDelay(pdMS_TO_TICKS(50));
			continue;
		}

		if (has_pixels)
		{
			// Per-pixel overrides ignore the pattern generator.
			led_strip.setAllRgb(0, 0, 0);
			for (size_t i = 0; i < app::LED_COUNT; i++)
			{
				int32_t px = pixels[i];
				if (px < 0)
				{
					continue;
				}
				led_strip.setPixelRgb(i, (px >> 16) & 0xFF, (px >> 8) & 0xFF, px & 0xFF);
			}
			led_strip.flush();
		}
		else if (pattern == rgb_pattern_t::SOLID_COLOR)
		{
			// Hold the exact requested colour (no animation).
			led_strip.runPattern(rgb_pattern_t::SOLID_COLOR, hue, saturation, value);
			last_frame_ms = now_ms;
		}
		else
		{
			// Animate by advancing the hue/phase offset at the configured speed.
			if (now_ms - last_frame_ms >= speed_ms)
			{
				phase = (phase + 5) % 360;
				last_frame_ms = now_ms;
			}
			led_strip.runPattern(pattern, phase, saturation, value);
		}

		vTaskDelay(pdMS_TO_TICKS(10));
	}
}

// ── Module entry points ─────────────────────────────────────────────

void led_ctrl::init(void)
{
	led_state_init_defaults();

	mqtt_register_cmd(identity_topic_cmd_rgb(), led_ctrl::handle_rgb_command);
	mqtt_register_cmd(identity_topic_cmd_notification(), led_ctrl::handle_notification_command);

	// Re-publish the canonical retained LED state on connect.
	app::register_on_connect([]()
		{
			led_ctrl::publish_status();
		});
}

void led_ctrl::start(void)
{
	xTaskCreate(led_test_task, "led_test", 4096, NULL, 3, NULL);
}