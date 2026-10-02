#include <assert.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

#include "lvgl.h"

#include "user_config.h"
#include "user_app.h"

#include "ui_port.hpp"

// Forward declarations (used by ui_port_init before their definitions).
static void example_increase_lvgl_tick(void *arg);
void example_lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *color_p);

// External Asset References
extern const lv_image_dsc_t wifi;    // Valid connection image asset
extern const lv_image_dsc_t wifi_no; // Missing connection image asset

static const char *TAG = "UI";

static SemaphoreHandle_t lvgl_mux = NULL;
static QueueHandle_t ui_event_queue = NULL;
static lv_obj_t *wifi_status_icon = NULL; // Overlay widget container

#define BYTES_PER_PIXEL (LV_COLOR_FORMAT_GET_SIZE(LV_COLOR_FORMAT_RGB565))
#define BUFF_SIZE (EPD_WIDTH * EPD_HEIGHT * BYTES_PER_PIXEL)

// 3. UI Status Event Definitions
typedef enum {
    UI_WIFI_DISCONNECTED,
    UI_WIFI_CONNECTED
} ui_event_type_t;

static ui_event_type_t wifi_status = ui_event_type_t::UI_WIFI_DISCONNECTED;

void ui_port_init(void)
{
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

	ui_event_queue = xQueueCreate(10, sizeof(ui_event_type_t));
}

void ui_create_wifi_icon(void)
{
	wifi_status_icon = lv_image_create(lv_screen_active());
	lv_image_set_src(wifi_status_icon, &wifi_no); // Default to disconnected

	// Push to the top right corner with a 10px breathing padding
	lv_obj_align(wifi_status_icon, LV_ALIGN_TOP_RIGHT, -10, 10);
}

bool ui_lock(int timeout_ms)
{
	const TickType_t timeout_ticks = (timeout_ms == -1) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
	return xSemaphoreTake(lvgl_mux, timeout_ticks) == pdTRUE;
}

void ui_unlock(void)
{
	assert(lvgl_mux && "bsp_display_start must be called first");
	xSemaphoreGive(lvgl_mux);
}

static void example_increase_lvgl_tick(void *arg)
{
	lv_tick_inc(EXAMPLE_LVGL_TICK_PERIOD_MS);
}

void example_lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *color_p)
{
	uint16_t *buffer = (uint16_t *)color_p;

	// 1. Detect if LVGL is commanding a full-screen draw (0,0 to 199,199)
	// or just a small, localized widget modification zone (like the Wi-Fi icon)
	bool is_full_refresh = (area->x1 == 0 && area->y1 == 0 && area->x2 == 199 && area->y2 == 199);

	if (is_full_refresh)
	{
		// Prime the controller for a FULL global blink cycle (prevents panel ghosting)
		driver->EPD_Init();
	}
	else
	{
		// Prime the controller for a silent, ultra-fast PARTIAL update loop
		driver->EPD_Init_Partial();
	}

	int black_pixels = 0;
	int white_pixels = 0;

	// This nested loop naturally handles partial frames because it only iterates
	// through the specific bounding box coordinates passed by the LVGL engine!
	for (int y = area->y1; y <= area->y2; y++)
	{
		for (int x = area->x1; x <= area->x2; x++)
		{
			uint16_t rgb565 = *buffer;

			uint8_t r = ((rgb565 >> 11) & 0x1F) << 3;
			uint8_t g = ((rgb565 >> 5) & 0x3F) << 2;
			uint8_t b = (rgb565 & 0x1F) << 3;

			uint8_t brightness = (r * 77 + g * 150 + b * 29) >> 8;

			uint8_t color = (brightness < 128) ? DRIVER_COLOR_BLACK : DRIVER_COLOR_WHITE;
			if (color == DRIVER_COLOR_BLACK)
			{
				black_pixels++;
			}
			else
			{
				white_pixels++;
			}

			driver->EPD_DrawColorPixel(x, y, color);
			buffer++;
		}
	}

	// 2. Commit the drawing data to the panel glass based on refresh type
	if (is_full_refresh)
	{
		ESP_LOGI("FLUSH", "Executing Global Full Refresh -> Black: %d, White: %d", black_pixels, white_pixels);
		driver->EPD_Display(); // Global flash refresh pass
	}
	else
	{
		ESP_LOGI("FLUSH", "Executing Silent Partial Refresh -> Black: %d, White: %d", black_pixels, white_pixels);
		driver->EPD_DisplayPart(); // Quick localized ink migration
	}

	lv_disp_flush_ready(disp); //
}

void ui_notify_network_status(bool connected)
{
	ui_event_type_t new_status = connected ? ui_event_type_t::UI_WIFI_CONNECTED : ui_event_type_t::UI_WIFI_DISCONNECTED;
	if (wifi_status == new_status)
	{
		return;
	}
	wifi_status = new_status;
	if (ui_event_queue)
	{
		xQueueSend(ui_event_queue, &wifi_status, 0);
	}
}

void ui_show_update_screen(void)
{
	ESP_LOGI(TAG, "Showing 'Update in progress' on display");

	if (ui_lock(-1))
	{
		lv_obj_t *scr = lv_screen_active();
		lv_obj_clean(scr);

		lv_obj_t *lbl = lv_label_create(scr);
		lv_label_set_text(lbl, "Update in\nprogress");
		lv_obj_set_style_text_font(lbl, LV_FONT_DEFAULT, 0);
		lv_obj_center(lbl);

		lv_obj_invalidate(scr);
		lv_refr_now(lv_display_get_default());

		ui_unlock();
	}
}

void example_lvgl_port_task(void *arg)
{
	uint32_t task_delay_ms = EXAMPLE_LVGL_TASK_MAX_DELAY_MS;
	for (;;)
	{
		if (ui_lock(-1))
		{
			task_delay_ms = lv_timer_handler();
			// Release the mutex
			ui_unlock();
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

void ui_overlay_task(void *arg)
{
    ui_event_type_t incoming_event;

    for (;;)
    {
        // Sleep indefinitely until a network event signals this queue
        if (xQueueReceive(ui_event_queue, &incoming_event, portMAX_DELAY) == pdTRUE)
        {
            // Always lock LVGL before mutating any live widgets
            if (ui_lock(-1))
            {
                if (wifi_status_icon != NULL)
                {
                    if (incoming_event == UI_WIFI_CONNECTED)
                    {
                        ESP_LOGI("UI_TASK", "Swapping icon source: WiFi Connected");
                        lv_image_set_src(wifi_status_icon, &wifi); // Apply active icon
                    }
                    else
                    {
                        ESP_LOGI("UI_TASK", "Swapping icon source: WiFi Disconnected");
                        lv_image_set_src(wifi_status_icon, &wifi_no); // Apply warning icon
                    }

                    // Force the widget to render the fresh source map
                    lv_obj_invalidate(wifi_status_icon);
                }
                ui_unlock(); // Always release the lock!
            }
        }
    }
}