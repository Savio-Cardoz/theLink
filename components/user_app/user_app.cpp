#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "user_app.h"
#include "driver/gpio.h"
#include "user_config.h"
#include "board_power_bsp.h"
#include "gui_guider.h"
#include "esp_log.h"
#include "esp_err.h"
#include "lvgl.h"

#include "driver/rtc_io.h"
#include "esp_sleep.h"

epaper_driver_display *driver = NULL;
board_power_bsp_t board_div(EPD_PWR_PIN, Audio_PWR_PIN, VBAT_PWR_PIN);

lv_ui src_ui;
lv_obj_t *dynamic_epd_image = NULL;
extern lv_display_t *disp;

void user_app_init(void)
{
    // board_div.VBAT_POWER_ON();
    board_div.POWEER_EPD_ON();
    board_div.POWEER_Audio_ON();
    /*epaper init*/
    custom_lcd_spi_t driver_config = {};
    driver_config.cs = EPD_CS_PIN;
    driver_config.dc = EPD_DC_PIN;
    driver_config.rst = EPD_RST_PIN;
    driver_config.busy = EPD_BUSY_PIN;
    driver_config.mosi = EPD_MOSI_PIN;
    driver_config.scl = EPD_SCK_PIN;
    driver_config.spi_host = EPD_SPI_NUM;
    driver_config.buffer_len = 5000;
    driver = new epaper_driver_display(EPD_WIDTH, EPD_HEIGHT, driver_config);
    driver->EPD_Init();
    driver->EPD_Clear();
    // driver->EPD_DisplayPartBaseImage();
    // driver->EPD_Init_Partial(); // 局部刷新初始化
}

void loop_lvgl_img(void *arg)
{
    lv_ui *ui = (lv_ui *)arg;
    for (;;)
    {
        lv_obj_clear_flag(ui->screen_img_1, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(ui->screen_img_2, LV_OBJ_FLAG_HIDDEN);
        vTaskDelay(pdMS_TO_TICKS(5000));
        lv_obj_clear_flag(ui->screen_img_2, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(ui->screen_img_1, LV_OBJ_FLAG_HIDDEN);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

void user_ui_init(void)
{
    // // Clear old test objects to establish a clean slate
    lv_obj_clean(lv_screen_active());

    dynamic_epd_image = lv_image_create(lv_screen_active());

    lv_obj_center(dynamic_epd_image);
}