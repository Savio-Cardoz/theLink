idf_component_register(SRCS "data_downloader.cpp" "main.cpp" "wifi.c" "wifi_no.c"
                    INCLUDE_DIRS "./"
                    REQUIRES led_strip sdcard_manager esp_http_client user_app nvs_flash mqtt json
)
