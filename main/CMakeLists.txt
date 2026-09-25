idf_component_register(SRCS "app_common.cpp" "app_main.cpp" "audio_ctrl.cpp" "config_store.cpp"
                    "display_ctrl.cpp" "download_mgr.cpp" "identity.cpp" "led_ctrl.cpp"
                    "mqtt_io.cpp" "ota_ctrl.cpp" "provisioning.cpp" "rgb_color.cpp"
                    "ui_port.cpp" "data_downloader.cpp" "wifi.c" "wifi_no.c"
                    INCLUDE_DIRS "./"
                    REQUIRES led_strip sdcard_manager esp_http_client user_app nvs_flash mqtt json mqtt_logger audio_bsp app_update network_provisioning qrcode esp_timer esp_wifi esp_netif esp_event
                    PRIV_REQUIRES codec_board
)