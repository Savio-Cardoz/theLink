idf_component_register(SRCS "app_main.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES epaper json mbedtls driver esp_http_client esp-tls nvs_flash esp_event esp_wifi wifi_provisioning)
