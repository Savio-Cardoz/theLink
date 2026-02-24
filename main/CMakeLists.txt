idf_component_register(SRCS "app_main.c"
                    INCLUDE_DIRS "."
                    REQUIRES json mbedtls driver esp_http_client esp-tls nvs_flash esp_event esp_wifi wifi_provisioning)
