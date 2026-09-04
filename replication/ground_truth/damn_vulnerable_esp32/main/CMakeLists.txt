idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_http_server nvs_flash esp_wifi mbedtls esp_driver_uart)