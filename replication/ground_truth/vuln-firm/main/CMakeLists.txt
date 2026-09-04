idf_component_register(
    SRCS "gateway_core.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_wifi spiffs nvs_flash lwip
)