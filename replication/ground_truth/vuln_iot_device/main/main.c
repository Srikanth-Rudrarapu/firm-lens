#include "device_config.h"
#include "crypto_ops.h"
#include "http_iface.h"
#include "build_info.h"
#include "mem_ops.h"
#include "session_mgr.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <nvs_flash.h>
#include <string.h>


void wifi_init(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_cfg = { 0 };
    strcpy((char *)wifi_cfg.sta.ssid, NET_SSID);
    strcpy((char *)wifi_cfg.sta.password, NET_PSK);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    esp_wifi_start();
}

void app_main(void) {
    nvs_flash_init();
    wifi_init();
    print_build_info();

    unsigned char out[32];
    stream_encrypt((unsigned char*)"plaintext-data-test", out, 20);



    start_http_iface();

    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
