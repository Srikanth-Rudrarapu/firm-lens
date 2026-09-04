#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"

static const char *TAG = "FIRMLENS_TARGET";

// --- STATIC VULNERABILITY SIGNATURES ---
__attribute__((used)) static const char* ec_priv_key = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...";
__attribute__((used)) static const char* hardcoded_pwd = "Admin@12345!"; 
__attribute__((used)) static const char* crypto_sig_1 = "@E (%d) %s: Setting aes key error, key_len: %d";
__attribute__((used)) static const char* ipv4_1 = "127.0.0.1";
__attribute__((used)) static const char* cleartext_mqtt = "mqtt://%s:%d";
__attribute__((used)) static const char* hidden_uri = "/config";
__attribute__((used)) static const uint8_t xor_obfuscation_table[8] = { 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55 };

// --- VULNERABLE UART LISTENER ---
void vulnerable_uart_listener(void *arg) {
    uart_config_t uart_config = {
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    uart_param_config(UART_NUM_0, &uart_config);
    uart_set_pin(UART_NUM_0, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_NUM_0, 1024 * 2, 0, 0, NULL, 0);

    uint8_t *data = (uint8_t *) malloc(1024);
    ESP_LOGW(TAG, "UART Attack Surface Ready.");

    while (1) {
        int len = uart_read_bytes(UART_NUM_0, data, 1023, 20 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = '\0';
            char stack_buffer[32];
            strcpy(stack_buffer, (char*)data); // CWE-120
            printf(stack_buffer); // CWE-134
            printf("\n");
        }
    }
}

// --- VULNERABLE WI-FI TCP SERVER ---
static void vulnerable_tcp_server(void *pvParameters) {
    char rx_buffer[1024];
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80);

    int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
    bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    listen(listen_sock, 1);
    
    ESP_LOGW(TAG, "Wi-Fi TCP Attack Surface Ready on Port 80.");

    while (1) {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        
        if (sock < 0) continue;

        int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len > 0) {
            rx_buffer[len] = 0;
            char target_buffer[64];
            
            // Network-based Buffer Overflow
            strcpy(target_buffer, rx_buffer);
            printf(target_buffer); // The Format String Detonator
            printf("\n");
            
            ESP_LOGI(TAG, "Processed TCP payload of length: %d", len);
        }
        close(sock);
    }
}

// --- INITIALIZATION ---
void app_main(void) {
    ESP_LOGI(TAG, "FirmLens Hybrid Target Booting...");
    
    // Initialize NVS (Required for Wi-Fi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    
    // Initialize Wi-Fi Access Point
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = "FirmLens_Target",
            .ssid_len = strlen("FirmLens_Target"),
            .channel = 1,
            .password = "firmware123",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    esp_wifi_start();

    // Launch both attack surfaces
    xTaskCreate(vulnerable_uart_listener, "uart_task", 4096, NULL, 5, NULL);
    xTaskCreate(vulnerable_tcp_server, "tcp_task", 4096, NULL, 5, NULL);
}