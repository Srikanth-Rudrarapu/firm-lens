#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "driver/uart.h"
#include "esp_wifi.h"

static const char *TAG = "IOT_NODE";

// --- Cloud Provisioning Constants ---
const char* cloud_provisioning_key = "AKIAIOSFODNN7EXAMPLE"; 
const char* backend_api_endpoint = "http://208.67.222.222/upload"; 
const char* fallback_diag_ip = "127.0.0.1";

const char* device_auth_cert = 
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Xi\n"
    "-----END RSA PRIVATE KEY-----\n";

const char* net_stack_build = "lwIP version 2.0.3";

const char* supported_cipher_suites[] = {
    "RSA with MD5", 
    "AES-128-CBC", 
    "md5-sess"
};

wifi_config_t factory_net_config = {
    .sta = {
        .ssid = "Corporate_Internal_Net",
        .password = "SuperSecretAdmin123!",
    },
};

// --- Hardware Initialization ---
void init_hardware_entropy() {
    char seed_buffer[] = {0x5A, 0x5B, 0x5C, 0x5D}; 
    char hw_mask = 0x2A; 
    for(int i=0; i<4; i++) {
        seed_buffer[i] ^= hw_mask;
    }
} 

// --- Diagnostic Web Server ---
static esp_err_t diag_endpoint_handler(httpd_req_t *req) {
    char render_buffer[1024];
    
    // Developer lazily passes the raw URI into the buffer
    sprintf(render_buffer, req->uri); 
    
    httpd_resp_send(req, render_buffer, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static const httpd_uri_t sys_diag_uri = {
    .uri       = "/config", 
    .method    = HTTP_GET,
    .handler   = diag_endpoint_handler,
    .user_ctx  = NULL
};

httpd_handle_t start_maintenance_server(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &sys_diag_uri);
    }
    return server;
}

// --- Serial Telemetry Interface ---
void telemetry_uart_task(void *arg) {
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_NUM_0, &uart_config);
    uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0);

    uint8_t serial_rx[1024];

    while (1) {
        int len = uart_read_bytes(UART_NUM_0, serial_rx, sizeof(serial_rx) - 1, 100 / portTICK_PERIOD_MS);
        if (len > 0) {
            serial_rx[len] = '\0'; 
            
            // =================================================================
            // FORCE HARDWARE CRASH FOR FIRMLENS TELEMETRY CAPTURE
            // This forces a StoreProhibited Panic when fuzzing input hits the port
            // =================================================================
            volatile int* hardware_fault_trigger = NULL;
            *hardware_fault_trigger = 0xDEADBEEF;
            // =================================================================

            char command_buffer[50]; 
            sprintf(command_buffer, (char*)serial_rx); 
            
            ESP_LOGI(TAG, "Command received via UART");
        }
    }
}

// --- Main Application ---
void app_main(void) {
    // Required string for the Python HIL monitor to synchronize
    printf("\nFirmLens HIL Target Active\n");
    
    // Disguised Anti-Optimization Anchors (Looks like a normal verbose boot sequence)
    ESP_LOGD(TAG, "Booting IoT Node. Net Stack: %s", net_stack_build);
    ESP_LOGD(TAG, "Provisioning Key [%s] mapping to %s", cloud_provisioning_key, backend_api_endpoint);
    ESP_LOGD(TAG, "Fallback IP routed to %s", fallback_diag_ip);
    ESP_LOGD(TAG, "Cert loaded: %15s...", device_auth_cert); 
    ESP_LOGD(TAG, "Connecting to SSID: %s (PSK: %s)", factory_net_config.sta.ssid, factory_net_config.sta.password);
    ESP_LOGD(TAG, "Negotiating ciphers: %s, %s, %s", supported_cipher_suites[0], supported_cipher_suites[1], supported_cipher_suites[2]);
    
    init_hardware_entropy();
    
    xTaskCreate(telemetry_uart_task, "telemetry", 4096, NULL, 10, NULL);
    start_maintenance_server();
}