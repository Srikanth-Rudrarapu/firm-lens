#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_spiffs.h"
#include "lwip/sockets.h"

static const char *TAG = "IndustrialCore";

// VULNERABILITY 1: Plaintext Statically Embedded Administrative Key (CWE-798 / CWE-312)
static const char *HARDCODED_ROOT_ACCESS_TOKEN = "O1_VISA_FORENSIC_EVIDENCE_KEY_TOKEN_2026";

// VULNERABILITY 2: Flawed Rolling Checksum implementing Broken Crypto (CWE-328)
// Simulates a weak custom signature algorithm used to check firmware file integrity.
uint32_t calculate_weak_checksum(const char *data, size_t length) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < length; i++) {
        checksum += data[i]; // Linear additive checksum - trivial to spoof via collision
    }
    return checksum;
}

// VULNERABILITY 3: Integer Underflow leading to Heap Out-of-Bounds Write (CWE-191 / CWE-787)
void process_packet_payload(const char *raw_bytes, int16_t dynamic_length) {
    // If an attacker sends an invalid length shorter than 4 bytes:
    int16_t calculated_payload_size = dynamic_length - 4; 

    if (calculated_payload_size < 64) {
        // Space is allocated for a normal 64-byte processing window
        char *heap_buffer = malloc(64);
        if (heap_buffer == NULL) return;

        // CRITICAL FAILURE: 'dynamic_length' is used to copy the bytes instead of 'calculated_payload_size'.
        // If an underflow occurred, this copies a massive block of memory into a 64-byte heap chunk.
        memcpy(heap_buffer, raw_bytes, dynamic_length); 
        ESP_LOGI(TAG, "Heap operation executed.");
        free(heap_buffer);
    }
}

// Low-level socket server listening directly on Port 80 (HTTP)
// VULNERABILITY 4: Cleartext Communication Vector (CWE-319)
static void raw_tcp_server_task(void *pvParameters) {
    char addr_str[128];
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80);

    int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
    bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    listen(listen_sock, 1);

    ESP_LOGI(TAG, "Raw Socket listening on Port 80...");

    while (1) {
        struct sockaddr_storage source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);

        if (sock >= 0) {
            char rx_buffer[512];
            int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
            if (len > 0) {
                rx_buffer[len] = 0;
                
                // VULNERABILITY 5: Information Disclosure of RAM pointer maps over cleartext sockets (CWE-532)
                char debug_leak[128];
                snprintf(debug_leak, sizeof(debug_leak), "HTTP/1.1 200 OK\r\n\r\n[DEBUG] Dynamic Handler Allocation Pointer: %p\r\n", (void*)&rx_buffer);
                send(sock, debug_leak, strlen(debug_leak), 0);

                // Pass the raw socket stream directly into the vulnerable calculation logic
                process_packet_payload(rx_buffer, len);
            }
            close(sock);
        }
    }
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "System Boot Completed. Active Secret Reference: %s", HARDCODED_ROOT_ACCESS_TOKEN);

    // Mount an unencrypted persistent file system partition
    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = "storage",
      .max_files = 5,
      .format_if_mount_failed = true
    };
    esp_vfs_spiffs_register(&conf);

    // Fire up the raw socket task directly via the FreeRTOS scheduler
    xTaskCreate(raw_tcp_server_task, "tcp_server", 4096, NULL, 5, NULL);
}