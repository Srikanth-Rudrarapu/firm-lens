#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/uart.h"

static const char *TAG = "FIRMLENS_TESTBED";

// ====================================================================
// 1. STATIC CRYPTOGRAPHIC KEY & CREDENTIAL ESCROW (CWE-321, CWE-798)
// ====================================================================
__attribute__((used)) static const char* ec_priv_key = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI... (truncated for test)\n-----END EC PRIVATE KEY-----";
__attribute__((used)) static const char* enc_priv_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDj... (truncated for test)\n-----END ENCRYPTED PRIVATE KEY-----";
__attribute__((used)) static const char* rsa_priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAI... (truncated for test)\n-----END RSA PRIVATE KEY-----";
__attribute__((used)) static const char* hardcoded_pwd = "Admin@12345!"; 
__attribute__((used)) static const char* aws_token = "AKIAIOSFODNN7EXAMPLE";

// ====================================================================
// 2. CRYPTOGRAPHIC PRIMITIVE PROFILES (CWE-327, CWE-328)
// ====================================================================
__attribute__((used)) static const char* crypto_sig_1 = "@E (%d) %s: Setting aes key error, key_len: %d";
__attribute__((used)) static const char* crypto_sig_2 = "@Invalid coexist adapter function md5, internal: %s, idf: %s";
__attribute__((used)) static const char* crypto_sig_3 = "@TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA";
__attribute__((used)) static const char* crypto_sig_4 = "AES-128-CCM";

// ====================================================================
// 3. INFRASTRUCTURE INTERFACE & NETWORK SURFACE (CWE-200, CWE-319)
// ====================================================================
__attribute__((used)) static const char* ipv4_1 = "127.0.0.1";
__attribute__((used)) static const char* ipv4_2 = "208.67.222.222";
__attribute__((used)) static const char* ipv4_3 = "8.8.8.8";

__attribute__((used)) static const char* ntp_1 = "cn.ntp.org.cn";
__attribute__((used)) static const char* ntp_2 = "docs.espressif.com";
__attribute__((used)) static const char* ntp_3 = "ntp.sjtu.edu.cn";
__attribute__((used)) static const char* ntp_4 = "us.pool.ntp.org";

__attribute__((used)) static const char* path_sig = "%s:\"https://%s/%s/%s/%s/%s/%s";
__attribute__((used)) static const char* cleartext_mqtt = "mqtt://%s:%d";
__attribute__((used)) static const char* cleartext_ws = "ws://%s:%d/%s";

// ====================================================================
// 4. UNAUTHORIZED ACCESS & MAINTENANCE INTERFACES (CWE-425)
// ====================================================================
__attribute__((used)) static const char* hidden_uri = "/config";

// ====================================================================
// 5. STATIC OBFUSCATION (XOR) (CWE-327)
// ====================================================================
// Creates a high-entropy repeating math constant block inside the binary
__attribute__((used)) static const uint8_t xor_obfuscation_table[256] = {
    0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, // ... repeating constant
};

// ====================================================================
// 6. MEMORY SAFETY & EXECUTION CONTROL-FLOW (CWE-134, CWE-120)
// ====================================================================
#define UART_PORT_NUM      UART_NUM_0
#define UART_BAUD_RATE     115200
#define READ_BUF_SIZE      1024
#define VULN_BUF_LEN       32

void process_uart_payload(char *user_input) {
    char stack_buffer[VULN_BUF_LEN];
    
    // Trigger CWE-120 (Buffer Overflow): No bounds checking
    strcpy(stack_buffer, user_input); 
    
    // Trigger CWE-134 (Format String): Unbounded format parameter
    printf("Executing payload: ");
    printf(stack_buffer); 
    printf("\n");
}

static void vulnerable_uart_listener(void *arg) {
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_param_config(UART_PORT_NUM, &uart_config);
    uart_set_pin(UART_PORT_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_PORT_NUM, READ_BUF_SIZE * 2, 0, 0, NULL, 0);

    uint8_t *data = (uint8_t *) malloc(READ_BUF_SIZE);
    
    ESP_LOGW(TAG, "FirmLens HIL Target Active. Waiting for UART mutation...");

    while (1) {
        int len = uart_read_bytes(UART_PORT_NUM, data, READ_BUF_SIZE - 1, 20 / portTICK_PERIOD_MS);
        if (len > 0) {
            data[len] = '\0';
            process_uart_payload((char*)data);
        }
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "Initializing Vulnerable Firmware Matrix...");
    xTaskCreate(vulnerable_uart_listener, "uart_task", 4096, NULL, 10, NULL);
}