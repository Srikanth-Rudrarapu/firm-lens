#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_http_client.h"

static const char *TAG = "VULN_FW";

// =========================
// Hardcoded secrets (VULN)
// =========================

// VULN #1: Hardcoded WiFi credentials
#define WIFI_SSID "MyHomeWiFi"
#define WIFI_PASS "SuperSecretPassword123"

// VULN #2: Hardcoded API key
static char api_key[] = "API_KEY_123456789";

// VULN #3: Hardcoded JWT token
static const char jwt_token[] =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SECRET_PAYLOAD.SIGNATURE";

// VULN #4: Weak RSA private key (short, placeholder)
static const char *weak_rsa_key =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIBOgIBAAJBALuFakeWeakKeyExampleOnly1234567890ABCDE=\n"
"-----END RSA PRIVATE KEY-----\n";

// =========================
// Weak crypto (VULN)
// =========================

// VULN #5: Weak XOR "encryption"
void weak_encrypt(char *data) {
    for (int i = 0; i < strlen(data); i++) {
        data[i] ^= 0x42;  // trivial XOR key
    }
}

// =========================
// Memory safety issues
// =========================

// VULN #6: Stack buffer overflow via strcpy
void vulnerable_copy(const char *input) {
    char buffer[16];
    // No bounds check: classic stack overflow
    strcpy(buffer, input);
    ESP_LOGI(TAG, "Buffer content: %s", buffer);
}

// VULN #7: Heap overflow
void heap_overflow() {
    char *buf = malloc(16);
    if (!buf) {
        ESP_LOGE(TAG, "malloc failed");
        return;
    }
    // Overwrite beyond allocated size
    memset(buf, 'A', 64);
    ESP_LOGW(TAG, "Heap overflow triggered");
    free(buf);
}

// VULN #8: Format string vulnerability
void format_string_vuln(char *user_input) {
    // Uncontrolled format string
    ESP_LOGE(TAG, user_input);
}

// =========================
// Backdoors / Insecure I/O
// =========================

// VULN #9: UART "backdoor" style function
// (Here we just log the command; in real life this might call system())
void uart_backdoor(const char *cmd) {
    ESP_LOGW(TAG, "Backdoor received command: %s", cmd);
    // On real POSIX: system(cmd);  // command injection
    // On ESP32, system() is not generally available, so we simulate.
}

// =========================
// Insecure network behavior
// =========================

// VULN #10: Insecure OTA over HTTP, no TLS, no signature check
void insecure_ota_check() {
    esp_http_client_config_t config = {
        .url = "http://example.com/ota/update.bin",  // HTTP, no TLS
        .timeout_ms = 2000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client) {
        esp_http_client_perform(client);
        esp_http_client_cleanup(client);
    }

    ESP_LOGW(TAG, "Checked OTA update over insecure HTTP, no signature verification");
}

// VULN #11: Insecure MQTT (simulated)
void insecure_mqtt() {
    ESP_LOGW(TAG, "Connecting to MQTT over plaintext tcp://broker.hivemq.com:1883 (no TLS, no auth)");
}

// VULN #12: Insecure BLE (simulated)
void insecure_ble() {
    ESP_LOGW(TAG, "BLE running with no authentication, no encryption (MITM possible)");
}

// =========================
// NVS / secret leakage
// =========================

// VULN #13: NVS secret leakage (simulated)
void leak_nvs() {
    ESP_LOGE(TAG, "Reading NVS secret key: %s", "MASTER_KEY_ABC123");
}

// VULN #14: Logging secrets directly
void leak_secret() {
    ESP_LOGE(TAG, "Leaking API key: %s", api_key);
    ESP_LOGE(TAG, "Leaking JWT: %s", jwt_token);
    ESP_LOGE(TAG, "Leaking RSA key: %s", weak_rsa_key);
}

// =========================
// WiFi init (still insecure)
// =========================

static void wifi_init() {
    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", WIFI_SSID);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_start();
}

// =========================
// Vulnerable main task
// =========================

static void vuln_task(void *pv) {
    ESP_LOGI(TAG, "Vulnerable task started");

    // Simulate user input for format string vuln
    char user_input_fmt[] = "User input: %x %x %x %x";

    // Simulate user input for buffer overflow
    char long_input[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // >16 bytes

    while (1) {
        ESP_LOGI(TAG, "=== Vulnerable cycle ===");

        // Hardcoded secret leakage
        leak_secret();
        leak_nvs();

        // Weak crypto
        char secret[] = "SensitiveData";
        weak_encrypt(secret);
        ESP_LOGI(TAG, "Weak encrypted data: %s", secret);

        // Memory safety issues
        vulnerable_copy(long_input);
        heap_overflow();
        format_string_vuln(user_input_fmt);

        // Backdoor simulation
        uart_backdoor("reboot; rm -rf /");

        // Insecure network behavior
        insecure_ota_check();
        insecure_mqtt();
        insecure_ble();

        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}

// =========================
// app_main
// =========================

void app_main(void) {
    ESP_LOGI(TAG, "Starting vulnerable firmware (stable loop)...");

    // Init NVS (required for WiFi)
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "nvs_flash_init failed: %d", ret);
    }

    // Init WiFi (with hardcoded creds)
    wifi_init();

    // Create a FreeRTOS task that runs all vulnerable behavior
    xTaskCreate(&vuln_task, "vuln_task", 4096, NULL, 5, NULL);

    // app_main returns, but the FreeRTOS task keeps running
    ESP_LOGI(TAG, "app_main finished setup, vuln_task running");
}
