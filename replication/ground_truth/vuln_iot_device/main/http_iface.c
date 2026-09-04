#include "http_iface.h"
#include "mem_ops.h"
#include "session_mgr.h"
#include "device_config.h"
#include <esp_http_server.h>
#include <string.h>

static esp_err_t root_handler(httpd_req_t *req) {
    char query[128];
    char resp[256];

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char token[64];
        if (httpd_query_key_value(query, "auth", token, sizeof(token)) == ESP_OK) {
            if (validate_token(token)) {
                snprintf(resp, sizeof(resp),
                         "Override OK. SSID=%s PSK=%s TOKEN=%s\n",
                         NET_SSID, NET_PSK, TOKEN_KEY);
                httpd_resp_sendstr(req, resp);
                return ESP_OK;
            }
        }
    }

    httpd_resp_sendstr(req, "Device Online\n");
    return ESP_OK;
}

static esp_err_t config_handler(httpd_req_t *req) {
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf)-1);
    buf[len] = 0;

    process_payload(buf);

    httpd_resp_sendstr(req, "Updated\n");
    return ESP_OK;
}

httpd_handle_t start_http_iface(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;

    httpd_handle_t server = NULL;
    httpd_start(&server, &config);

    httpd_uri_t root = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler
    };
    httpd_register_uri_handler(server, &root);

    httpd_uri_t cfg = {
        .uri = "/device/update",
        .method = HTTP_POST,
        .handler = config_handler
    };
    httpd_register_uri_handler(server, &cfg);

    return server;
}
