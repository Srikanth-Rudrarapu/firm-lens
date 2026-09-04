#include "build_info.h"
#include "esp_app_desc.h"
#include <stdio.h>

void print_build_info(void) {
    const esp_app_desc_t *app = esp_app_get_description();
    printf("Build: %s %s\n", app->date, app->time);
    printf("Version: %s\n", app->version);
    printf("IDF: %s\n", app->idf_ver);
}
