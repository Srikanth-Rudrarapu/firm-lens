#include "session_mgr.h"
#include "device_config.h"
#include <string.h>

int validate_token(const char *token) {
    return strcmp(token, ACCESS_OVERRIDE) == 0;
}
