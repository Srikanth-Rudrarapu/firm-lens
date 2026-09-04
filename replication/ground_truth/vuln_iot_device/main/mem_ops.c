#include "mem_ops.h"
#include <string.h>
#include <stdio.h>

void process_payload(const char *input) {
    char buf[32];
    strcpy(buf, input);  // CWE-120
    printf("Payload: %s\n", buf);
}
