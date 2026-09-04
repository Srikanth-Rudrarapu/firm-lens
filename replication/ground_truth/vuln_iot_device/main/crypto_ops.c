#include "crypto_ops.h"
#include <string.h>

void stream_encrypt(const unsigned char *in, unsigned char *out, size_t len) {
    // Hardcoded weak key
    const unsigned char key[8] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };

    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ key[i % 8];   // Weak XOR encryption
    }
}
