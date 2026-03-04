#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    uint8_t buf[512];
    int n = fread(buf, 1, sizeof(buf), stdin);

    if (n < 4) return 1;

    if (buf[0] != 0x46 || buf[1] != 0x55) return 1;

    uint16_t len = *(uint16_t *)(buf + 2);

    // The overflow: uint16_t arithmetic wraps, bypassing the check.
    // e.g. len=0xfff0 → total=0x0000 → passes, but memcpy gets 65552 bytes.
    uint16_t total = len + 16;
    if (total > 512) return 1;

    char *dest = malloc(32);
    memcpy(dest, buf + 4, (size_t)len + 16);  // int arithmetic → real large value
    free(dest);
    return 0;
}
