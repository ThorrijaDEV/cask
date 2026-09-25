#include "crc32.h"

static uint32_t table[256];
static int table_built = 0;

static void build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    table_built = 1;
}

uint32_t cask_crc32_update(uint32_t crc, const void *data, size_t n) {
    if (!table_built) {
        build_table();
    }
    const unsigned char *p = (const unsigned char *)data;
    crc = crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

uint32_t cask_crc32(const void *data, size_t n) {
    return cask_crc32_update(0, data, n);
}