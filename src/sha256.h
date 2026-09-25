#ifndef CASK_SHA256_H
#define CASK_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char buf[64];
    size_t buflen;
} cask_sha256_ctx;

void cask_sha256_init(cask_sha256_ctx *ctx);
void cask_sha256_update(cask_sha256_ctx *ctx, const void *data, size_t n);
void cask_sha256_final(cask_sha256_ctx *ctx, unsigned char out[32]);
void cask_sha256(const void *data, size_t n, unsigned char out[32]);

#endif