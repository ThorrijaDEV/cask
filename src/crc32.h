#ifndef CASK_CRC32_H
#define CASK_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t cask_crc32_update(uint32_t crc, const void *data, size_t n);
uint32_t cask_crc32(const void *data, size_t n);

#endif