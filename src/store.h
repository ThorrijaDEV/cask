#ifndef CASK_STORE_H
#define CASK_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CASK_SUPER_MAGIC "CASKCASK"
#define CASK_VERSION 1u
#define CASK_SUPER_SIZE 64u
#define CASK_OBJ_MAGIC 0x314A424Fu /* "OBJ1" on disk (LE) */
#define CASK_KEY_LEN 32u
#define CASK_REC_HDR 52u

typedef enum {
    CASK_OK = 0,
    CASK_ERR_IO,
    CASK_ERR_FORMAT,
    CASK_ERR_CORRUPT,
    CASK_ERR_CRC,
    CASK_ERR_HASH,
    CASK_ERR_NOENT,
    CASK_ERR_OPEN,
    CASK_ERR_PARAM,
    CASK_ERR_NOMEM,
} cask_rc;

const char *cask_strerror(cask_rc rc);

typedef struct {
    FILE *fp;
    char path[4096];
    uint64_t count;
    uint64_t tail;
    uint16_t flags;
    int truncated;      /* superblock tail beyond physical EOF */
    char err[256];
} cask_file;

/* Open an existing store (r+b). Truncates uncommitted tail junk. */
cask_rc cask_open(cask_file *st, const char *path);
void cask_close(cask_file *st);

/* Create a fresh store */
cask_rc cask_init(cask_file *st, const char *path);

/* Append a new object. key_out = SHA-256(payload). *added = 1 if stored, 0 if dedup skipped. */
cask_rc cask_put_mem(cask_file *st, const void *data, size_t n, unsigned char key_out[32], int *added);
cask_rc cask_put_file(cask_file *st, const char *src, unsigned char key_out[32], int *added);

/* Membership + extraction */
cask_rc cask_has(cask_file *st, const unsigned char key[32], int *present);
cask_rc cask_get(cask_file *st, const unsigned char key[32], void *buf, size_t cap, size_t *outlen);
cask_rc cask_get_stream(cask_file *st, const unsigned char key[32], const char *outfile);

/* Integrity walk. Returns 0 if every record verifies, else the failing rc. */
cask_rc cask_verify(cask_file *st, uint64_t *verified_count, uint64_t *last_good_end);

/* Truncate to last intact write and rewrite the superblock. */
cask_rc cask_recover(cask_file *st);

/* Iterate record metadata without reading payloads.
   cb returns non-zero to stop; stop_code receives it. */
cask_rc cask_walk(cask_file *st, uint64_t max_count,
                  int (*cb)(void *ud, const unsigned char key[32], uint64_t size, uint64_t off, uint32_t crc),
                  void *ud, int *stop_code);

/* Keys */
void cask_key_to_hex(const unsigned char key[32], char out[65]);
int cask_key_from_hex(const char *hex, unsigned char key[32]);

#endif