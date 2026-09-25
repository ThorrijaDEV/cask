#define _POSIX_C_SOURCE 200809L
#include "store.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crc32.h"
#include "sha256.h"

#define SUPER_MAGIC_OFF 0u
#define SUPER_VERSION_OFF 8u
#define SUPER_FLAGS_OFF 10u
#define SUPER_COUNT_OFF 12u
#define SUPER_TAIL_OFF 20u
#define SUPER_CRC_OFF 60u

#define REC_MAGIC_OFF 0u
#define REC_FLAGS_OFF 4u
#define REC_SIZE_OFF 8u
#define REC_KEY_OFF 16u
#define REC_CRC_OFF 48u

static void put_u16(unsigned char *dst, uint16_t v) {
    dst[0] = (unsigned char)(v & 0xFF);
    dst[1] = (unsigned char)(v >> 8);
}

static void put_u32(unsigned char *dst, uint32_t v) {
    dst[0] = (unsigned char)(v & 0xFF);
    dst[1] = (unsigned char)((v >> 8) & 0xFF);
    dst[2] = (unsigned char)((v >> 16) & 0xFF);
    dst[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void put_u64(unsigned char *dst, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (unsigned char)((v >> (i * 8)) & 0xFF);
    }
}

static uint16_t get_u16(const unsigned char *src) {
    return (uint16_t)(src[0] | (src[1] << 8));
}

static uint32_t get_u32(const unsigned char *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static uint64_t get_u64(const unsigned char *src) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | src[i];
    }
    return v;
}

const char *cask_strerror(cask_rc rc) {
    switch (rc) {
    case CASK_OK:
        return "ok";
    case CASK_ERR_IO:
        return "I/O error";
    case CASK_ERR_FORMAT:
        return "invalid store format";
    case CASK_ERR_CORRUPT:
        return "store corrupted or truncated";
    case CASK_ERR_CRC:
        return "checksum mismatch (crc32)";
    case CASK_ERR_HASH:
        return "content hash mismatch (sha256)";
    case CASK_ERR_NOENT:
        return "object not found";
    case CASK_ERR_OPEN:
        return "cannot open store";
    case CASK_ERR_PARAM:
        return "invalid parameter";
    case CASK_ERR_NOMEM:
        return "out of memory";
    }
    return "unknown error";
}

static void set_err(cask_file *st, const char *msg) {
    snprintf(st->err, sizeof(st->err), "%s: %s", msg, strerror(errno));
}

static int fsync_store(cask_file *st) {
    if (fflush(st->fp) != 0 || fsync(fileno(st->fp)) != 0) {
        set_err(st, "fsync");
        return -1;
    }
    return 0;
}

static void super_build(unsigned char raw[CASK_SUPER_SIZE], uint32_t count, uint64_t tail,
                        uint16_t flags) {
    memcpy(raw, CASK_SUPER_MAGIC, 8);
    put_u16(raw + SUPER_VERSION_OFF, CASK_VERSION);
    put_u16(raw + SUPER_FLAGS_OFF, flags);
    put_u64(raw + SUPER_COUNT_OFF, count);
    put_u64(raw + SUPER_TAIL_OFF, tail);
    put_u32(raw + SUPER_CRC_OFF, cask_crc32(raw, SUPER_CRC_OFF));
}

static int commit_super(cask_file *st) {
    unsigned char raw[CASK_SUPER_SIZE];
    super_build(raw, (uint32_t)st->count, st->tail, st->flags);
    if (fseeko(st->fp, 0, SEEK_SET) != 0 ||
        fwrite(raw, 1, CASK_SUPER_SIZE, st->fp) != CASK_SUPER_SIZE) {
        set_err(st, "write superblock");
        return -1;
    }
    return fsync_store(st);
}

static cask_rc read_exact_at(cask_file *st, unsigned char *buf, size_t n, uint64_t off) {
    if (n == 0) {
        return CASK_OK;
    }
    if (fseeko(st->fp, (off_t)off, SEEK_SET) != 0 || fread(buf, 1, n, st->fp) != n) {
        return CASK_ERR_CORRUPT;
    }
    return CASK_OK;
}

cask_rc cask_init(cask_file *st, const char *path) {
    if (st == NULL || path == NULL) {
        return CASK_ERR_PARAM;
    }
    FILE *fp = fopen(path, "w+b");
    if (fp == NULL) {
        set_err(st, "create store");
        return CASK_ERR_OPEN;
    }
    st->fp = fp;
    st->count = 0;
    st->tail = CASK_SUPER_SIZE;
    st->flags = 0;
    st->truncated = 0;
    st->err[0] = '\0';
    snprintf(st->path, sizeof(st->path), "%s", path);
    if (commit_super(st) != 0) {
        cask_close(st);
        return CASK_ERR_IO;
    }
    return CASK_OK;
}

cask_rc cask_open(cask_file *st, const char *path) {
    if (st == NULL || path == NULL) {
        return CASK_ERR_PARAM;
    }
    memset(st, 0, sizeof(*st));
    FILE *fp = fopen(path, "r+b");
    if (fp == NULL) {
        set_err(st, "open store");
        return CASK_ERR_OPEN;
    }
    st->fp = fp;
    snprintf(st->path, sizeof(st->path), "%s", path);
    unsigned char raw[CASK_SUPER_SIZE];
    if (fread(raw, 1, CASK_SUPER_SIZE, fp) != CASK_SUPER_SIZE) {
        set_err(st, "read superblock");
        cask_close(st);
        return CASK_ERR_FORMAT;
    }
    if (memcmp(raw, CASK_SUPER_MAGIC, 8) != 0) {
        snprintf(st->err, sizeof(st->err), "not a cask store");
        cask_close(st);
        return CASK_ERR_FORMAT;
    }
    if (get_u16(raw + SUPER_VERSION_OFF) != CASK_VERSION) {
        snprintf(st->err, sizeof(st->err), "unsupported format version");
        cask_close(st);
        return CASK_ERR_FORMAT;
    }
    if (cask_crc32(raw, SUPER_CRC_OFF) != get_u32(raw + SUPER_CRC_OFF)) {
        snprintf(st->err, sizeof(st->err), "superblock checksum mismatch");
        cask_close(st);
        return CASK_ERR_CRC;
    }
    st->flags = get_u16(raw + SUPER_FLAGS_OFF);
    st->count = get_u64(raw + SUPER_COUNT_OFF);
    st->tail = get_u64(raw + SUPER_TAIL_OFF);

    struct stat sb;
    if (fstat(fileno(fp), &sb) != 0) {
        set_err(st, "stat store");
        cask_close(st);
        return CASK_ERR_IO;
    }
    uint64_t size = (uint64_t)sb.st_size;
    if (st->tail > size) {
        st->truncated = 1;
        st->tail = size;
    } else if (st->tail < size) {
        /* uncommitted append tail junk */
        if (ftruncate(fileno(fp), (off_t)st->tail) != 0) {
            set_err(st, "truncate store");
            cask_close(st);
            return CASK_ERR_IO;
        }
    }
    return CASK_OK;
}

void cask_close(cask_file *st) {
    if (st != NULL && st->fp != NULL) {
        fclose(st->fp);
        st->fp = NULL;
    }
}

void cask_key_to_hex(const unsigned char key[32], char out[65]) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = h[key[i] >> 4];
        out[i * 2 + 1] = h[key[i] & 0xF];
    }
    out[64] = '\0';
}

int cask_key_from_hex(const char *hex, unsigned char key[32]) {
    for (int i = 0; i < 32; i++) {
        unsigned hi, lo;
        char a = hex[i * 2], b = hex[i * 2 + 1];
        if (a >= '0' && a <= '9') hi = (unsigned)(a - '0');
        else if (a >= 'a' && a <= 'f') hi = (unsigned)(a - 'a' + 10);
        else if (a >= 'A' && a <= 'F') hi = (unsigned)(a - 'A' + 10);
        else return 0;
        if (b >= '0' && b <= '9') lo = (unsigned)(b - '0');
        else if (b >= 'a' && b <= 'f') lo = (unsigned)(b - 'a' + 10);
        else if (b >= 'A' && b <= 'F') lo = (unsigned)(b - 'A' + 10);
        else return 0;
        key[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/* ---- object records ---- */

typedef struct {
    const unsigned char *key;
    uint64_t off, size;
    int found;
} find_ctx;

static int find_cb(void *ud, const unsigned char key[32], uint64_t size, uint64_t off, uint32_t crc) {
    (void)crc;
    find_ctx *f = (find_ctx *)ud;
    if (memcmp(key, f->key, 32) == 0) {
        f->found = 1;
        f->size = size;
        f->off = off;
        return 1;
    }
    return 0;
}

static cask_rc scan_records(cask_file *st, uint64_t start, uint64_t max,
                            int (*cb)(void *, const unsigned char[32], uint64_t, uint64_t, uint32_t),
                            void *ud, uint64_t *seen) {
    uint64_t cur = start, n = 0;
    struct stat sb;
    if (fstat(fileno(st->fp), &sb) != 0) {
        set_err(st, "stat store");
        return CASK_ERR_IO;
    }
    uint64_t fsize = (uint64_t)sb.st_size;
    while (max == 0 || n < max) {
        if (cur >= fsize || fsize - cur < CASK_REC_HDR) {
            break;
        }
        unsigned char hdr[52];
        if (read_exact_at(st, hdr, sizeof(hdr), cur) != CASK_OK) {
            break;
        }
        if (get_u32(hdr + REC_MAGIC_OFF) != CASK_OBJ_MAGIC) {
            break;
        }
        uint64_t size = get_u64(hdr + REC_SIZE_OFF);
        if (cur + CASK_REC_HDR + size > fsize) {
            break;
        }
        if (cb && cb(ud, hdr + REC_KEY_OFF, size, cur, get_u32(hdr + REC_CRC_OFF))) {
            break;
        }
        cur += CASK_REC_HDR + size;
        n++;
    }
    if (seen) {
        *seen = n;
    }
    return CASK_OK;
}

cask_rc cask_walk(cask_file *st, uint64_t max_count,
                  int (*cb)(void *, const unsigned char[32], uint64_t, uint64_t, uint32_t), void *ud,
                  int *stop_code) {
    if (st == NULL || st->fp == NULL) {
        return CASK_ERR_PARAM;
    }
    uint64_t seen = 0;
    cask_rc rc = scan_records(st, CASK_SUPER_SIZE, max_count, cb, ud, &seen);
    if (rc == CASK_OK && stop_code) {
        *stop_code = 0;
    }
    return rc;
}

cask_rc cask_has(cask_file *st, const unsigned char key[32], int *present) {
    if (st == NULL || st->fp == NULL || key == NULL || present == NULL) {
        return CASK_ERR_PARAM;
    }
    find_ctx f = {key, 0, 0, 0};
    cask_rc rc = scan_records(st, CASK_SUPER_SIZE, st->count, find_cb, &f, NULL);
    if (rc != CASK_OK)
        return rc;
    *present = f.found;
    return CASK_OK;
}

static void rec_build(unsigned char hdr[52], const unsigned char key[32], uint64_t size,
                      uint32_t crc) {
    put_u32(hdr + REC_MAGIC_OFF, CASK_OBJ_MAGIC);
    put_u16(hdr + REC_FLAGS_OFF, 0);
    put_u64(hdr + REC_SIZE_OFF, size);
    memcpy(hdr + REC_KEY_OFF, key, 32);
    put_u32(hdr + REC_CRC_OFF, crc);
}

/* append already-hashed payload present in `buf` (could be a mem buffer) */
static cask_rc append_payload(cask_file *st, const void *payload, size_t n,
                              const unsigned char key[32], uint32_t crc) {
    uint64_t base = st->tail;
    unsigned char hdr[52];
    rec_build(hdr, key, n, crc);
    if (fseeko(st->fp, (off_t)base, SEEK_SET) != 0 ||
        fwrite(hdr, 1, sizeof(hdr), st->fp) != sizeof(hdr)) {
        set_err(st, "append header");
        return CASK_ERR_IO;
    }
    if (n > 0 && fwrite(payload, 1, n, st->fp) != n) {
        set_err(st, "append payload");
        return CASK_ERR_IO;
    }
    if (fsync_store(st) != 0) {
        return CASK_ERR_IO;
    }
    st->tail = base + sizeof(hdr) + n;
    st->count++;
    if (commit_super(st) != 0) {
        return CASK_ERR_IO;
    }
    return CASK_OK;
}

cask_rc cask_put_mem(cask_file *st, const void *data, size_t n, unsigned char key_out[32],
                     int *added) {
    if (st == NULL || st->fp == NULL || data == NULL || key_out == NULL || added == NULL) {
        return CASK_ERR_PARAM;
    }
    cask_sha256(data, n, key_out);
    int present;
    cask_rc rc = cask_has(st, key_out, &present);
    if (rc != CASK_OK)
        return rc;
    if (present) {
        *added = 0;
        return CASK_OK;
    }
    uint32_t crc = cask_crc32(data, n);
    rc = append_payload(st, data, n, key_out, crc);
    if (rc == CASK_OK) {
        *added = 1;
    }
    return rc;
}

cask_rc cask_put_file(cask_file *st, const char *src, unsigned char key_out[32], int *added) {
    if (st == NULL || st->fp == NULL || src == NULL || key_out == NULL || added == NULL) {
        return CASK_ERR_PARAM;
    }
    FILE *in = fopen(src, "rb");
    if (in == NULL) {
        set_err(st, "open source");
        return CASK_ERR_IO;
    }
    cask_sha256_ctx ctx;
    cask_sha256_init(&ctx);
    unsigned char buf[1 << 16];
    size_t rd;
    while ((rd = fread(buf, 1, sizeof(buf), in)) > 0) {
        cask_sha256_update(&ctx, buf, rd);
    }
    if (ferror(in)) {
        fclose(in);
        set_err(st, "read source");
        return CASK_ERR_IO;
    }
    cask_sha256_final(&ctx, key_out);
    fclose(in);

    int present;
    cask_rc rc = cask_has(st, key_out, &present);
    if (rc != CASK_OK)
        return rc;
    if (present) {
        *added = 0;
        return CASK_OK;
    }

    /* stream append: write header (crc patched after payload) */
    uint64_t base = st->tail;
    unsigned char hdr[52];
    put_u32(hdr + REC_MAGIC_OFF, CASK_OBJ_MAGIC);
    put_u16(hdr + REC_FLAGS_OFF, 0);
    put_u64(hdr + REC_SIZE_OFF, (uint64_t)0); /* patched below */
    memcpy(hdr + REC_KEY_OFF, key_out, 32);
    put_u32(hdr + REC_CRC_OFF, 0);

    /* first a stat pass to know final size (file size is reliable after close) */
    struct stat sb;
    if (stat(src, &sb) != 0) {
        set_err(st, "stat source");
        return CASK_ERR_IO;
    }
    uint64_t size = (uint64_t)sb.st_size;
    put_u64(hdr + REC_SIZE_OFF, size);

    in = fopen(src, "rb");
    if (in == NULL) {
        set_err(st, "reopen source");
        return CASK_ERR_IO;
    }
    if (fseeko(st->fp, (off_t)base, SEEK_SET) != 0 || fwrite(hdr, 1, sizeof(hdr), st->fp) != sizeof(hdr)) {
        fclose(in);
        set_err(st, "append header");
        return CASK_ERR_IO;
    }
    uint32_t crc = 0;
    while ((rd = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, rd, st->fp) != rd) {
            fclose(in);
            set_err(st, "append payload");
            return CASK_ERR_IO;
        }
        crc = cask_crc32_update(crc, buf, rd);
    }
    uint32_t ferr = ferror(in);
    fclose(in);
    if (ferr) {
        set_err(st, "read source");
        return CASK_ERR_IO;
    }

    /* patch stored crc */
    unsigned char crcb[4];
    put_u32(crcb, crc);
    if (fseeko(st->fp, (off_t)(base + REC_CRC_OFF), SEEK_SET) != 0 ||
        fwrite(crcb, 1, 4, st->fp) != 4) {
        set_err(st, "patch crc");
        return CASK_ERR_IO;
    }
    if (fsync_store(st) != 0) {
        return CASK_ERR_IO;
    }
    st->tail = base + sizeof(hdr) + size;
    st->count++;
    if (commit_super(st) != 0) {
        return CASK_ERR_IO;
    }
    *added = 1;
    return CASK_OK;
}

cask_rc cask_get(cask_file *st, const unsigned char key[32], void *buf, size_t cap,
                 size_t *outlen) {
    if (st == NULL || st->fp == NULL || key == NULL || buf == NULL) {
        return CASK_ERR_PARAM;
    }
    find_ctx f = {key, 0, 0, 0};
    cask_rc rc = scan_records(st, CASK_SUPER_SIZE, st->count, find_cb, &f, NULL);
    if (rc != CASK_OK)
        return rc;
    if (!f.found) {
        return CASK_ERR_NOENT;
    }
    if (f.size > cap) {
        return CASK_ERR_PARAM;
    }
    rc = read_exact_at(st, (unsigned char *)buf, (size_t)f.size, f.off + CASK_REC_HDR);
    if (rc != CASK_OK)
        return rc;
    if (outlen) {
        *outlen = (size_t)f.size;
    }
    return CASK_OK;
}

cask_rc cask_get_stream(cask_file *st, const unsigned char key[32], const char *outfile) {
    if (st == NULL || st->fp == NULL || key == NULL) {
        return CASK_ERR_PARAM;
    }
    find_ctx f = {key, 0, 0, 0};
    cask_rc rc = scan_records(st, CASK_SUPER_SIZE, st->count, find_cb, &f, NULL);
    if (rc != CASK_OK)
        return rc;
    if (!f.found) {
        return CASK_ERR_NOENT;
    }
    FILE *dst;
    if (outfile != NULL) {
        dst = fopen(outfile, "wb");
        if (dst == NULL) {
            return CASK_ERR_IO;
        }
    } else {
        dst = stdout;
    }
    unsigned char buf[1 << 16];
    uint64_t got = 0;
    while (got < f.size) {
        size_t want = (size_t)(f.size - got);
        if (want > sizeof(buf))
            want = sizeof(buf);
        if (read_exact_at(st, buf, want, f.off + CASK_REC_HDR + got) != CASK_OK) {
            if (dst != stdout)
                fclose(dst);
            return CASK_ERR_CORRUPT;
        }
        if (fwrite(buf, 1, want, dst) != want) {
            if (dst != stdout)
                fclose(dst);
            return CASK_ERR_IO;
        }
        got += want;
    }
    if (dst != stdout) {
        if (fclose(dst) != 0) {
            return CASK_ERR_IO;
        }
    }
    return CASK_OK;
}

/* integrity: walk every record, recompute crc32 + sha256 of payload on the fly */
static cask_rc verify_inner(cask_file *st, uint64_t *verified_count, uint64_t *last_good_end) {
    struct stat sb;
    if (fstat(fileno(st->fp), &sb) != 0) {
        set_err(st, "stat store");
        return CASK_ERR_IO;
    }
    uint64_t fsize = (uint64_t)sb.st_size;
    uint64_t cur = CASK_SUPER_SIZE, n = 0;
    unsigned char buf[1 << 16];
    for (;;) {
        if (cur >= fsize || fsize - cur < CASK_REC_HDR) {
            break; /* truncated tail */
        }
        unsigned char hdr[52];
        if (read_exact_at(st, hdr, sizeof(hdr), cur) != CASK_OK) {
            break;
        }
        if (get_u32(hdr + REC_MAGIC_OFF) != CASK_OBJ_MAGIC) {
            break;
        }
        uint64_t size = get_u64(hdr + REC_SIZE_OFF);
        if (cur + CASK_REC_HDR + size > fsize) {
            break;
        }
        uint32_t want_crc = get_u32(hdr + REC_CRC_OFF);
        uint32_t rcrc = 0;
        cask_sha256_ctx rctx;
        cask_sha256_init(&rctx);
        uint64_t got = 0;
        while (got < size) {
            size_t want = (size_t)(size - got);
            if (want > sizeof(buf))
                want = sizeof(buf);
            if (read_exact_at(st, buf, want, cur + CASK_REC_HDR + got) != CASK_OK) {
                if (verified_count)
                    *verified_count = n;
                if (last_good_end)
                    *last_good_end = cur;
                return CASK_ERR_CORRUPT;
            }
            rcrc = cask_crc32_update(rcrc, buf, want);
            cask_sha256_update(&rctx, buf, want);
            got += want;
        }
        unsigned char rkey[32];
        cask_sha256_final(&rctx, rkey);
        if (rcrc != want_crc) {
            if (verified_count)
                *verified_count = n;
            if (last_good_end)
                *last_good_end = cur;
            return CASK_ERR_CRC;
        }
        if (memcmp(rkey, hdr + REC_KEY_OFF, 32) != 0) {
            if (verified_count)
                *verified_count = n;
            if (last_good_end)
                *last_good_end = cur;
            return CASK_ERR_HASH;
        }
        cur += CASK_REC_HDR + size;
        n++;
    }
    /* reached EOF; if it doesn't line up with the superblock, still an inconsistency */
    if (verified_count)
        *verified_count = n;
    if (last_good_end)
        *last_good_end = cur;
    return CASK_OK;
}

cask_rc cask_verify(cask_file *st, uint64_t *verified_count, uint64_t *last_good_end) {
    if (st == NULL || st->fp == NULL) {
        return CASK_ERR_PARAM;
    }
    uint64_t verified, end;
    cask_rc rc = verify_inner(st, &verified, &end);
    if (rc == CASK_OK) {
        if (verified != st->count || end != st->tail) {
            rc = CASK_ERR_CORRUPT;
        }
    }
    if (verified_count)
        *verified_count = verified;
    if (last_good_end)
        *last_good_end = end;
    return rc;
}

cask_rc cask_recover(cask_file *st) {
    if (st == NULL || st->fp == NULL) {
        return CASK_ERR_PARAM;
    }
    uint64_t verified, end;
    cask_rc rc = verify_inner(st, &verified, &end);
    if (rc == CASK_ERR_IO || rc == CASK_ERR_PARAM) {
        return rc;
    }
    if (ftruncate(fileno(st->fp), (off_t)end) != 0) {
        set_err(st, "truncate store");
        return CASK_ERR_IO;
    }
    st->count = verified;
    st->tail = end;
    st->truncated = 0;
    if (commit_super(st) != 0) {
        return CASK_ERR_IO;
    }
    return CASK_OK;
}