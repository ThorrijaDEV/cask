#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/crc32.h"
#include "../src/sha256.h"
#include "../src/store.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        checks++;                                                                \
        if (!(cond)) {                                                           \
            failures++;                                                          \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);               \
        }                                                                        \
    } while (0)

static void hexdump(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        sprintf(out + i * 2, "%02x", b[i]);
    }
    out[n * 2] = '\0';
}

static const char *TMPDIR;
static char path_buf[6][512];
static int init_paths(void) {
    TMPDIR = getenv("TMPDIR");
    if (!TMPDIR)
        TMPDIR = "/tmp";
    for (int i = 0; i < 6; i++) {
        snprintf(path_buf[i], sizeof(path_buf[i]), "%s/cask-test-%d.cask", TMPDIR, i);
        remove(path_buf[i]);
    }
    return 0;
}

static void test_crc32_known(void) {
    uint32_t c = cask_crc32((const void *)"123456789", 9);
    CHECK(c == 0xCBF43926u);
}

static void test_sha256_known(void) {
    unsigned char out[32];
    char hex[65];
    cask_sha256((const void *)"abc", 3, out);
    hexdump(out, 32, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    cask_sha256((const void *)"", 0, out);
    hexdump(out, 32, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    /* sha256 of 1,000,000 'a' via the streaming API */
    cask_sha256_ctx ctx;
    cask_sha256_init(&ctx);
    unsigned char buf[1000];
    memset(buf, 'a', sizeof(buf));
    for (int i = 0; i < 1000; i++) {
        cask_sha256_update(&ctx, buf, sizeof(buf));
    }
    cask_sha256_final(&ctx, out);
    hexdump(out, 32, hex);
    CHECK(strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
}

static void test_key_hex(void) {
    char hex[65];
    unsigned char key[32], back[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (unsigned char)(i * 7 + 3);
    }
    cask_key_to_hex(key, hex);
    CHECK(strlen(hex) == 64);
    CHECK(cask_key_from_hex(hex, back) == 1);
    CHECK(memcmp(key, back, 32) == 0);
    CHECK(cask_key_from_hex("zz", back) == 0);
    CHECK(cask_key_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", back) == 1);
    CHECK(cask_key_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", back) == 1);
}

static void test_store_roundtrip(cask_file *st) {
    const char *payload = "hola, cask!";
    unsigned char key[32];
    int added = 0;
    cask_rc rc = cask_put_mem(st, payload, strlen(payload), key, &added);
    CHECK(rc == CASK_OK);
    CHECK(added == 1);
    CHECK(st->count == 1);

    char got[64];
    size_t gotlen = 0;
    rc = cask_get(st, key, got, sizeof(got), &gotlen);
    CHECK(rc == CASK_OK);
    CHECK(gotlen == strlen(payload));
    CHECK(memcmp(got, payload, gotlen) == 0);
}

static void test_store_dedup(cask_file *st) {
    const char *a = "mismo contenido una y otra vez";
    const char *b = "contenido diferente";
    unsigned char ka[32], kb[32];
    int added = 0;
    CHECK(cask_put_mem(st, a, strlen(a), ka, &added) == CASK_OK && added == 1);
    CHECK(cask_put_mem(st, a, strlen(a), ka, &added) == CASK_OK && added == 0);
    CHECK(cask_put_mem(st, b, strlen(b), kb, &added) == CASK_OK && added == 1);
    CHECK(st->count == 3); /* roundtrip object (1) + a + b */
    int present = 0;
    CHECK(cask_has(st, ka, &present) == CASK_OK && present == 1);
    CHECK(cask_has(st, kb, &present) == CASK_OK && present == 1);
    unsigned char bad[32];
    memset(bad, 0x42, 32);
    CHECK(cask_has(st, bad, &present) == CASK_OK && present == 0);
}

static void test_store_verify_clean(cask_file *st) {
    uint64_t verified = 0, end = 0;
    cask_rc rc = cask_verify(st, &verified, &end);
    CHECK(rc == CASK_OK);
    CHECK(verified == st->count);
}

static void test_corruption_recovery(const char *path) {
    cask_file st;
    CHECK(cask_init(&st, path) == CASK_OK);
    unsigned char k1[32], k2[32], k3[32];
    int added = 0;
    CHECK(cask_put_mem(&st, "uno", 3, k1, &added) == CASK_OK && added == 1);
    CHECK(cask_put_mem(&st, "dos", 3, k2, &added) == CASK_OK && added == 1);
    CHECK(cask_put_mem(&st, "tres", 4, k3, &added) == CASK_OK && added == 1);
    cask_close(&st);
    /* records: [uno off=64 len=55][dos off=119 len=55][tres off=174 len=56] */

    /* flip a byte inside the LAST record's payload (record3 starts at 174) */
    FILE *f = fopen(path, "r+b");
    CHECK(f != NULL);
    unsigned char c;
    CHECK(fseeko(f, 174 + 52 + 1, SEEK_SET) == 0);
    CHECK(fread(&c, 1, 1, f) == 1);
    c ^= 0xFF;
    CHECK(fseeko(f, -1, SEEK_CUR) == 0);
    CHECK(fwrite(&c, 1, 1, f) == 1);
    fclose(f);

    /* verify detects the corruption; recover drops the bad tail record */
    CHECK(cask_open(&st, path) == CASK_OK);
    uint64_t verified = 0, end = 0;
    cask_rc rc = cask_verify(&st, &verified, &end);
    CHECK(rc == CASK_ERR_CRC);
    CHECK(verified == 2);
    CHECK(cask_recover(&st) == CASK_OK);
    cask_close(&st);

    CHECK(cask_open(&st, path) == CASK_OK);
    CHECK(st.count == 2);
    int present = 0;
    CHECK(cask_has(&st, k1, &present) == CASK_OK && present == 1);
    CHECK(cask_has(&st, k2, &present) == CASK_OK && present == 1);
    CHECK(cask_has(&st, k3, &present) == CASK_OK && present == 0);
    cask_close(&st);

    /* re-add, then physically truncate inside the stored tail and recover */
    CHECK(cask_open(&st, path) == CASK_OK);
    CHECK(cask_put_mem(&st, "cuatro", 6, k3, &added) == CASK_OK && added == 1);
    cask_close(&st);
    struct stat sb;
    CHECK(stat(path, &sb) == 0);
    FILE *tf = fopen(path, "r+b");
    CHECK(tf != NULL);
    CHECK(ftruncate(fileno(tf), (off_t)sb.st_size - 20) == 0);
    fclose(tf);

    CHECK(cask_open(&st, path) == CASK_OK);
    rc = cask_verify(&st, &verified, &end);
    CHECK(rc == CASK_ERR_CORRUPT);
    CHECK(cask_recover(&st) == CASK_OK);
    cask_close(&st);

    CHECK(cask_open(&st, path) == CASK_OK);
    CHECK(st.count == 2);
    CHECK(cask_has(&st, k1, &present) == CASK_OK && present == 1);
    CHECK(cask_has(&st, k3, &present) == CASK_OK && present == 0);
    cask_close(&st);
}

static void test_crash_tail_junk(const char *path) {
    cask_file st;
    CHECK(cask_init(&st, path) == CASK_OK);
    unsigned char k1[32];
    int added = 0;
    CHECK(cask_put_mem(&st, "algo", 4, k1, &added) == CASK_OK && added == 1);
    uint64_t tail_before = st.tail;
    cask_close(&st);

    /* simulate a crash mid-append: junk sits past the committed tail */
    FILE *f = fopen(path, "ab");
    CHECK(f != NULL);
    const char junk[] = "HASH basura parcial sin confirmar";
    CHECK(fwrite(junk, 1, sizeof(junk) - 1, f) == sizeof(junk) - 1);
    fclose(f);

    CHECK(cask_open(&st, path) == CASK_OK);
    CHECK(st.tail == tail_before);
    CHECK(st.count == 1);
    struct stat sb;
    CHECK(fstat(fileno(st.fp), &sb) == 0);
    CHECK((uint64_t)sb.st_size == tail_before);
    uint64_t verified = 0, end = 0;
    CHECK(cask_verify(&st, &verified, &end) == CASK_OK);
    cask_close(&st);
}

static void test_put_file(const char *srcrel, const char *store_path) {
    FILE *s = fopen(srcrel, "wb");
    CHECK(s != NULL);
    for (int i = 0; i < 200000; i++) {
        fputc((char)(i * 31), s);
    }
    fclose(s);

    cask_file st;
    CHECK(cask_init(&st, store_path) == CASK_OK);
    unsigned char key[32];
    int added = 0;
    CHECK(cask_put_file(&st, srcrel, key, &added) == CASK_OK && added == 1);
    uint64_t verified = 0, end = 0;
    CHECK(cask_verify(&st, &verified, &end) == CASK_OK && verified == 1);

    /* buffer too small -> ERR_PARAM */
    char out[64];
    size_t outlen = 0;
    memset(out, 0, sizeof(out));
    CHECK(cask_get(&st, key, out, sizeof(out), &outlen) == CASK_ERR_PARAM);

    /* stream out and compare bytes */
    char strel[600];
    snprintf(strel, sizeof(strel), "%s/cask-get-out-%d.bin", TMPDIR, getpid());
    remove(strel);
    CHECK(cask_get_stream(&st, key, strel) == CASK_OK);

    struct stat sa, sb;
    CHECK(stat(srcrel, &sa) == 0);
    CHECK(stat(strel, &sb) == 0);
    CHECK(sa.st_size == sb.st_size);
    FILE *fa = fopen(srcrel, "rb"), *fb = fopen(strel, "rb");
    CHECK(fa != NULL && fb != NULL);
    int same = 1;
    int ca, cb;
    do {
        ca = fgetc(fa);
        cb = fgetc(fb);
        if (ca != cb) {
            same = 0;
            break;
        }
    } while (ca != EOF);
    CHECK(same == 1);
    fclose(fa);
    fclose(fb);
    cask_close(&st);
}

int main(void) {
    init_paths();
    test_crc32_known();
    test_sha256_known();
    test_key_hex();

    {
        cask_file st;
        CHECK(cask_init(&st, path_buf[0]) == CASK_OK);
        test_store_roundtrip(&st);
        test_store_dedup(&st);
        test_store_verify_clean(&st);
        cask_close(&st);

        CHECK(cask_open(&st, path_buf[0]) == CASK_OK);
        test_store_verify_clean(&st);
        int present = 0;
        unsigned char any[32];
        memset(any, 0, 32);
        CHECK(cask_has(&st, any, &present) == CASK_OK);
        cask_close(&st);
    }

    test_corruption_recovery(path_buf[1]);
    test_crash_tail_junk(path_buf[2]);

    {
        char src[600];
        snprintf(src, sizeof(src), "%s/cask-src-%d.bin", TMPDIR, getpid());
        test_put_file(src, path_buf[3]);
        remove(src);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}