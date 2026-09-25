#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "store.h"

static void usage(const char *prog) {
    fprintf(stderr,
            "cask — content-addressable append-only store (C, zero deps)\n"
            "\n"
            "usage:\n"
            "  %s init <store>                  create a new store\n"
            "  %s put <store> <file...>         add files (dedup by SHA-256); '-' = stdin\n"
            "  %s get <store> <sha256> [-o out] extract an object (default: stdout)\n"
            "  %s has <store> <sha256>          check membership\n"
            "  %s verify <store>                validate structure + checksums\n"
            "  %s recover <store>               truncate to last intact write\n"
            "  %s dump <store>                  list objects\n"
            "  %s info <store>                  show store summary\n"
            "\n",
            prog, prog, prog, prog, prog, prog, prog, prog);
}

static int parse_key(const char *hex, unsigned char key[32]) {
    if (hex == NULL || strlen(hex) != 64 || !cask_key_from_hex(hex, key)) {
        fprintf(stderr, "cask: invalid key (expected 64 hex chars)\n");
        return -1;
    }
    return 0;
}

static int cmd_init(int argc, char **argv) {
    if (argc < 3) {
        usage("cask");
        return 1;
    }
    cask_file st;
    cask_rc rc = cask_init(&st, argv[2]);
    if (rc != CASK_OK) {
        fprintf(stderr, "cask: %s\n", cask_strerror(rc));
        return 1;
    }
    printf("initialized %s (format v%u)\n", argv[2], CASK_VERSION);
    cask_close(&st);
    return 0;
}

static int open_store(const char *path, cask_file *st) {
    cask_rc rc = cask_open(st, path);
    if (rc != CASK_OK) {
        fprintf(stderr, "cask: %s: %s\n", path,
                st->err[0] ? st->err : cask_strerror(rc));
        return -1;
    }
    return 0;
}

static int cmd_put(int argc, char **argv) {
    if (argc < 4) {
        usage("cask");
        return 1;
    }
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    int added_total = 0, skipped = 0;
    for (int i = 3; i < argc; i++) {
        const char *src = argv[i];
        unsigned char key[32];
        int added = 0;
        cask_rc rc;
        if (strcmp(src, "-") == 0) {
            FILE *tmp = tmpfile();
            if (!tmp) {
                fprintf(stderr, "cask: cannot create temp file\n");
                cask_close(&st);
                return 1;
            }
            char buf[65536];
            size_t rd;
            while ((rd = fread(buf, 1, sizeof(buf), stdin)) > 0)
                fwrite(buf, 1, rd, tmp);
            fflush(tmp);
            rewind(tmp);
            /* reuse put_file by writing stdin to a temp path via /proc? no:
               bridge via put_mem reading the temp file */
            long n = ftell(tmp);
            rewind(tmp);
            unsigned char *mem = malloc(n > 0 ? (size_t)n : 1);
            if (!mem) {
                fclose(tmp);
                cask_close(&st);
                return 1;
            }
            if (n > 0 && fread(mem, 1, (size_t)n, tmp) != (size_t)n) {
                free(mem);
                fclose(tmp);
                cask_close(&st);
                return 1;
            }
            fclose(tmp);
            rc = cask_put_mem(&st, mem, (size_t)n, key, &added);
            free(mem);
        } else {
            rc = cask_put_file(&st, src, key, &added);
        }
        if (rc != CASK_OK) {
            fprintf(stderr, "cask: put %s: %s\n", src, cask_strerror(rc));
            cask_close(&st);
            return 1;
        }
        char hex[65];
        cask_key_to_hex(key, hex);
        if (added) {
            printf("added   %s\n", hex);
            added_total++;
        } else {
            printf("skipped %s (duplicate)\n", hex);
            skipped++;
        }
    }
    printf("# %d added, %d skipped, %llu objects\n", added_total, skipped,
           (unsigned long long)st.count);
    cask_close(&st);
    return 0;
}

static int cmd_has(int argc, char **argv) {
    if (argc < 4) {
        usage("cask");
        return 1;
    }
    unsigned char key[32];
    if (parse_key(argv[3], key) != 0)
        return 1;
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    int present = 0;
    cask_rc rc = cask_has(&st, key, &present);
    if (rc != CASK_OK) {
        fprintf(stderr, "cask: %s\n", cask_strerror(rc));
        cask_close(&st);
        return 1;
    }
    printf(present ? "yes\n" : "no\n");
    cask_close(&st);
    return present ? 0 : 1;
}

static int cmd_get(int argc, char **argv) {
    if (argc < 4) {
        usage("cask");
        return 1;
    }
    const char *outfile = NULL;
    for (int i = 4; i < argc - 1; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            outfile = argv[i + 1];
            i++;
        }
    }
    unsigned char key[32];
    if (parse_key(argv[3], key) != 0)
        return 1;
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    cask_rc rc = cask_get_stream(&st, key, outfile);
    cask_close(&st);
    if (rc != CASK_OK) {
        fprintf(stderr, "cask: %s\n", cask_strerror(rc));
        return 1;
    }
    return 0;
}

struct dump_ud {
    uint64_t n;
    uint64_t bytes;
    int stop;
};

static int dump_cb(void *ud, const unsigned char key[32], uint64_t size, uint64_t off,
                   uint32_t crc) {
    struct dump_ud *d = (struct dump_ud *)ud;
    char hex[65];
    cask_key_to_hex(key, hex);
    printf("%-64s %8lluB  off=%llu\n", hex, (unsigned long long)size, (unsigned long long)off);
    (void)crc;
    d->n++;
    d->bytes += size;
    return 0;
}

static int cmd_dump(int argc, char **argv) {
    if (argc < 3) {
        usage("cask");
        return 1;
    }
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    struct dump_ud d = {0, 0, 0};
    cask_walk(&st, st.count, dump_cb, &d, &d.stop);
    printf("# %llu objects, %llu bytes payload\n", (unsigned long long)d.n,
           (unsigned long long)d.bytes);
    cask_close(&st);
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    if (argc < 3) {
        usage("cask");
        return 1;
    }
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    uint64_t verified = 0, end = 0;
    cask_rc rc = cask_verify(&st, &verified, &end);
    cask_close(&st);
    if (rc == CASK_OK) {
        printf("ok: %llu objects, all crc32+sha256 intact\n", (unsigned long long)verified);
        return 0;
    }
    if (rc == CASK_ERR_CORRUPT) {
        printf("corrupt: only %llu intact objects, tail at %llu (run `cask recover`)\n",
               (unsigned long long)verified, (unsigned long long)end);
        return 1;
    }
    fprintf(stderr, "cask: %s\n", cask_strerror(rc));
    return 1;
}

static int cmd_recover(int argc, char **argv) {
    if (argc < 3) {
        usage("cask");
        return 1;
    }
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    cask_rc rc = cask_recover(&st);
    cask_close(&st);
    if (rc != CASK_OK) {
        fprintf(stderr, "cask: %s\n", cask_strerror(rc));
        return 1;
    }
    printf("recovered\n");
    return 0;
}

static int cmd_info(int argc, char **argv) {
    if (argc < 3) {
        usage("cask");
        return 1;
    }
    struct stat sb;
    if (stat(argv[2], &sb) != 0) {
        fprintf(stderr, "cask: %s: %s\n", argv[2], strerror(errno));
        return 1;
    }
    cask_file st;
    if (open_store(argv[2], &st) != 0)
        return 1;
    uint64_t fsize = (uint64_t)sb.st_size;
    printf("store:        %s\n", st.path);
    printf("format:       v%u\n", CASK_VERSION);
    printf("objects:      %llu\n", (unsigned long long)st.count);
    printf("tail:         %llu bytes\n", (unsigned long long)st.tail);
    printf("file size:    %llu bytes\n", (unsigned long long)fsize);
    printf("physical tail:%llu bytes\n", (unsigned long long)(fsize >= st.tail ? fsize : st.tail));
    if (st.truncated)
        printf("status:       TRUNCATED (payload lost past superblock tail)\n");
    else if (fsize > st.tail)
        printf("status:       uncommitted tail junk present\n");
    else
        printf("status:       clean\n");
    cask_close(&st);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "init") == 0)
        return cmd_init(argc, argv);
    if (strcmp(cmd, "put") == 0)
        return cmd_put(argc, argv);
    if (strcmp(cmd, "get") == 0)
        return cmd_get(argc, argv);
    if (strcmp(cmd, "has") == 0)
        return cmd_has(argc, argv);
    if (strcmp(cmd, "verify") == 0)
        return cmd_verify(argc, argv);
    if (strcmp(cmd, "recover") == 0)
        return cmd_recover(argc, argv);
    if (strcmp(cmd, "dump") == 0)
        return cmd_dump(argc, argv);
    if (strcmp(cmd, "info") == 0)
        return cmd_info(argc, argv);
    usage(argv[0]);
    return 1;
}