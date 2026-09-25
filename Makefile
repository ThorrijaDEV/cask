CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
BIN     := cask
SRC     := src/crc32.c src/sha256.c src/store.c src/main.c
OBJ     := $(SRC:.c=.o)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: tests/run_tests
	./tests/run_tests

tests/run_tests: src/crc32.c src/sha256.c src/store.c tests/run_tests.c
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all -o $@ \
	    src/crc32.c src/sha256.c src/store.c tests/run_tests.c

clean:
	rm -f $(BIN) $(OBJ) tests/run_tests

.PHONY: all test clean