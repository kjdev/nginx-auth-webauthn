# Makefile for the ngx_auth_webauthn unit tests.
#
# The shared src/ngx_auth_webauthn_*.c sources are written against the nginx
# core API.  These tests have no nginx runtime, so they link the same
# ngx_compat/ shim the CLI uses (tools/admin/ngx_compat).  ngx_compat is on the
# include path FIRST so its ngx_core.h / ngx_config.h shadow the real nginx
# headers and redirect to the shim.

CC          ?= cc

SRC_DIR     := ../../src
COMPAT_DIR  := ../../tools/admin/ngx_compat

WARN_FLAGS  := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
               -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes

BASE_CFLAGS := -std=c11 -D_GNU_SOURCE $(WARN_FLAGS) \
               -I$(COMPAT_DIR) -I$(SRC_DIR)

CFLAGS      ?= -O2 -g $(BASE_CFLAGS)

# crypto: OpenSSL EVP (SHA-256 and, later, signature verification).
LDLIBS      := -lcrypto

SRCS        := \
    test_runner.c \
    $(COMPAT_DIR)/ngx_compat.c \
    $(SRC_DIR)/ngx_auth_webauthn_hash.c

.PHONY: test test-asan clean

test: test_runner.bin
	./test_runner.bin

test_runner.bin: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

test-asan: $(SRCS)
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer \
	    -o test_runner_asan.bin $(SRCS) $(LDLIBS) -fsanitize=address
	./test_runner_asan.bin

clean:
	rm -f test_runner.bin test_runner_asan.bin
