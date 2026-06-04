# Makefile for auth-webauthn-admin CLI
#
# Build the standalone CLI that registers / revokes / lists / shows WebAuthn
# credentials in Redis. Shares source with the NGINX module (src/).
#
# The shared src/ngx_auth_webauthn_*.c files are written against the nginx
# core API (ngx_pool_t / ngx_str_t / ngx_log_error / ngx_*_base64url), the
# same as every sibling module.  This CLI has no nginx runtime, so it links a
# small ngx_compat/ shim that provides a malloc-backed ngx_pool_t and the
# handful of ngx core helpers the shared code and nxe-json depend on.
# That shim IS the "override the nginx dependency for the CLI" mechanism;
# the module build links the real nginx core instead.

TARGET      := auth-webauthn-admin

CC          ?= gcc
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin

SRC_DIR     := ../../src
NXE_JSON_DIR := ../../nxe-json/src
COMPAT_DIR  := ngx_compat
ADMIN_DIR   := .
BUILD_DIR   := build

WARN_FLAGS  := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
               -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes

# ngx_compat is included FIRST so its ngx_core.h / ngx_config.h shadow the
# real nginx headers, redirecting them to the shim.
BASE_CFLAGS := -std=c11 -D_GNU_SOURCE $(WARN_FLAGS) \
               -I$(COMPAT_DIR) -I$(SRC_DIR) -I$(NXE_JSON_DIR) -I$(ADMIN_DIR)

ifeq ($(DEBUG),1)
CFLAGS      ?= -O0 -g3 $(BASE_CFLAGS)
else
CFLAGS      ?= -O2 -g $(BASE_CFLAGS)
endif

ifeq ($(ASAN),1)
CFLAGS      += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS     += -fsanitize=address
endif

# jansson: pulled in by nxe-json.  cbor: COSE / attestationObject parsing.
# hiredis: Redis store.  crypto: OpenSSL EVP (COSE->DER, hashing).
LDLIBS      := -lcrypto -ljansson -lhiredis -lcbor

# nginx-core shim (override layer for the no-nginx CLI build).
COMPAT_SRCS := \
    $(COMPAT_DIR)/ngx_compat.c

# nxe-json submodule source, compiled straight into the CLI (same files the
# module links via config -> nxe-json/config.ngx).
NXE_SRCS    := \
    $(NXE_JSON_DIR)/nxe_json.c

# Shared sources: the NGINX-independent-usable subset of ngx_auth_webauthn_*.
# These are the registration-path modules; the module build adds the rest
# (challenge / assertion / verify handlers) on top of the same files.
# base64url is not a file here: it comes from nginx core / the shim.
SHARED_SRCS := \
    $(SRC_DIR)/ngx_auth_webauthn_hash.c \
    $(SRC_DIR)/ngx_auth_webauthn_redis.c \
    $(SRC_DIR)/ngx_auth_webauthn_credential.c \
    $(SRC_DIR)/ngx_auth_webauthn_cose.c \
    $(SRC_DIR)/ngx_auth_webauthn_authdata.c \
    $(SRC_DIR)/ngx_auth_webauthn_attestation.c

ADMIN_SRCS  := \
    auth_webauthn_admin_main.c \
    auth_webauthn_admin_register.c \
    auth_webauthn_admin_revoke.c \
    auth_webauthn_admin_list.c \
    auth_webauthn_admin_show.c

COMPAT_OBJS := $(patsubst $(COMPAT_DIR)/%.c,$(BUILD_DIR)/compat/%.o,$(COMPAT_SRCS))
NXE_OBJS    := $(patsubst $(NXE_JSON_DIR)/%.c,$(BUILD_DIR)/nxe/%.o,$(NXE_SRCS))
SHARED_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/shared/%.o,$(SHARED_SRCS))
ADMIN_OBJS  := $(patsubst %.c,$(BUILD_DIR)/admin/%.o,$(ADMIN_SRCS))
OBJS        := $(COMPAT_OBJS) $(NXE_OBJS) $(SHARED_OBJS) $(ADMIN_OBJS)
DEPS        := $(OBJS:.o=.d)

.PHONY: all clean install uninstall format

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/compat/%.o: $(COMPAT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD_DIR)/nxe/%.o: $(NXE_JSON_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD_DIR)/shared/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILD_DIR)/admin/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

format:
	uncrustify -c ../../.uncrustify.cfg -l c --no-backup --replace --mtime \
	    $(ADMIN_SRCS) $(wildcard *.h)

-include $(DEPS)
