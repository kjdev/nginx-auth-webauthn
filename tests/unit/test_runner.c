/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * Unit test runner for the WebAuthn-specific shared layer
 * (ngx_auth_webauthn_*).  Built against the ngx_compat shim so it links the
 * same sources the module and CLI use, without an nginx runtime.  Plain
 * assert-style checks, no external test framework (cmocka etc.).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_hash.h"

#include <stdio.h>
#include <string.h>

static int  tests_run = 0;
static int  tests_failed = 0;

#define CHECK(cond, label)                                                   \
    do {                                                                     \
        tests_run++;                                                         \
        if (cond) {                                                          \
            printf("ok   - %s\n", (label));                                  \
        } else {                                                             \
            tests_failed++;                                                  \
            printf("FAIL - %s\n", (label));                                  \
        }                                                                    \
    } while (0)


static void
to_hex(const u_char *in, size_t n, char *out)
{
    static const char  hex[] = "0123456789abcdef";
    size_t             i;

    for (i = 0; i < n; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}


/*
 * Known-answer test: SHA-256(data) must equal the expected hex digest.
 * Vectors are from FIPS 180-2 / RFC 6234 (empty input, "abc", 56-byte
 * message).
 */
static void
test_sha256_vector(const char *name, const u_char *data, size_t len,
    const char *expected)
{
    u_char     digest[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    char       hex[NGX_AUTH_WEBAUTHN_SHA256_LEN * 2 + 1];
    char       label[128];
    ngx_int_t  rc;

    rc = ngx_auth_webauthn_hash_sha256(data, len, digest);

    snprintf(label, sizeof(label), "sha256 %s: returns NGX_OK", name);
    CHECK(rc == NGX_OK, label);

    to_hex(digest, sizeof(digest), hex);

    snprintf(label, sizeof(label), "sha256 %s: digest matches", name);
    CHECK(strcmp(hex, expected) == 0, label);

    if (strcmp(hex, expected) != 0) {
        printf("       expected %s\n", expected);
        printf("       got      %s\n", hex);
    }
}


static void
test_sha256_null_out(void)
{
    ngx_int_t  rc;

    rc = ngx_auth_webauthn_hash_sha256((const u_char *) "abc", 3, NULL);
    CHECK(rc == NGX_ERROR, "sha256 NULL out: returns NGX_ERROR");
}


int
main(void)
{
    test_sha256_vector("empty", (const u_char *) "", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    test_sha256_vector("abc", (const u_char *) "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    test_sha256_vector("56-byte",
        (const u_char *)
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    test_sha256_null_out();

    printf("\n%d tests, %d failed\n", tests_run, tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
