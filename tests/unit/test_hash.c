/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_hash.h"


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


void
run_hash_tests(void)
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
}
