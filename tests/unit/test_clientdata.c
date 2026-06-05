/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_clientdata.h"

#include <stdlib.h>


/* The 32-byte raw challenge the tests issue and expect back. */
static const u_char  challenge_raw[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};


static void
encode_challenge(ngx_pool_t *pool, ngx_str_t *out)
{
    ngx_str_t  src;

    src.data = (u_char *) challenge_raw;
    src.len = sizeof(challenge_raw);

    out->data = ngx_pnalloc(pool, ngx_base64_encoded_length(src.len));
    ngx_encode_base64url(out, &src);
}


/* Run clientdata_verify against a JSON document and assert the result. */
static void
run_case(ngx_pool_t *pool, const char *label, const char *json,
    ngx_int_t expected)
{
    ngx_str_t   type = ngx_string("webauthn.get");
    ngx_str_t   challenge;
    ngx_str_t   origins[] = { ngx_string("https://example.com") };
    ngx_int_t   rc;

    challenge.data = (u_char *) challenge_raw;
    challenge.len = sizeof(challenge_raw);

    rc = ngx_auth_webauthn_clientdata_verify(pool, (const u_char *) json,
        strlen(json), &type, &challenge, origins, 1);

    CHECK(rc == expected, label);
    if (rc != expected) {
        printf("       expected %ld, got %ld\n", (long) expected, (long) rc);
    }
}


void
run_clientdata_tests(void)
{
    ngx_pool_t  *pool;
    ngx_str_t    b64;
    char         json[512];

    pool = ngx_create_pool(4096, NULL);
    CHECK(pool != NULL, "clientdata: pool created");
    if (pool == NULL) {
        return;
    }

    encode_challenge(pool, &b64);

    /* valid */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.get\",\"challenge\":\"%.*s\","
        "\"origin\":\"https://example.com\",\"crossOrigin\":false}",
        (int) b64.len, b64.data);
    run_case(pool, "clientdata valid: NGX_OK", json, NGX_OK);

    /* valid without crossOrigin key */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.get\",\"challenge\":\"%.*s\","
        "\"origin\":\"https://example.com\"}",
        (int) b64.len, b64.data);
    run_case(pool, "clientdata no crossOrigin: NGX_OK", json, NGX_OK);

    /* wrong type */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.create\",\"challenge\":\"%.*s\","
        "\"origin\":\"https://example.com\"}",
        (int) b64.len, b64.data);
    run_case(pool, "clientdata wrong type: NGX_DECLINED", json, NGX_DECLINED);

    /* wrong challenge (valid base64url, different bytes) */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.get\",\"challenge\":\"%s\","
        "\"origin\":\"https://example.com\"}",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    run_case(pool, "clientdata wrong challenge: NGX_DECLINED", json,
        NGX_DECLINED);

    /* disallowed origin */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.get\",\"challenge\":\"%.*s\","
        "\"origin\":\"https://evil.example\"}",
        (int) b64.len, b64.data);
    run_case(pool, "clientdata bad origin: NGX_DECLINED", json, NGX_DECLINED);

    /* crossOrigin true */
    snprintf(json, sizeof(json),
        "{\"type\":\"webauthn.get\",\"challenge\":\"%.*s\","
        "\"origin\":\"https://example.com\",\"crossOrigin\":true}",
        (int) b64.len, b64.data);
    run_case(pool, "clientdata crossOrigin true: NGX_DECLINED", json,
        NGX_DECLINED);

    /* malformed JSON */
    run_case(pool, "clientdata malformed: NGX_DECLINED",
        "{\"type\":\"webauthn.get\",", NGX_DECLINED);

    ngx_destroy_pool(pool);
}
