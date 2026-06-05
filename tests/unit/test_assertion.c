/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_assertion.h"

/*
 * ES256 assertion test vectors generated with python `cryptography`
 * (random EC P-256 key).  rpId "example.com", origin "https://example.com",
 * challenge = bytes 0x00..0x1f.  For each authData variant:
 *   signedData = authData || SHA256(clientDataJSON), signed with ECDSA/SHA-256
 *   (DER signature).  Variants: valid (flags UP|UV), up_clear (UV only),
 *   ed_set (UP|ED).  signCount = 5 in all.
 */

static const u_char pubkey_der[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x70, 0xcd, 0x9e, 0x48, 0xab, 0x71, 0xb8, 0x40, 0xd1,
    0x92, 0x86, 0x2f, 0x9d, 0x3b, 0x1f, 0x19, 0x33, 0xfc, 0x3e, 0x2c, 0xab,
    0x0a, 0xb8, 0xe4, 0xcb, 0x12, 0xe9, 0x84, 0x5d, 0xd2, 0x8b, 0x6c, 0x46,
    0x34, 0x23, 0x06, 0xed, 0x28, 0x7a, 0x6d, 0x82, 0x46, 0x92, 0xed, 0x71,
    0x71, 0xa6, 0xe7, 0x9e, 0x2b, 0x3c, 0x2d, 0x0b, 0x7c, 0xd5, 0x35, 0x88,
    0x6d, 0x60, 0xa1, 0xf4, 0x35, 0x53, 0x55,
};

static const u_char challenge_raw[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const char client_data_json[] =
    "{\"type\":\"webauthn.get\","
    "\"challenge\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\","
    "\"origin\":\"https://example.com\"}";

static const u_char authdata_valid[] = {
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x05, 0x00, 0x00, 0x00,
    0x05,
};

static const u_char sig_valid[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0xae, 0xe8, 0xa3, 0x32, 0xe0, 0x5d, 0x55,
    0xea, 0x47, 0x21, 0x6d, 0x67, 0x48, 0x3a, 0xa3, 0x52, 0x7c, 0x92, 0x20,
    0xb1, 0xd2, 0xe0, 0x57, 0x40, 0xe1, 0x30, 0x87, 0xff, 0xcb, 0x3a, 0x6f,
    0x12, 0x02, 0x20, 0x76, 0xa0, 0x00, 0xa8, 0xf9, 0x7c, 0xa5, 0x69, 0xa3,
    0xd2, 0x18, 0xee, 0xec, 0x67, 0x38, 0x50, 0xb5, 0x7c, 0x99, 0xb8, 0x00,
    0x98, 0x62, 0xa9, 0x59, 0x38, 0x75, 0x3c, 0x82, 0xec, 0xba, 0x7e,
};

static const u_char authdata_up_clear[] = {
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x04, 0x00, 0x00, 0x00,
    0x05,
};

static const u_char sig_up_clear[] = {
    0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0xf0, 0xec, 0xe6, 0x14, 0x2f, 0x9d,
    0xa1, 0x0b, 0x25, 0xa2, 0x7b, 0xd6, 0x07, 0x4d, 0x3f, 0xd1, 0x12, 0x97,
    0x84, 0xe1, 0x55, 0x37, 0xbe, 0x41, 0x7f, 0xd3, 0x60, 0xe3, 0xec, 0x01,
    0xf6, 0x02, 0x21, 0x00, 0x89, 0x9c, 0x06, 0x28, 0x71, 0x1f, 0xea, 0xeb,
    0x9c, 0x0f, 0x53, 0xa4, 0xf0, 0xd2, 0x65, 0xdf, 0x68, 0x61, 0xf9, 0x93,
    0xf3, 0xf6, 0x4d, 0x0e, 0x45, 0x94, 0x6e, 0x98, 0x06, 0x60, 0xc5, 0x9f,
};

static const u_char authdata_ed_set[] = {
    0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11,
    0x80, 0x34, 0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab,
    0x13, 0xd2, 0x12, 0x55, 0x86, 0xce, 0x19, 0x47, 0x85, 0x00, 0x00, 0x00,
    0x05,
};

static const u_char sig_ed_set[] = {
    0x30, 0x44, 0x02, 0x20, 0x3f, 0x6e, 0x17, 0x4d, 0x86, 0x29, 0xbf, 0xdf,
    0x56, 0x26, 0x1b, 0xb8, 0x8f, 0x29, 0x36, 0x58, 0xf3, 0xc4, 0x95, 0xb4,
    0x50, 0x91, 0xb6, 0x2c, 0xb6, 0x7f, 0x38, 0xe1, 0xa5, 0x49, 0xce, 0x8e,
    0x02, 0x20, 0x79, 0x39, 0xaf, 0x9d, 0xaf, 0x6c, 0xf1, 0x3f, 0x83, 0x7c,
    0x76, 0xaa, 0x3c, 0x60, 0x37, 0xf9, 0x8d, 0x97, 0xd1, 0x9e, 0x48, 0x50,
    0x54, 0x65, 0x58, 0x33, 0x29, 0x61, 0x7f, 0x15, 0xb2, 0x17,
};


/* Build the fixed parts and run a verification with the given policy/inputs. */
static ngx_int_t
verify_with(ngx_pool_t *pool, const u_char *ad, size_t adlen,
    const u_char *sig, size_t siglen,
    ngx_auth_webauthn_assertion_policy_t *policy, uint32_t stored,
    ngx_auth_webauthn_assertion_result_t *result)
{
    ngx_auth_webauthn_assertion_t       a;
    ngx_auth_webauthn_assertion_cred_t  cred;

    a.authenticator_data.data = (u_char *) ad;
    a.authenticator_data.len = adlen;
    a.client_data_json.data = (u_char *) client_data_json;
    a.client_data_json.len = sizeof(client_data_json) - 1;
    a.signature.data = (u_char *) sig;
    a.signature.len = siglen;

    cred.public_key.data = (u_char *) pubkey_der;
    cred.public_key.len = sizeof(pubkey_der);
    cred.alg = -7;
    cred.sign_count = stored;

    return ngx_auth_webauthn_assertion_verify(pool, &a, &cred, policy, result);
}


static void
base_policy(ngx_auth_webauthn_assertion_policy_t *p, ngx_str_t *origins)
{
    ngx_str_set(&p->rp_id, "example.com");
    p->expected_challenge.data = (u_char *) challenge_raw;
    p->expected_challenge.len = sizeof(challenge_raw);
    ngx_str_set(&origins[0], "https://example.com");
    p->allowed_origins = origins;
    p->norigins = 1;
    p->require_uv = 0;
    p->clone_detection = NGX_AUTH_WEBAUTHN_CLONE_STRICT;
}


void
run_assertion_tests(void)
{
    ngx_auth_webauthn_assertion_policy_t  policy;
    ngx_auth_webauthn_assertion_result_t  result;
    ngx_str_t                             origins[1];
    ngx_pool_t                           *pool;
    u_char                                tampered[sizeof(sig_valid)];
    ngx_int_t                             rc;

    pool = ngx_create_pool(8192, NULL);
    CHECK(pool != NULL, "assertion: pool created");
    if (pool == NULL) {
        return;
    }

    /* valid: stored counter below received -> OK, returns received count */
    base_policy(&policy, origins);
    result.auth_sign_count = 0;
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 4, &result);
    CHECK(rc == NGX_OK, "assertion valid: NGX_OK");
    CHECK(result.auth_sign_count == 5, "assertion valid: returns signCount");

    /* require_uv with UV present -> OK */
    base_policy(&policy, origins);
    policy.require_uv = 1;
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 4, &result);
    CHECK(rc == NGX_OK, "assertion require_uv present: NGX_OK");

    /* tampered signature -> DECLINED */
    base_policy(&policy, origins);
    ngx_memcpy(tampered, sig_valid, sizeof(sig_valid));
    tampered[sizeof(tampered) - 1] ^= 0x01;
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        tampered, sizeof(tampered), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion tampered sig: NGX_DECLINED");

    /* rpId mismatch -> DECLINED */
    base_policy(&policy, origins);
    ngx_str_set(&policy.rp_id, "evil.com");
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion rpId mismatch: NGX_DECLINED");

    /* origin not allowed -> DECLINED */
    base_policy(&policy, origins);
    ngx_str_set(&origins[0], "https://evil.example");
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion bad origin: NGX_DECLINED");

    /* challenge mismatch -> DECLINED */
    base_policy(&policy, origins);
    policy.expected_challenge.data = (u_char *) pubkey_der;  /* wrong bytes */
    policy.expected_challenge.len = sizeof(challenge_raw);
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion challenge mismatch: NGX_DECLINED");

    /* User Present flag clear -> DECLINED */
    base_policy(&policy, origins);
    rc = verify_with(pool, authdata_up_clear, sizeof(authdata_up_clear),
        sig_up_clear, sizeof(sig_up_clear), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion UP clear: NGX_DECLINED");

    /* Extension-data flag set -> DECLINED */
    base_policy(&policy, origins);
    rc = verify_with(pool, authdata_ed_set, sizeof(authdata_ed_set),
        sig_ed_set, sizeof(sig_ed_set), &policy, 4, &result);
    CHECK(rc == NGX_DECLINED, "assertion ED set: NGX_DECLINED");

    /* clone detection: equal counter, strict -> DECLINED */
    base_policy(&policy, origins);
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 5, &result);
    CHECK(rc == NGX_DECLINED, "assertion clone strict equal: NGX_DECLINED");

    /* clone detection: equal counter, lax -> OK */
    base_policy(&policy, origins);
    policy.clone_detection = NGX_AUTH_WEBAUTHN_CLONE_LAX;
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 5, &result);
    CHECK(rc == NGX_OK, "assertion clone lax equal: NGX_OK");

    /* clone detection: counter regression, strict -> DECLINED */
    base_policy(&policy, origins);
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 10, &result);
    CHECK(rc == NGX_DECLINED, "assertion clone strict regress: NGX_DECLINED");

    /* clone detection: off, counter regression -> OK */
    base_policy(&policy, origins);
    policy.clone_detection = NGX_AUTH_WEBAUTHN_CLONE_OFF;
    rc = verify_with(pool, authdata_valid, sizeof(authdata_valid),
        sig_valid, sizeof(sig_valid), &policy, 10, &result);
    CHECK(rc == NGX_OK, "assertion clone off regress: NGX_OK");

    /* NULL argument -> ERROR */
    base_policy(&policy, origins);
    rc = ngx_auth_webauthn_assertion_verify(pool, NULL, NULL, &policy,
        &result);
    CHECK(rc == NGX_ERROR, "assertion NULL args: NGX_ERROR");

    ngx_destroy_pool(pool);
}
