/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_attestation.h"
#include "ngx_auth_webauthn_authdata.h"
#include "ngx_auth_webauthn_hash.h"

#include <stdlib.h>
#include <cbor.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

/*
 * Attestation tests build self-contained attestationObjects at runtime: an
 * ES256 key is generated, packed into a COSE_Key / authData, and (for "packed")
 * self-signed over authData || clientDataHash.  This avoids brittle hand-coded
 * CBOR vectors and exercises the full parse + verify path against real crypto.
 */

#define RP_ID         "example.com"
#define CRED_ID_LEN   4


/* Add (key, value) to a definite map, releasing the local references.  A
 * failure here means a test-setup allocation problem, so abort loudly. */
static void
map_add(cbor_item_t *map, cbor_item_t *key, cbor_item_t *value)
{
    if (!cbor_map_add(map, (struct cbor_pair){ .key = key, .value = value })) {
        abort();
    }
    cbor_decref(&key);
    cbor_decref(&value);
}


/* Build a COSE_Key (ES256) for the given P-256 coordinates, serialized into a
 * malloc buffer the caller frees. */
static u_char *
build_cose_es256(const u_char *x, const u_char *y, size_t *out_len)
{
    u_char       *buf = NULL;
    size_t        buflen;
    cbor_item_t  *cose;

    cose = cbor_new_definite_map(5);

    map_add(cose, cbor_build_uint8(1), cbor_build_uint8(2));         /* kty EC2 */
    map_add(cose, cbor_build_uint8(3), cbor_build_negint8(6));       /* alg -7 */
    map_add(cose, cbor_build_negint8(0), cbor_build_uint8(1));       /* crv P-256 */
    map_add(cose, cbor_build_negint8(1), cbor_build_bytestring(x, 32));
    map_add(cose, cbor_build_negint8(2), cbor_build_bytestring(y, 32));

    buflen = cbor_serialize_alloc(cose, &buf, NULL);
    cbor_decref(&cose);

    *out_len = buflen;
    return buf;
}


/* Build authData with AT set: rpIdHash || flags || signCount || aaguid ||
 * credIdLen || credId || cosePublicKey.  Allocated from pool. */
static ngx_int_t
build_authdata(ngx_pool_t *pool, const u_char *cose, size_t cose_len,
    ngx_str_t *out)
{
    u_char  *p;
    size_t   len;

    len = NGX_AUTH_WEBAUTHN_AUTHDATA_MIN_LEN + NGX_AUTH_WEBAUTHN_AAGUID_LEN
          + 2 + CRED_ID_LEN + cose_len;

    p = ngx_palloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    out->len = len;

    if (ngx_auth_webauthn_hash_sha256((const u_char *) RP_ID,
            sizeof(RP_ID) - 1, p) != NGX_OK)
    {
        return NGX_ERROR;
    }
    p += NGX_AUTH_WEBAUTHN_SHA256_LEN;

    *p++ = NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UP
           | NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UV
           | NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT;

    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* signCount = 0 */

    ngx_memzero(p, NGX_AUTH_WEBAUTHN_AAGUID_LEN);
    p += NGX_AUTH_WEBAUTHN_AAGUID_LEN;

    *p++ = 0; *p++ = CRED_ID_LEN;                      /* credIdLen */
    ngx_memset(p, 0xAB, CRED_ID_LEN);                  /* credId */
    p += CRED_ID_LEN;

    ngx_memcpy(p, cose, cose_len);

    return NGX_OK;
}


/*
 * Serialize an attestationObject.  fmt selects the format.  When sig != NULL a
 * packed attStmt {alg:-7, sig} is added; when with_x5c is set an x5c array is
 * also added.  Result is malloc'd; caller frees.
 */
static u_char *
build_att_obj(const char *fmt, const u_char *authdata, size_t authlen,
    const u_char *sig, size_t siglen, int with_x5c, size_t *out_len)
{
    u_char       *buf = NULL;
    size_t        buflen;
    cbor_item_t  *att;
    cbor_item_t  *stmt;
    cbor_item_t  *arr;
    cbor_item_t  *cert;

    att = cbor_new_definite_map(3);

    map_add(att, cbor_build_string("fmt"), cbor_build_string(fmt));

    if (sig != NULL) {
        stmt = cbor_new_definite_map(with_x5c ? 3 : 2);
        map_add(stmt, cbor_build_string("alg"), cbor_build_negint8(6));
        map_add(stmt, cbor_build_string("sig"),
            cbor_build_bytestring(sig, siglen));
        if (with_x5c) {
            arr = cbor_new_definite_array(1);
            cert = cbor_build_bytestring((const u_char *) "\x01\x02\x03", 3);
            if (!cbor_array_push(arr, cert)) {
                abort();
            }
            cbor_decref(&cert);
            map_add(stmt, cbor_build_string("x5c"), arr);
        }
        map_add(att, cbor_build_string("attStmt"), stmt);
    } else {
        map_add(att, cbor_build_string("attStmt"), cbor_new_definite_map(0));
    }

    map_add(att, cbor_build_string("authData"),
        cbor_build_bytestring(authdata, authlen));

    buflen = cbor_serialize_alloc(att, &buf, NULL);
    cbor_decref(&att);

    *out_len = buflen;
    return buf;
}


/* Generate a P-256 key and emit its COSE_Key plus the EVP_PKEY handle. */
static EVP_PKEY *
gen_es256(u_char **cose, size_t *cose_len)
{
    u_char     pub[200];
    size_t     publen = 0;
    EVP_PKEY  *pkey;

    pkey = EVP_EC_gen("P-256");
    if (pkey == NULL) {
        return NULL;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub,
            sizeof(pub), &publen) != 1
        || publen != 65 || pub[0] != 0x04)
    {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    *cose = build_cose_es256(pub + 1, pub + 33, cose_len);
    if (*cose == NULL) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}


/* ECDSA/SHA-256 sign data, returning a malloc'd DER signature. */
static u_char *
sign_es256(EVP_PKEY *pkey, const u_char *data, size_t len, size_t *sig_len)
{
    u_char      *sig = NULL;
    size_t       n = 0;
    EVP_MD_CTX  *ctx;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1
        || EVP_DigestSign(ctx, NULL, &n, data, len) != 1
        || (sig = malloc(n)) == NULL
        || EVP_DigestSign(ctx, sig, &n, data, len) != 1)
    {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    *sig_len = n;
    return sig;
}


static void
test_attestation_none(ngx_pool_t *pool)
{
    u_char                            *cose = NULL;
    u_char                            *obj = NULL;
    size_t                             cose_len = 0;
    size_t                             obj_len = 0;
    ngx_str_t                          authdata;
    ngx_str_t                          rp_id = ngx_string(RP_ID);
    ngx_str_t                          bad_rp = ngx_string("evil.com");
    ngx_str_t                          cdh;
    u_char                             hash[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    ngx_int_t                          rc;
    EVP_PKEY                          *pkey;
    ngx_auth_webauthn_attestation_t    att;

    pkey = gen_es256(&cose, &cose_len);
    CHECK(pkey != NULL, "attestation none: key generated");
    if (pkey == NULL) {
        return;
    }

    rc = build_authdata(pool, cose, cose_len, &authdata);
    CHECK(rc == NGX_OK, "attestation none: authData built");

    obj = build_att_obj("none", authdata.data, authdata.len, NULL, 0, 0,
        &obj_len);
    CHECK(obj != NULL, "attestation none: object built");

    rc = ngx_auth_webauthn_attestation_parse(pool, obj, obj_len, &att);
    CHECK(rc == NGX_OK, "attestation none: parse NGX_OK");
    CHECK(att.fmt.len == 4 && ngx_memcmp(att.fmt.data, "none", 4) == 0,
        "attestation none: fmt == none");
    CHECK(att.auth_data.len == authdata.len, "attestation none: authData len");

    ngx_auth_webauthn_hash_sha256((const u_char *) "cdj", 3, hash);
    cdh.data = hash;
    cdh.len = sizeof(hash);

    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_NONE);
    CHECK(rc == NGX_OK, "attestation none: verify NONE NGX_OK");

    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_PACKED);
    CHECK(rc == NGX_OK, "attestation none: verify PACKED accepts none");

    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &bad_rp, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_NONE);
    CHECK(rc == NGX_DECLINED, "attestation none: rpId mismatch NGX_DECLINED");

    free(cose);
    free(obj);
    EVP_PKEY_free(pkey);
}


static void
test_attestation_packed(ngx_pool_t *pool)
{
    u_char                            *cose = NULL;
    u_char                            *obj = NULL;
    u_char                            *sig = NULL;
    u_char                            *signed_data;
    size_t                             cose_len = 0;
    size_t                             obj_len = 0;
    size_t                             sig_len = 0;
    ngx_str_t                          authdata;
    ngx_str_t                          rp_id = ngx_string(RP_ID);
    ngx_str_t                          cdh;
    u_char                             hash[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    ngx_int_t                          rc;
    EVP_PKEY                          *pkey;
    ngx_auth_webauthn_attestation_t    att;

    pkey = gen_es256(&cose, &cose_len);
    CHECK(pkey != NULL, "attestation packed: key generated");
    if (pkey == NULL) {
        return;
    }

    rc = build_authdata(pool, cose, cose_len, &authdata);
    CHECK(rc == NGX_OK, "attestation packed: authData built");

    /* clientDataHash + signedData = authData || clientDataHash */
    ngx_auth_webauthn_hash_sha256((const u_char *) "cdj", 3, hash);
    cdh.data = hash;
    cdh.len = sizeof(hash);

    signed_data = ngx_palloc(pool, authdata.len + cdh.len);
    CHECK(signed_data != NULL, "attestation packed: signedData alloc");
    ngx_memcpy(signed_data, authdata.data, authdata.len);
    ngx_memcpy(signed_data + authdata.len, cdh.data, cdh.len);

    sig = sign_es256(pkey, signed_data, authdata.len + cdh.len, &sig_len);
    CHECK(sig != NULL, "attestation packed: signed");

    /* valid packed self-attestation */
    obj = build_att_obj("packed", authdata.data, authdata.len, sig, sig_len, 0,
        &obj_len);
    rc = ngx_auth_webauthn_attestation_parse(pool, obj, obj_len, &att);
    CHECK(rc == NGX_OK, "attestation packed: parse NGX_OK");
    CHECK(att.att_alg == -7, "attestation packed: attStmt alg == -7");
    CHECK(att.att_sig.len == sig_len, "attestation packed: sig captured");

    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_PACKED);
    CHECK(rc == NGX_OK, "attestation packed: verify NGX_OK");

    /* packed rejected when only NONE is allowed */
    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_NONE);
    CHECK(rc == NGX_DECLINED, "attestation packed: NONE policy declines");

    /* wrong clientDataHash -> signature fails */
    ngx_auth_webauthn_hash_sha256((const u_char *) "other", 5, hash);
    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_PACKED);
    CHECK(rc == NGX_DECLINED, "attestation packed: bad cdh NGX_DECLINED");
    ngx_auth_webauthn_hash_sha256((const u_char *) "cdj", 3, hash);  /* restore */
    free(obj);

    /* tampered signature -> DECLINED */
    sig[sig_len - 1] ^= 0x01;
    obj = build_att_obj("packed", authdata.data, authdata.len, sig, sig_len, 0,
        &obj_len);
    rc = ngx_auth_webauthn_attestation_parse(pool, obj, obj_len, &att);
    CHECK(rc == NGX_OK, "attestation packed tampered: parse NGX_OK");
    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_PACKED);
    CHECK(rc == NGX_DECLINED, "attestation packed tampered: NGX_DECLINED");
    sig[sig_len - 1] ^= 0x01;  /* restore */
    free(obj);

    /* x5c present -> declined (Phase 1 self-attestation only) */
    obj = build_att_obj("packed", authdata.data, authdata.len, sig, sig_len, 1,
        &obj_len);
    rc = ngx_auth_webauthn_attestation_parse(pool, obj, obj_len, &att);
    CHECK(rc == NGX_OK, "attestation packed x5c: parse NGX_OK");
    CHECK(att.has_x5c != 0, "attestation packed x5c: x5c detected");
    rc = ngx_auth_webauthn_attestation_verify(pool, &att, &rp_id, &cdh,
        NGX_AUTH_WEBAUTHN_ATT_PACKED);
    CHECK(rc == NGX_DECLINED, "attestation packed x5c: NGX_DECLINED");
    free(obj);

    free(cose);
    free(sig);
    EVP_PKEY_free(pkey);
}


static void
test_attestation_malformed(ngx_pool_t *pool)
{
    static const u_char              garbage[] = { 0x01, 0x02, 0x03, 0x04 };
    ngx_int_t                        rc;
    ngx_auth_webauthn_attestation_t  att;

    rc = ngx_auth_webauthn_attestation_parse(pool, garbage, sizeof(garbage),
        &att);
    CHECK(rc == NGX_DECLINED, "attestation malformed: NGX_DECLINED");

    rc = ngx_auth_webauthn_attestation_parse(pool, NULL, 0, &att);
    CHECK(rc == NGX_ERROR, "attestation NULL data: NGX_ERROR");
}


void
run_attestation_tests(void)
{
    ngx_pool_t  *pool;

    pool = ngx_create_pool(16384, NULL);
    CHECK(pool != NULL, "attestation: pool created");
    if (pool == NULL) {
        return;
    }

    test_attestation_none(pool);
    test_attestation_packed(pool);
    test_attestation_malformed(pool);

    ngx_destroy_pool(pool);
}
