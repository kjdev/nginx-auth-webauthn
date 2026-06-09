/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_attestation.h"
#include "ngx_auth_webauthn_authdata.h"
#include "ngx_auth_webauthn_cose.h"
#include "ngx_auth_webauthn_hash.h"

#include <cbor.h>
#include <openssl/evp.h>


/* Extract a signed integer from a CBOR uint/negint item. */
static ngx_int_t
ngx_auth_webauthn_attestation_int(cbor_item_t *item, int64_t *out)
{
    if (item == NULL) {
        return NGX_DECLINED;
    }

    if (cbor_isa_uint(item)) {
        *out = (int64_t) cbor_get_int(item);
        return NGX_OK;
    }

    if (cbor_isa_negint(item)) {
        *out = -1 - (int64_t) cbor_get_int(item);
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/* True when item is a definite CBOR text string equal to literal. */
static ngx_uint_t
ngx_auth_webauthn_attestation_str_eq(cbor_item_t *item, const char *literal,
    size_t litlen)
{
    if (item == NULL
        || !cbor_isa_string(item)
        || !cbor_string_is_definite(item)
        || cbor_string_length(item) != litlen)
    {
        return 0;
    }

    return ngx_memcmp(cbor_string_handle(item), literal, litlen) == 0;
}


/* Copy a definite CBOR byte/text string's bytes into a pool ngx_str_t. */
static ngx_int_t
ngx_auth_webauthn_attestation_dup(ngx_pool_t *pool, const u_char *src,
    size_t len, ngx_str_t *dst)
{
    dst->len = len;

    if (len == 0) {
        dst->data = (u_char *) "";
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src, len);

    return NGX_OK;
}


/* Pull alg / sig / x5c out of the packed attStmt map. */
static ngx_int_t
ngx_auth_webauthn_attestation_parse_stmt(ngx_pool_t *pool, cbor_item_t *stmt,
    ngx_auth_webauthn_attestation_t *out)
{
    size_t i;
    size_t size;
    int64_t alg;
    struct cbor_pair *pairs;

    if (!cbor_isa_map(stmt)) {
        return NGX_DECLINED;
    }

    size = cbor_map_size(stmt);
    pairs = cbor_map_handle(stmt);

    for (i = 0; i < size; i++) {
        cbor_item_t *k = pairs[i].key;
        cbor_item_t *v = pairs[i].value;

        if (ngx_auth_webauthn_attestation_str_eq(k, "alg", sizeof("alg") - 1)) {
            if (ngx_auth_webauthn_attestation_int(v, &alg) == NGX_OK) {
                out->att_alg = (int) alg;
            }

        } else if (ngx_auth_webauthn_attestation_str_eq(k, "sig",
                                                        sizeof("sig") - 1))
        {
            if (!cbor_isa_bytestring(v) || !cbor_bytestring_is_definite(v)) {
                return NGX_DECLINED;
            }
            if (ngx_auth_webauthn_attestation_dup(pool,
                                                  cbor_bytestring_handle(v),
                                                  cbor_bytestring_length(v),
                                                  &out->att_sig) != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else if (ngx_auth_webauthn_attestation_str_eq(k, "x5c",
                                                        sizeof("x5c") - 1))
        {
            if (cbor_isa_array(v) && cbor_array_size(v) > 0) {
                out->has_x5c = 1;
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_attestation_parse(ngx_pool_t *pool, const u_char *data,
    size_t len, ngx_auth_webauthn_attestation_t *out)
{
    size_t i;
    size_t size;
    ngx_int_t rc;
    cbor_item_t *root = NULL;
    cbor_item_t *v_fmt = NULL;
    cbor_item_t *v_auth_data = NULL;
    cbor_item_t *v_att_stmt = NULL;
    struct cbor_pair *pairs;
    struct cbor_load_result result;

    if (pool == NULL || out == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_auth_webauthn_attestation_t));

    if (data == NULL) {
        return NGX_ERROR;
    }

    root = cbor_load(data, len, &result);
    if (root == NULL) {
        return NGX_DECLINED;
    }

    if (result.error.code != CBOR_ERR_NONE || !cbor_isa_map(root)) {
        rc = NGX_DECLINED;
        goto done;
    }

    size = cbor_map_size(root);
    pairs = cbor_map_handle(root);

    for (i = 0; i < size; i++) {
        cbor_item_t *k = pairs[i].key;

        if (ngx_auth_webauthn_attestation_str_eq(k, "fmt", sizeof("fmt") - 1)) {
            v_fmt = pairs[i].value;

        } else if (ngx_auth_webauthn_attestation_str_eq(k, "authData",
                                                        sizeof("authData") - 1))
        {
            v_auth_data = pairs[i].value;

        } else if (ngx_auth_webauthn_attestation_str_eq(k, "attStmt",
                                                        sizeof("attStmt") - 1))
        {
            v_att_stmt = pairs[i].value;
        }
    }

    /* fmt and authData are mandatory. */
    if (v_fmt == NULL
        || !cbor_isa_string(v_fmt)
        || !cbor_string_is_definite(v_fmt)
        || v_auth_data == NULL
        || !cbor_isa_bytestring(v_auth_data)
        || !cbor_bytestring_is_definite(v_auth_data))
    {
        rc = NGX_DECLINED;
        goto done;
    }

    if (ngx_auth_webauthn_attestation_dup(pool, cbor_string_handle(v_fmt),
                                          cbor_string_length(v_fmt),
                                          &out->fmt) != NGX_OK
        || ngx_auth_webauthn_attestation_dup(pool,
                                             cbor_bytestring_handle(
                                                 v_auth_data),
                                             cbor_bytestring_length(
                                                 v_auth_data),
                                             &out->auth_data) != NGX_OK)
    {
        rc = NGX_ERROR;
        goto done;
    }

    /* attStmt is present for packed; "none" carries an empty map. */
    if (v_att_stmt != NULL) {
        rc = ngx_auth_webauthn_attestation_parse_stmt(pool, v_att_stmt, out);
        if (rc != NGX_OK) {
            goto done;
        }
    }

    rc = NGX_OK;

done:

    cbor_decref(&root);

    return rc;
}


/* True when the parsed attestation format equals literal. */
static ngx_uint_t
ngx_auth_webauthn_attestation_fmt_is(ngx_auth_webauthn_attestation_t *att,
    const char *literal, size_t litlen)
{
    return att->fmt.len == litlen
           && ngx_memcmp(att->fmt.data, literal, litlen) == 0;
}


/*
 * Verify a packed self-attestation signature over authData || clientDataHash
 * with the credential public key extracted from authData.
 */
static ngx_int_t
ngx_auth_webauthn_attestation_verify_packed(ngx_pool_t *pool,
    ngx_auth_webauthn_attestation_t *att, ngx_auth_webauthn_authdata_t *ad,
    ngx_str_t *client_data_hash)
{
    const EVP_MD *md;
    u_char *signed_data;
    size_t signed_len;
    int key_alg;
    int ret;
    ngx_int_t rc;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;

    if (att->att_sig.len == 0) {
        return NGX_DECLINED;
    }

    /* The credential public key lives in the attested credential data. */
    if ((ad->flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT) == 0
        || ad->cose_public_key.len == 0)
    {
        return NGX_DECLINED;
    }

    rc = ngx_auth_webauthn_cose_to_pkey(ad->cose_public_key.data,
                                        ad->cose_public_key.len, &pkey,
                                        &key_alg);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Self-attestation: attStmt alg must match the credential key alg. */
    if (att->att_alg != key_alg) {
        EVP_PKEY_free(pkey);
        return NGX_DECLINED;
    }

    switch (key_alg) {
    case NGX_AUTH_WEBAUTHN_COSE_ALG_ES256:
    case NGX_AUTH_WEBAUTHN_COSE_ALG_RS256:
        md = EVP_sha256();
        break;
    case NGX_AUTH_WEBAUTHN_COSE_ALG_EDDSA:
        md = NULL;  /* Ed25519 PureEdDSA: no pre-hash */
        break;
    default:
        EVP_PKEY_free(pkey);
        return NGX_DECLINED;
    }

    signed_len = att->auth_data.len + client_data_hash->len;
    signed_data = ngx_pnalloc(pool, signed_len);
    if (signed_data == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    ngx_memcpy(signed_data, att->auth_data.data, att->auth_data.len);
    ngx_memcpy(signed_data + att->auth_data.len, client_data_hash->data,
               client_data_hash->len);

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1) {
        ret = EVP_DigestVerify(ctx, att->att_sig.data, att->att_sig.len,
                               signed_data, signed_len);
        if (ret == 1) {
            rc = NGX_OK;
        } else if (ret == 0) {
            rc = NGX_DECLINED;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return rc;
}


ngx_int_t
ngx_auth_webauthn_attestation_verify(ngx_pool_t *pool,
    ngx_auth_webauthn_attestation_t *att, ngx_str_t *expected_rp_id,
    ngx_str_t *client_data_hash, ngx_uint_t require)
{
    u_char rp_id_hash[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    ngx_int_t rc;
    ngx_auth_webauthn_authdata_t ad;

    if (pool == NULL || att == NULL || expected_rp_id == NULL
        || client_data_hash == NULL)
    {
        return NGX_ERROR;
    }

    /* rpIdHash must match the configured RP ID regardless of format. */
    rc = ngx_auth_webauthn_authdata_parse(att->auth_data.data,
                                          att->auth_data.len, &ad);
    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_auth_webauthn_hash_sha256(expected_rp_id->data, expected_rp_id->len,
                                      rp_id_hash) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_memcmp(ad.rp_id_hash, rp_id_hash, NGX_AUTH_WEBAUTHN_SHA256_LEN)
        != 0)
    {
        return NGX_DECLINED;
    }

    /* fmt == "none" is always acceptable. */
    if (ngx_auth_webauthn_attestation_fmt_is(att, "none", sizeof("none") - 1)) {
        return NGX_OK;
    }

    if (require == NGX_AUTH_WEBAUTHN_ATT_NONE) {
        return NGX_DECLINED;
    }

    /* require == PACKED: only packed self-attestation. */
    if (!ngx_auth_webauthn_attestation_fmt_is(att, "packed",
                                              sizeof("packed") - 1))
    {
        return NGX_DECLINED;
    }

    if (att->has_x5c) {
        return NGX_DECLINED;  /* certificate chains are out of scope (Phase 1) */
    }

    return ngx_auth_webauthn_attestation_verify_packed(pool, att, &ad,
                                                       client_data_hash);
}
