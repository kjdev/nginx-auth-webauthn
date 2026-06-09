/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_cose.h"

#include <cbor.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

/* COSE key common parameters */
#define NGX_AUTH_WEBAUTHN_COSE_LABEL_KTY   1
#define NGX_AUTH_WEBAUTHN_COSE_LABEL_ALG   3

/* COSE key type values (RFC 8152, 13) */
#define NGX_AUTH_WEBAUTHN_COSE_KTY_OKP     1
#define NGX_AUTH_WEBAUTHN_COSE_KTY_EC2     2
#define NGX_AUTH_WEBAUTHN_COSE_KTY_RSA     3

/* COSE elliptic curve values */
#define NGX_AUTH_WEBAUTHN_COSE_CRV_P256    1
#define NGX_AUTH_WEBAUTHN_COSE_CRV_ED25519 6

/* Uncompressed EC point: 0x04 || X || Y, with 32-byte P-256 coordinates */
#define NGX_AUTH_WEBAUTHN_P256_COORD_LEN   32
#define NGX_AUTH_WEBAUTHN_P256_POINT_LEN   (1 + 2 * \
                                            NGX_AUTH_WEBAUTHN_P256_COORD_LEN)
#define NGX_AUTH_WEBAUTHN_ED25519_KEY_LEN  32


static ngx_int_t
ngx_auth_webauthn_cose_int(cbor_item_t *item, int64_t *out)
{
    if (item == NULL) {
        return NGX_DECLINED;
    }

    if (cbor_isa_uint(item)) {
        *out = (int64_t) cbor_get_int(item);
        return NGX_OK;
    }

    if (cbor_isa_negint(item)) {
        /* libcbor stores -1 - n; recover the signed value */
        *out = -1 - (int64_t) cbor_get_int(item);
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_auth_webauthn_cose_bytes(cbor_item_t *item, u_char **data, size_t *len)
{
    if (item == NULL
        || !cbor_isa_bytestring(item)
        || !cbor_bytestring_is_definite(item))
    {
        return NGX_DECLINED;
    }

    *data = cbor_bytestring_handle(item);
    *len = cbor_bytestring_length(item);

    return NGX_OK;
}


static ngx_int_t
ngx_auth_webauthn_cose_ec2_pkey(cbor_item_t *crv, cbor_item_t *x_item,
    cbor_item_t *y_item, EVP_PKEY **pkey)
{
    u_char point[NGX_AUTH_WEBAUTHN_P256_POINT_LEN];
    u_char *x;
    u_char *y;
    size_t x_len;
    size_t y_len;
    int64_t crv_id;
    ngx_int_t rc;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    if (ngx_auth_webauthn_cose_int(crv, &crv_id) != NGX_OK
        || crv_id != NGX_AUTH_WEBAUTHN_COSE_CRV_P256)
    {
        return NGX_DECLINED;
    }

    if (ngx_auth_webauthn_cose_bytes(x_item, &x, &x_len) != NGX_OK
        || ngx_auth_webauthn_cose_bytes(y_item, &y, &y_len) != NGX_OK
        || x_len != NGX_AUTH_WEBAUTHN_P256_COORD_LEN
        || y_len != NGX_AUTH_WEBAUTHN_P256_COORD_LEN)
    {
        return NGX_DECLINED;
    }

    point[0] = 0x04;
    ngx_memcpy(point + 1, x, NGX_AUTH_WEBAUTHN_P256_COORD_LEN);
    ngx_memcpy(point + 1 + NGX_AUTH_WEBAUTHN_P256_COORD_LEN, y,
               NGX_AUTH_WEBAUTHN_P256_COORD_LEN);

    rc = NGX_ERROR;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        goto done;
    }

    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "prime256v1", 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                            point, sizeof(point)) != 1)
    {
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL) {
        goto done;
    }

    if (EVP_PKEY_fromdata_init(ctx) == 1
        && EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) == 1)
    {
        rc = NGX_OK;
    }

done:

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(bld);

    return rc;
}


static ngx_int_t
ngx_auth_webauthn_cose_okp_pkey(cbor_item_t *crv, cbor_item_t *x_item,
    EVP_PKEY **pkey)
{
    u_char *x;
    size_t x_len;
    int64_t crv_id;

    if (ngx_auth_webauthn_cose_int(crv, &crv_id) != NGX_OK
        || crv_id != NGX_AUTH_WEBAUTHN_COSE_CRV_ED25519)
    {
        return NGX_DECLINED;
    }

    if (ngx_auth_webauthn_cose_bytes(x_item, &x, &x_len) != NGX_OK
        || x_len != NGX_AUTH_WEBAUTHN_ED25519_KEY_LEN)
    {
        return NGX_DECLINED;
    }

    *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x, x_len);
    if (*pkey == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_auth_webauthn_cose_rsa_pkey(cbor_item_t *n_item, cbor_item_t *e_item,
    EVP_PKEY **pkey)
{
    u_char *n;
    u_char *e;
    size_t n_len;
    size_t e_len;
    ngx_int_t rc;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_e = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;

    if (ngx_auth_webauthn_cose_bytes(n_item, &n, &n_len) != NGX_OK
        || ngx_auth_webauthn_cose_bytes(e_item, &e, &e_len) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    rc = NGX_ERROR;

    bn_n = BN_bin2bn(n, (int) n_len, NULL);
    bn_e = BN_bin2bn(e, (int) e_len, NULL);
    bld = OSSL_PARAM_BLD_new();
    if (bn_n == NULL || bn_e == NULL || bld == NULL) {
        goto done;
    }

    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) != 1
        || OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) != 1)
    {
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (params == NULL || ctx == NULL) {
        goto done;
    }

    if (EVP_PKEY_fromdata_init(ctx) == 1
        && EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) == 1)
    {
        rc = NGX_OK;
    }

done:

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);

    return rc;
}


ngx_int_t
ngx_auth_webauthn_cose_to_pkey(const u_char *cose, size_t cose_len,
    EVP_PKEY **pkey, int *alg)
{
    size_t i;
    size_t map_size;
    int64_t key;
    int64_t kty;
    int64_t alg_id;
    ngx_int_t rc;
    cbor_item_t *root = NULL;
    cbor_item_t *v_kty = NULL;
    cbor_item_t *v_alg = NULL;
    cbor_item_t *v_m1 = NULL;           /* label -1: crv | rsa n   */
    cbor_item_t *v_m2 = NULL;           /* label -2: x   | rsa e   */
    cbor_item_t *v_m3 = NULL;           /* label -3: y             */
    struct cbor_pair *pairs;
    struct cbor_load_result result;

    if (cose == NULL || pkey == NULL || alg == NULL) {
        return NGX_ERROR;
    }

    *pkey = NULL;

    root = cbor_load(cose, cose_len, &result);
    if (root == NULL) {
        return NGX_ERROR;
    }

    if (result.error.code != CBOR_ERR_NONE || !cbor_isa_map(root)) {
        rc = NGX_ERROR;
        goto done;
    }

    map_size = cbor_map_size(root);
    pairs = cbor_map_handle(root);

    /*
     * The meaning of labels -1/-2/-3 depends on kty, so collect the raw value
     * items in one pass and interpret them once the key type is known.
     */
    for (i = 0; i < map_size; i++) {
        if (ngx_auth_webauthn_cose_int(pairs[i].key, &key) != NGX_OK) {
            continue;
        }

        switch (key) {
        case NGX_AUTH_WEBAUTHN_COSE_LABEL_KTY:
            v_kty = pairs[i].value;
            break;
        case NGX_AUTH_WEBAUTHN_COSE_LABEL_ALG:
            v_alg = pairs[i].value;
            break;
        case -1:
            v_m1 = pairs[i].value;
            break;
        case -2:
            v_m2 = pairs[i].value;
            break;
        case -3:
            v_m3 = pairs[i].value;
            break;
        default:
            break;
        }
    }

    if (ngx_auth_webauthn_cose_int(v_kty, &kty) != NGX_OK
        || ngx_auth_webauthn_cose_int(v_alg, &alg_id) != NGX_OK)
    {
        rc = NGX_DECLINED;
        goto done;
    }

    switch (kty) {
    case NGX_AUTH_WEBAUTHN_COSE_KTY_EC2:
        if (alg_id != NGX_AUTH_WEBAUTHN_COSE_ALG_ES256) {
            rc = NGX_DECLINED;
            break;
        }
        rc = ngx_auth_webauthn_cose_ec2_pkey(v_m1, v_m2, v_m3, pkey);
        break;

    case NGX_AUTH_WEBAUTHN_COSE_KTY_OKP:
        if (alg_id != NGX_AUTH_WEBAUTHN_COSE_ALG_EDDSA) {
            rc = NGX_DECLINED;
            break;
        }
        rc = ngx_auth_webauthn_cose_okp_pkey(v_m1, v_m2, pkey);
        break;

    case NGX_AUTH_WEBAUTHN_COSE_KTY_RSA:
        if (alg_id != NGX_AUTH_WEBAUTHN_COSE_ALG_RS256) {
            rc = NGX_DECLINED;
            break;
        }
        rc = ngx_auth_webauthn_cose_rsa_pkey(v_m1, v_m2, pkey);
        break;

    default:
        rc = NGX_DECLINED;
        break;
    }

    if (rc == NGX_OK) {
        *alg = (int) alg_id;
    }

done:

    cbor_decref(&root);

    return rc;
}


ngx_int_t
ngx_auth_webauthn_cose_to_der(ngx_pool_t *pool, const u_char *cose,
    size_t cose_len, ngx_str_t *der, int *alg)
{
    int der_len;
    u_char *p;
    EVP_PKEY *pkey = NULL;
    ngx_int_t rc;

    if (pool == NULL || der == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_auth_webauthn_cose_to_pkey(cose, cose_len, &pkey, alg);
    if (rc != NGX_OK) {
        return rc;
    }

    der_len = i2d_PUBKEY(pkey, NULL);
    if (der_len <= 0) {
        rc = NGX_ERROR;
        goto done;
    }

    der->data = ngx_pnalloc(pool, (size_t) der_len);
    if (der->data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    p = der->data;
    if (i2d_PUBKEY(pkey, &p) != der_len) {
        rc = NGX_ERROR;
        goto done;
    }

    der->len = (size_t) der_len;
    rc = NGX_OK;

done:

    EVP_PKEY_free(pkey);

    return rc;
}
