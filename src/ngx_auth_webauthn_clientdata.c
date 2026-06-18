/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_clientdata.h"

#include "nxe_json.h"


static ngx_int_t
ngx_auth_webauthn_clientdata_get_string(nxe_json_t *root, const char *key,
    ngx_str_t *out)
{
    nxe_json_t *node;

    node = nxe_json_object_get(root, key);
    if (node == NULL) {
        return NGX_DECLINED;
    }

    if (nxe_json_string(node, out) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_flag_t
ngx_auth_webauthn_str_equal(ngx_str_t *a, ngx_str_t *b)
{
    return a->len == b->len
           && (a->len == 0 || ngx_memcmp(a->data, b->data, a->len) == 0);
}


ngx_int_t
ngx_auth_webauthn_clientdata_verify(ngx_pool_t *pool, const u_char *data,
    size_t len, ngx_str_t *expected_type, ngx_str_t *expected_challenge,
    ngx_str_t *allowed_origins, ngx_uint_t norigins)
{
    ngx_str_t input;
    ngx_str_t type;
    ngx_str_t challenge_b64;
    ngx_str_t challenge;
    ngx_str_t origin;
    nxe_json_t *root;
    nxe_json_t *cross_origin_node;
    ngx_flag_t cross_origin;
    ngx_uint_t i;
    ngx_int_t rc;

    if (pool == NULL || data == NULL || expected_type == NULL
        || expected_challenge == NULL
        || (norigins > 0 && allowed_origins == NULL))
    {
        return NGX_ERROR;
    }

    input.data = (u_char *) data;
    input.len = len;

    root = nxe_json_parse_untrusted(&input, pool);
    if (root == NULL) {
        return NGX_DECLINED;
    }

    /* type == expected_type */
    if (ngx_auth_webauthn_clientdata_get_string(root, "type", &type)
        != NGX_OK)
    {
        rc = NGX_DECLINED;
        goto done;
    }

    if (!ngx_auth_webauthn_str_equal(&type, expected_type)) {
        rc = NGX_DECLINED;
        goto done;
    }

    /* challenge: base64url-decode and compare against expected raw bytes */
    if (ngx_auth_webauthn_clientdata_get_string(root, "challenge",
                                                &challenge_b64)
        != NGX_OK)
    {
        rc = NGX_DECLINED;
        goto done;
    }

    challenge.data = ngx_pnalloc(pool,
                                 ngx_base64_decoded_length(challenge_b64.len));
    if (challenge.data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    if (ngx_decode_base64url(&challenge, &challenge_b64) != NGX_OK) {
        rc = NGX_DECLINED;
        goto done;
    }

    if (!ngx_auth_webauthn_str_equal(&challenge, expected_challenge)) {
        rc = NGX_DECLINED;
        goto done;
    }

    /* origin must match one of the configured allow-list entries exactly */
    if (ngx_auth_webauthn_clientdata_get_string(root, "origin", &origin)
        != NGX_OK)
    {
        rc = NGX_DECLINED;
        goto done;
    }

    rc = NGX_DECLINED;
    for (i = 0; i < norigins; i++) {
        if (ngx_auth_webauthn_str_equal(&origin, &allowed_origins[i])) {
            rc = NGX_OK;
            break;
        }
    }

    if (rc != NGX_OK) {
        goto done;
    }

    /* crossOrigin, when present, must not be true */
    cross_origin_node = nxe_json_object_get(root, "crossOrigin");
    if (cross_origin_node != NULL
        && nxe_json_boolean(cross_origin_node, &cross_origin) == NGX_OK
        && cross_origin)
    {
        rc = NGX_DECLINED;
        goto done;
    }

    rc = NGX_OK;

done:

    nxe_json_free(root);

    return rc;
}
