/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_hash.h"

#include <openssl/evp.h>


ngx_int_t
ngx_auth_webauthn_hash_sha256(const u_char *data, size_t len, u_char *out)
{
    unsigned int digest_len;

    if (out == NULL || (data == NULL && len != 0)) {
        return NGX_ERROR;
    }

    /*
     * EVP_Digest is the single-shot form: it allocates, inits, updates and
     * finalises a context internally, so there is no EVP_MD_CTX to manage.
     * For the empty input, pass a non-NULL pointer: a NULL data pointer is
     * undefined behaviour even when len is 0.
     */
    if (EVP_Digest(len == 0 ? (const u_char *) "" : data, len, out,
                   &digest_len, EVP_sha256(), NULL)
        != 1)
    {
        return NGX_ERROR;
    }

    if (digest_len != NGX_AUTH_WEBAUTHN_SHA256_LEN) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
