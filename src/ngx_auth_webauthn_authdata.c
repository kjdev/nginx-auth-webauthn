/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_authdata.h"


ngx_int_t
ngx_auth_webauthn_authdata_parse(const u_char *data, size_t len,
    ngx_auth_webauthn_authdata_t *out)
{
    size_t offset;
    size_t cred_id_len;
    const u_char *p;

    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_auth_webauthn_authdata_t));

    if (data == NULL || len < NGX_AUTH_WEBAUTHN_AUTHDATA_MIN_LEN) {
        return NGX_DECLINED;
    }

    p = data;

    ngx_memcpy(out->rp_id_hash, p, NGX_AUTH_WEBAUTHN_SHA256_LEN);
    p += NGX_AUTH_WEBAUTHN_SHA256_LEN;

    out->flags = *p++;

    /* signCount: 4-byte big-endian uint32 */
    out->sign_count = ((uint32_t) p[0] << 24)
                      | ((uint32_t) p[1] << 16)
                      | ((uint32_t) p[2] << 8)
                      | ((uint32_t) p[3]);

    if ((out->flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT) == 0) {
        /* assertion form: nothing follows the fixed prefix */
        return NGX_OK;
    }

    /*
     * attestedCredentialData: aaguid (16) | credentialIdLength (2) |
     * credentialId | credentialPublicKey.  Need at least aaguid + length
     * field beyond the 37-byte prefix.
     */
    offset = NGX_AUTH_WEBAUTHN_AUTHDATA_MIN_LEN;

    if (len < offset + NGX_AUTH_WEBAUTHN_AAGUID_LEN + 2) {
        return NGX_DECLINED;
    }

    ngx_memcpy(out->aaguid, data + offset, NGX_AUTH_WEBAUTHN_AAGUID_LEN);
    offset += NGX_AUTH_WEBAUTHN_AAGUID_LEN;

    cred_id_len = ((size_t) data[offset] << 8) | (size_t) data[offset + 1];
    offset += 2;

    if (cred_id_len > len - offset) {
        return NGX_DECLINED;
    }

    out->credential_id.data = (u_char *) data + offset;
    out->credential_id.len = cred_id_len;
    offset += cred_id_len;

    /*
     * Remaining bytes are the COSE public key (and, in principle, extensions
     * when ED is set).  CBOR has no length prefix, so the slice is handed off
     * whole; the COSE decoder consumes one map and ignores any trailing data.
     */
    out->cose_public_key.data = (u_char *) data + offset;
    out->cose_public_key.len = len - offset;

    return NGX_OK;
}
