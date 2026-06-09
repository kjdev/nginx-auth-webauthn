/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_AUTHDATA_H
#define NGX_AUTH_WEBAUTHN_AUTHDATA_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_hash.h"

/*
 * authenticatorData fixed-prefix layout (WebAuthn level 2, 6.1):
 *   rpIdHash (32) | flags (1) | signCount (4, big endian)
 * followed, when the AT flag is set, by attestedCredentialData:
 *   aaguid (16) | credentialIdLength (2, big endian) | credentialId
 *   | credentialPublicKey (COSE_Key, variable-length CBOR)
 */
#define NGX_AUTH_WEBAUTHN_AUTHDATA_MIN_LEN  37
#define NGX_AUTH_WEBAUTHN_AAGUID_LEN        16

/* flags bit masks */
#define NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UP  0x01  /* User Present */
#define NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UV  0x04  /* User Verified */
#define NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT  0x40  /* Attested credential data */
#define NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_ED  0x80  /* Extension data */


typedef struct {
    u_char    rp_id_hash[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    u_char    flags;
    uint32_t  sign_count;

    /*
     * Only populated when the AT flag is set.  credential_id and
     * cose_public_key are borrowed views into the input buffer (no copy);
     * they stay valid only as long as the caller keeps data alive.  When AT
     * is clear they are zeroed (len == 0, data == NULL).
     */
    u_char     aaguid[NGX_AUTH_WEBAUTHN_AAGUID_LEN];
    ngx_str_t  credential_id;
    ngx_str_t  cose_public_key;
} ngx_auth_webauthn_authdata_t;


/*
 * Parse the authenticatorData byte string in data[0..len) into out.
 *
 * Handles both assertion form (AT flag clear, exactly the 37-byte prefix)
 * and attestation form (AT flag set, attestedCredentialData appended).  The
 * COSE public key has no length prefix in CBOR, so cose_public_key is set to
 * all remaining bytes after the credentialId.  This assumes no extension
 * (ED) block follows the credential public key; the Phase 1 registration
 * paths (none / packed self attestation) carry no extensions.
 *
 * Flag interpretation (UP / UV checks, rejecting AT/ED in assertions) is left
 * to the caller.
 *
 * Returns NGX_OK on success, NGX_DECLINED on malformed / truncated input,
 * NGX_ERROR when out is NULL.
 */
ngx_int_t ngx_auth_webauthn_authdata_parse(const u_char *data, size_t len,
    ngx_auth_webauthn_authdata_t *out);

#endif /* NGX_AUTH_WEBAUTHN_AUTHDATA_H */
