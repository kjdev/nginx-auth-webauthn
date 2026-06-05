/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_ATTESTATION_H
#define NGX_AUTH_WEBAUTHN_ATTESTATION_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * attestationObject parsing and Phase 1 attestation-statement verification.
 * Used by the admin CLI registration path (docs/ARCHITECTURE.md 4.6); the
 * authentication gate does not link this (the public key is already DER in
 * Redis).  Phase 1 supports only "none" and "packed" self-attestation; x5c
 * certificate chains, tpm, android-safetynet, apple and fido-u2f come later
 * (tasks/roadmap.md).
 */

/* Required attestation level for ngx_auth_webauthn_attestation_verify. */
#define NGX_AUTH_WEBAUTHN_ATT_NONE    0  /* accept only fmt == "none" */
#define NGX_AUTH_WEBAUTHN_ATT_PACKED  1  /* accept "none" + packed self */


typedef struct {
    ngx_str_t   fmt;        /* attestation format, e.g. "none" / "packed" */
    ngx_str_t   auth_data;  /* authData byte string (copied from pool) */

    /* "packed" attStmt subset (zeroed for other formats). */
    int         att_alg;    /* COSE alg from attStmt; 0 when absent */
    ngx_str_t   att_sig;    /* signature (copied from pool); len 0 when absent */
    ngx_uint_t  has_x5c;    /* non-zero when an x5c chain is present */
} ngx_auth_webauthn_attestation_t;


/*
 * Decode the CBOR attestationObject in data[0..len) ({fmt, attStmt, authData})
 * into out.  fmt / auth_data / att_sig are copied into pool so they outlive the
 * decoded CBOR tree.  Returns NGX_OK on success, NGX_DECLINED on malformed or
 * incomplete CBOR, NGX_ERROR on a NULL argument or allocation failure.
 */
ngx_int_t ngx_auth_webauthn_attestation_parse(ngx_pool_t *pool,
    const u_char *data, size_t len, ngx_auth_webauthn_attestation_t *out);


/*
 * Verify a parsed attestation against the Phase 1 policy.
 *
 *   require == NGX_AUTH_WEBAUTHN_ATT_NONE
 *     accept only fmt == "none".
 *   require == NGX_AUTH_WEBAUTHN_ATT_PACKED
 *     accept fmt == "none"; for fmt == "packed" verify self-attestation
 *     (att_sig over authData || client_data_hash with the credential public
 *     key carried in authData).  x5c-bearing packed statements are declined.
 *
 * In all cases the authData rpIdHash must equal SHA-256(expected_rp_id).
 * client_data_hash is the 32-byte SHA-256 of the registration clientDataJSON.
 *
 * Returns NGX_OK when the attestation satisfies the policy, NGX_DECLINED on a
 * policy/verification failure, NGX_ERROR on a NULL argument or OpenSSL error.
 */
ngx_int_t ngx_auth_webauthn_attestation_verify(ngx_pool_t *pool,
    ngx_auth_webauthn_attestation_t *att, ngx_str_t *expected_rp_id,
    ngx_str_t *client_data_hash, ngx_uint_t require);

#endif /* NGX_AUTH_WEBAUTHN_ATTESTATION_H */
