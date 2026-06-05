/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_ASSERTION_H
#define NGX_AUTH_WEBAUTHN_ASSERTION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_authdata.h"

/*
 * Sign-counter clone-detection policy, matching the
 * auth_webauthn_clone_detection directive (docs/ARCHITECTURE.md 6.5).
 */
#define NGX_AUTH_WEBAUTHN_CLONE_STRICT  0
#define NGX_AUTH_WEBAUTHN_CLONE_LAX     1
#define NGX_AUTH_WEBAUTHN_CLONE_OFF     2


/*
 * The base64url-decoded assertion response.  The verify handler fills these
 * after JSON-parsing the POST body and decoding each field.
 */
typedef struct {
    ngx_str_t  authenticator_data;
    ngx_str_t  client_data_json;
    ngx_str_t  signature;
} ngx_auth_webauthn_assertion_t;


/*
 * The subset of a stored credential record the verifier needs.  public_key is
 * the DER SubjectPublicKeyInfo (i2d_PUBKEY output) written at registration.
 */
typedef struct {
    ngx_str_t  public_key;
    int        alg;          /* COSE alg: -7 ES256 / -8 EdDSA / -257 RS256 */
    uint32_t   sign_count;   /* last value persisted in Redis */
} ngx_auth_webauthn_assertion_cred_t;


/*
 * Expected values and policy supplied by configuration / the challenge store.
 * expected_challenge is the raw challenge bytes the handler retrieved from the
 * shared-memory store; allowed_origins is the configured allow-list.
 */
typedef struct {
    ngx_str_t   rp_id;
    ngx_str_t   expected_challenge;
    ngx_str_t  *allowed_origins;
    ngx_uint_t  norigins;
    ngx_uint_t  require_uv;        /* non-zero requires the UV flag */
    ngx_uint_t  clone_detection;   /* NGX_AUTH_WEBAUTHN_CLONE_* */
} ngx_auth_webauthn_assertion_policy_t;


/*
 * Verifier output.  auth_sign_count is the counter read from authData so the
 * handler can persist it on success.
 */
typedef struct {
    uint32_t  auth_sign_count;
} ngx_auth_webauthn_assertion_result_t;


/*
 * Verify a WebAuthn assertion (docs/ARCHITECTURE.md 6.1, the cryptographic
 * steps).  This is a pure function: the caller has already parsed the request,
 * decoded the fields, fetched the credential, and pulled the challenge from the
 * store.  It runs clientData verification, authData parsing, rpIdHash / flag /
 * clone-counter checks, and the public-key signature check, but does not touch
 * Redis, the challenge store, or mint a session token.
 *
 * Returns NGX_OK when the assertion is valid (result->auth_sign_count is then
 * set), NGX_DECLINED on any verification failure (an authentication rejection),
 * NGX_ERROR on a NULL argument or an internal/OpenSSL error.
 */
ngx_int_t ngx_auth_webauthn_assertion_verify(ngx_pool_t *pool,
    ngx_auth_webauthn_assertion_t *assertion,
    ngx_auth_webauthn_assertion_cred_t *cred,
    ngx_auth_webauthn_assertion_policy_t *policy,
    ngx_auth_webauthn_assertion_result_t *result);

#endif /* NGX_AUTH_WEBAUTHN_ASSERTION_H */
