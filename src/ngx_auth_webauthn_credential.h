/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_CREDENTIAL_H
#define NGX_AUTH_WEBAUTHN_CREDENTIAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_redis.h"
#include "ngx_auth_webauthn_authdata.h"  /* NGX_AUTH_WEBAUTHN_AAGUID_LEN */

/*
 * Credential record CRUD over Redis (docs/ARCHITECTURE.md 5.1).
 *
 * Storage:
 *   {prefix}cred:{credential_id}   Hash  - the credential record
 *   {prefix}user:{user_id}:creds   Set   - the user's credential-id index
 *
 * prefix is the configured auth_webauthn_redis_key_prefix (default "webauthn:")
 * and is passed in by the caller; this layer stays free of directive defaults.
 * public_key is stored as DER SubjectPublicKeyInfo (i2d_PUBKEY output) so the
 * authentication path needs no CBOR/COSE decoder.
 */

typedef struct {
    ngx_str_t   credential_id;  /* base64url; the Redis key suffix */
    ngx_str_t   user_id;
    ngx_str_t   public_key;     /* DER (i2d_PUBKEY) */
    int         alg;            /* COSE alg: -7 ES256 / -8 EdDSA / -257 RS256 */
    uint32_t    sign_count;
    int64_t     created_at;     /* unix time */
    int64_t     last_used_at;   /* unix time */
    u_char      aaguid[NGX_AUTH_WEBAUTHN_AAGUID_LEN];
    ngx_uint_t  has_aaguid;     /* non-zero when aaguid holds 16 valid bytes */
    ngx_str_t   transports;     /* CSV (usb,nfc,ble,internal); may be empty */
} ngx_auth_webauthn_credential_t;


/*
 * Fetch {prefix}cred:{credential_id} and parse it into out (allocated fields
 * come from pool).  Returns NGX_OK on a complete record, NGX_DECLINED when the
 * key is missing or required fields (public_key / alg) are absent, NGX_ERROR
 * on a NULL argument or a Redis / allocation error.
 */
ngx_int_t ngx_auth_webauthn_credential_get(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *credential_id,
    ngx_auth_webauthn_credential_t *out);

/*
 * Store cred as {prefix}cred:{cred->credential_id} (HSET) and add the id to the
 * {prefix}user:{cred->user_id}:creds index (SADD).  Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_auth_webauthn_credential_put(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_auth_webauthn_credential_t *cred);

/*
 * Update sign_count and last_used_at on an existing credential (one HSET).
 * Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_auth_webauthn_credential_update_counter(
    ngx_auth_webauthn_redis_t *redis, ngx_pool_t *pool, ngx_str_t *prefix,
    ngx_str_t *credential_id, uint32_t new_count, int64_t last_used_at);

/*
 * Delete a credential: look up its user_id, DEL the record, then SREM the id
 * from the user index.  Returns NGX_OK on success, NGX_DECLINED when the
 * credential does not exist, NGX_ERROR on a Redis / allocation error.
 */
ngx_int_t ngx_auth_webauthn_credential_delete(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *credential_id);

#endif /* NGX_AUTH_WEBAUTHN_CREDENTIAL_H */
