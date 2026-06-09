/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_CHALLENGE_H
#define NGX_AUTH_WEBAUTHN_CHALLENGE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_redis.h"

/*
 * Redis-backed challenge store (docs/ARCHITECTURE.md 5.2, 7.1).
 *
 * Challenges are 32-byte CSPRNG nonces issued by the challenge handler and
 * consumed once by the verify handler.  They live in Redis under the key
 * "{prefix}chal:{raw32}" so every node behind a load balancer sees the same
 * set: the node that issues a challenge and the node that verifies it need not
 * be the same.  One-shot use is atomic via GETDEL (Redis 6.2+) and expiry is
 * the native SET ... EX TTL, so there is no per-node cleaner.
 */

/* Challenge length in bytes (CSPRNG nonce, docs/ARCHITECTURE.md 7.1). */
#define NGX_AUTH_WEBAUTHN_CHALLENGE_LEN  32


/*
 * Generate a 32-byte challenge with RAND_bytes, store it in Redis under
 * "{prefix}chal:{raw32}" with an expiry of ttl seconds, and copy the raw nonce
 * into out (which must hold at least NGX_AUTH_WEBAUTHN_CHALLENGE_LEN bytes).
 * key_prefix is the configured Redis key prefix (e.g. "webauthn:").  Returns
 * NGX_OK, or NGX_ERROR on a CSPRNG / allocation / Redis failure or a NULL
 * argument.
 */
ngx_int_t ngx_auth_webauthn_challenge_issue(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key_prefix, time_t ttl, u_char *out);

/*
 * Atomically consume challenge[0..len): GETDEL its Redis key and return NGX_OK
 * when it existed (and is now gone), NGX_DECLINED when it was absent, already
 * used, expired, or len is not NGX_AUTH_WEBAUTHN_CHALLENGE_LEN, and NGX_ERROR
 * on an allocation / Redis failure or a NULL argument.
 */
ngx_int_t ngx_auth_webauthn_challenge_consume(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key_prefix, const u_char *challenge,
    size_t len);

#endif /* NGX_AUTH_WEBAUTHN_CHALLENGE_H */
