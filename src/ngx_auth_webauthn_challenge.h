/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_CHALLENGE_H
#define NGX_AUTH_WEBAUTHN_CHALLENGE_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Shared-memory challenge store (docs/ARCHITECTURE.md 5.2, 7.1).
 *
 * Challenges are 32-byte CSPRNG nonces issued by the challenge handler and
 * consumed once by the verify handler.  They live in an nginx slab zone so
 * all workers see the same set; a rbtree gives O(log n) lookup keyed by the
 * first four challenge bytes (full 32-byte compare breaks ties), and a queue
 * in insertion order lets issue() opportunistically evict expired entries
 * without a dedicated cleaner timer.
 */

/* Challenge length in bytes (CSPRNG nonce, docs/ARCHITECTURE.md 7.1). */
#define NGX_AUTH_WEBAUTHN_CHALLENGE_LEN  32


/* Opaque shared-memory state; the layout lives in the .c file. */
typedef struct ngx_auth_webauthn_challenge_sh_s
    ngx_auth_webauthn_challenge_sh_t;

/*
 * Per-zone bookkeeping the module allocates from cf->pool and stores in
 * shm_zone->data.  init_zone fills sh / shpool (reusing the previous
 * incarnation's on reload).
 */
typedef struct {
    ngx_auth_webauthn_challenge_sh_t *sh;
    ngx_slab_pool_t                  *shpool;
} ngx_auth_webauthn_challenge_ctx_t;


/*
 * shm zone init callback (ngx_shm_zone_init_pt).  Builds the rbtree / queue
 * in the slab on first init and rebinds the context on reload.
 */
ngx_int_t ngx_auth_webauthn_challenge_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);

/*
 * Generate a 32-byte challenge with RAND_bytes, store it with an expiry of
 * now + ttl seconds, and copy it into out (which must hold at least
 * NGX_AUTH_WEBAUTHN_CHALLENGE_LEN bytes).  Returns NGX_OK, or NGX_ERROR on a
 * CSPRNG / slab-exhaustion / NULL-argument failure.
 */
ngx_int_t ngx_auth_webauthn_challenge_issue(ngx_shm_zone_t *shm_zone,
    u_char *out, time_t ttl);

/*
 * Look up challenge[0..len) and, when present and not expired, delete it
 * (one-shot) and return NGX_OK.  Returns NGX_DECLINED when it is absent,
 * expired, or len is not NGX_AUTH_WEBAUTHN_CHALLENGE_LEN; NGX_ERROR on a
 * NULL argument.  An expired entry found here is removed in passing.
 */
ngx_int_t ngx_auth_webauthn_challenge_consume(ngx_shm_zone_t *shm_zone,
    const u_char *challenge, size_t len);

#endif /* NGX_AUTH_WEBAUTHN_CHALLENGE_H */
