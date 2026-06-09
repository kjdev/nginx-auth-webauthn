/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_REDIS_H
#define NGX_AUTH_WEBAUTHN_REDIS_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Thin synchronous Redis client over hiredis.  hiredis is fully encapsulated
 * here: redisContext / redisReply never appear in this header, so callers
 * (credential store, admin CLI) work in ngx_str_t terms only, the same way
 * nxe-json hides jansson.  One connection per handle, no pool (Phase 1; an
 * async NGINX-upstream client comes later, docs/ARCHITECTURE.md 3.1).
 *
 * Every command is issued binary-safe (redisCommandArgv) because Hash values
 * carry raw bytes (public_key DER, aaguid).
 */

/* Connection settings; the caller fills these from directives. */
typedef struct {
    ngx_str_t   host;
    int         port;
    ngx_str_t   password;    /* len == 0 skips AUTH */
    ngx_uint_t  db;          /* 0 skips SELECT */
    ngx_uint_t  timeout_ms;  /* connect + command; 0 uses the library default */
} ngx_auth_webauthn_redis_conf_t;

/* Opaque handle (wraps redisContext). */
typedef struct ngx_auth_webauthn_redis_s ngx_auth_webauthn_redis_t;

/* One HGETALL / SMEMBERS field-value element, copied into the caller's pool. */
typedef struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_auth_webauthn_redis_pair_t;


/*
 * Open a connection: connect with timeout, set the command timeout, then AUTH
 * (when a password is set) and SELECT (when db > 0).  On success *out owns the
 * handle, which the caller frees with ngx_auth_webauthn_redis_close.  The
 * handle is allocated from pool but holds an OS socket, so close it explicitly.
 *
 * Returns NGX_OK on success, NGX_ERROR on a NULL argument, allocation failure,
 * or any connect / AUTH / SELECT failure.
 */
ngx_int_t ngx_auth_webauthn_redis_connect(ngx_pool_t *pool, ngx_log_t *log,
    ngx_auth_webauthn_redis_conf_t *conf, ngx_auth_webauthn_redis_t **out);

void ngx_auth_webauthn_redis_close(ngx_auth_webauthn_redis_t *redis);


/*
 * HSET key with npairs field-value pairs in one command.  Returns NGX_OK on
 * success, NGX_ERROR on a protocol / connection error.
 */
ngx_int_t ngx_auth_webauthn_redis_hset(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_auth_webauthn_redis_pair_t *pairs, ngx_uint_t npairs);

/*
 * HGETALL key.  *pairs / *npairs receive the field-value pairs allocated from
 * pool.  A missing key is not an error: *npairs is set to 0 and NGX_OK is
 * returned.  Returns NGX_ERROR on a protocol / connection / allocation error.
 */
ngx_int_t ngx_auth_webauthn_redis_hgetall(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key,
    ngx_auth_webauthn_redis_pair_t **pairs, ngx_uint_t *npairs);

/* DEL key.  A missing key is not an error.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t ngx_auth_webauthn_redis_del(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key);

/* SADD key member.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t ngx_auth_webauthn_redis_sadd(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_str_t *member);

/* SREM key member.  A missing member is not an error.  NGX_OK / NGX_ERROR. */
ngx_int_t ngx_auth_webauthn_redis_srem(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_str_t *member);

/*
 * SMEMBERS key.  *members / *nmembers receive the members allocated from pool.
 * A missing key yields *nmembers == 0 and NGX_OK.  NGX_ERROR on error.
 */
ngx_int_t ngx_auth_webauthn_redis_smembers(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key,
    ngx_str_t **members, ngx_uint_t *nmembers);

/* EXPIRE key seconds.  Returns NGX_OK / NGX_ERROR. */
ngx_int_t ngx_auth_webauthn_redis_expire(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_uint_t seconds);

/*
 * INCR key and ensure it carries a TTL of `seconds`, atomically: the TTL is
 * set on the first hit of a fresh counter and on any counter found without an
 * expiry (so a previously orphaned key heals instead of locking the key out
 * forever).  INCR and EXPIRE run in one server-side script, so a dropped
 * connection cannot leave the counter without a TTL.  *value receives the
 * post-increment count.  Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_auth_webauthn_redis_incr_expire(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_uint_t seconds, ngx_int_t *value);

/*
 * SET key value EX seconds.  value may carry raw bytes (binary-safe).  Returns
 * NGX_OK on success, NGX_ERROR on a protocol / connection error.
 */
ngx_int_t ngx_auth_webauthn_redis_set_ex(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_str_t *value, ngx_uint_t seconds);

/*
 * GETDEL key (Redis 6.2+): atomically read and delete the key.  *found is set
 * to 1 when the key existed (and is now gone) and 0 when it was absent or
 * already expired.  The deleted value is not returned: callers only need the
 * existence flag.  Returns NGX_OK on success, NGX_ERROR on a protocol /
 * connection error.
 */
ngx_int_t ngx_auth_webauthn_redis_getdel(ngx_auth_webauthn_redis_t *redis,
    ngx_str_t *key, ngx_uint_t *found);

#endif /* NGX_AUTH_WEBAUTHN_REDIS_H */
