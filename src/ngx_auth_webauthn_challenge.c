/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_challenge.h"

#include <openssl/rand.h>


/* Build "{prefix}chal:{raw}" into out (allocated from pool).  raw carries the
 * 32 binary challenge bytes; the key is binary-safe (issued via
 * redisCommandArgv), so no encoding is applied. */
static ngx_int_t
ngx_auth_webauthn_challenge_key(ngx_pool_t *pool, ngx_str_t *prefix,
    const u_char *raw, size_t rawlen, ngx_str_t *out)
{
    static const char  mid[] = "chal:";
    size_t             midlen = sizeof(mid) - 1;
    u_char            *p;

    out->len = prefix->len + midlen + rawlen;
    p = ngx_pnalloc(pool, out->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    ngx_memcpy(p, prefix->data, prefix->len);
    ngx_memcpy(p + prefix->len, mid, midlen);
    ngx_memcpy(p + prefix->len + midlen, raw, rawlen);

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_challenge_issue(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key_prefix, time_t ttl, u_char *out)
{
    u_char     challenge[NGX_AUTH_WEBAUTHN_CHALLENGE_LEN];
    ngx_str_t  key, value;

    if (redis == NULL || pool == NULL || key_prefix == NULL || out == NULL
        || ttl <= 0)
    {
        return NGX_ERROR;
    }

    if (RAND_bytes(challenge, NGX_AUTH_WEBAUTHN_CHALLENGE_LEN) != 1) {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_challenge_key(pool, key_prefix, challenge,
                                        NGX_AUTH_WEBAUTHN_CHALLENGE_LEN, &key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* The value is an unread marker: presence under the key is all consume()
     * checks.  The verification proper re-derives everything else from
     * clientDataJSON and the policy. */
    ngx_str_set(&value, "1");

    if (ngx_auth_webauthn_redis_set_ex(redis, &key, &value,
                                       (ngx_uint_t) ttl) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(out, challenge, NGX_AUTH_WEBAUTHN_CHALLENGE_LEN);

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_challenge_consume(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key_prefix, const u_char *challenge,
    size_t len)
{
    ngx_str_t   key;
    ngx_uint_t  found;

    if (redis == NULL || pool == NULL || key_prefix == NULL
        || challenge == NULL)
    {
        return NGX_ERROR;
    }
    if (len != NGX_AUTH_WEBAUTHN_CHALLENGE_LEN) {
        return NGX_DECLINED;
    }

    if (ngx_auth_webauthn_challenge_key(pool, key_prefix, challenge, len, &key)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_redis_getdel(redis, &key, &found) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Absent / already used / expired: GETDEL found nothing. */
    return found ? NGX_OK : NGX_DECLINED;
}
