/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_credential.h"

#include <stdio.h>

/* Hash field names (docs/ARCHITECTURE.md 5.1). */
#define NGX_AUTH_WEBAUTHN_CRED_F_USER_ID      "user_id"
#define NGX_AUTH_WEBAUTHN_CRED_F_PUBLIC_KEY   "public_key"
#define NGX_AUTH_WEBAUTHN_CRED_F_ALG          "alg"
#define NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT   "sign_count"
#define NGX_AUTH_WEBAUTHN_CRED_F_CREATED_AT   "created_at"
#define NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT "last_used_at"
#define NGX_AUTH_WEBAUTHN_CRED_F_AAGUID       "aaguid"
#define NGX_AUTH_WEBAUTHN_CRED_F_TRANSPORTS   "transports"

/* Decimal buffer big enough for any int64 with sign and NUL. */
#define NGX_AUTH_WEBAUTHN_CRED_NUMBUF  24

/* HSET pairs: user_id, public_key, alg, sign_count, created_at,
 * last_used_at, transports, aaguid. */
#define NGX_AUTH_WEBAUTHN_CRED_MAX_PAIRS  8


/* Build {prefix}cred:{cid} into out (allocated from pool). */
static ngx_int_t
ngx_auth_webauthn_credential_record_key(ngx_pool_t *pool, ngx_str_t *prefix,
    ngx_str_t *cid, ngx_str_t *out)
{
    static const char mid[] = "cred:";
    size_t midlen = sizeof(mid) - 1;
    u_char *p;

    out->len = prefix->len + midlen + cid->len;
    p = ngx_pnalloc(pool, out->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    ngx_memcpy(p, prefix->data, prefix->len);
    ngx_memcpy(p + prefix->len, mid, midlen);
    ngx_memcpy(p + prefix->len + midlen, cid->data, cid->len);

    return NGX_OK;
}


/* Build {prefix}user:{uid}:creds into out (allocated from pool). */
static ngx_int_t
ngx_auth_webauthn_credential_index_key(ngx_pool_t *pool, ngx_str_t *prefix,
    ngx_str_t *uid, ngx_str_t *out)
{
    static const char mid[] = "user:";
    static const char suffix[] = ":creds";
    size_t midlen = sizeof(mid) - 1;
    size_t suffixlen = sizeof(suffix) - 1;
    u_char *p;

    out->len = prefix->len + midlen + uid->len + suffixlen;
    p = ngx_pnalloc(pool, out->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    ngx_memcpy(p, prefix->data, prefix->len);
    p += prefix->len;
    ngx_memcpy(p, mid, midlen);
    p += midlen;
    ngx_memcpy(p, uid->data, uid->len);
    p += uid->len;
    ngx_memcpy(p, suffix, suffixlen);

    return NGX_OK;
}


/* Parse a decimal int64 from a non-NUL-terminated value.  Rejects empty
 * input, non-digit characters, and overflow. */
static ngx_int_t
ngx_auth_webauthn_credential_atoi64(ngx_str_t *s, int64_t *out)
{
    size_t i;
    int neg;
    uint64_t acc;
    uint64_t limit;

    if (s->len == 0) {
        return NGX_ERROR;
    }

    i = 0;
    neg = 0;
    if (s->data[0] == '-') {
        neg = 1;
        i = 1;
        if (s->len == 1) {
            return NGX_ERROR;
        }
    }

    /* Magnitude limit: 2^63 for negatives, 2^63 - 1 for positives. */
    limit = neg ? (uint64_t) INT64_MAX + 1 : (uint64_t) INT64_MAX;

    acc = 0;
    for ( /* void */ ; i < s->len; i++) {
        u_char c = s->data[i];

        if (c < '0' || c > '9') {
            return NGX_ERROR;
        }

        if (acc > (limit - (uint64_t) (c - '0')) / 10) {
            return NGX_ERROR;
        }

        acc = acc * 10 + (uint64_t) (c - '0');
    }

    *out = neg ? -(int64_t) acc : (int64_t) acc;

    return NGX_OK;
}


/* Append a "name" / decimal-"value" pair, formatting v into buf. */
static void
ngx_auth_webauthn_credential_num_pair(ngx_auth_webauthn_redis_pair_t *pair,
    const char *name, size_t namelen, char *buf, int n)
{
    pair->name.data = (u_char *) name;
    pair->name.len = namelen;
    pair->value.data = (u_char *) buf;
    pair->value.len = (n > 0) ? (size_t) n : 0;
}


ngx_int_t
ngx_auth_webauthn_credential_get(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *credential_id,
    ngx_auth_webauthn_credential_t *out)
{
    ngx_str_t key;
    ngx_uint_t i;
    ngx_uint_t npairs;
    int64_t v;
    ngx_auth_webauthn_redis_pair_t *pairs;

    if (redis == NULL || pool == NULL || prefix == NULL || credential_id == NULL
        || out == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_auth_webauthn_credential_t));
    out->credential_id = *credential_id;

    if (ngx_auth_webauthn_credential_record_key(pool, prefix, credential_id,
                                                &key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_redis_hgetall(redis, pool, &key, &pairs, &npairs)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (npairs == 0) {
        return NGX_DECLINED;  /* no such credential */
    }

    for (i = 0; i < npairs; i++) {
        ngx_str_t *n = &pairs[i].name;
        ngx_str_t *val = &pairs[i].value;

        if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_USER_ID) - 1
            && ngx_strncmp(n->data, NGX_AUTH_WEBAUTHN_CRED_F_USER_ID, n->len)
            == 0)
        {
            out->user_id = *val;

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_PUBLIC_KEY) - 1
                   && ngx_strncmp(n->data,
                                  NGX_AUTH_WEBAUTHN_CRED_F_PUBLIC_KEY,
                                  n->len) == 0)
        {
            out->public_key = *val;

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_ALG) - 1
                   && ngx_strncmp(n->data, NGX_AUTH_WEBAUTHN_CRED_F_ALG, n->len)
                   == 0)
        {
            if (ngx_auth_webauthn_credential_atoi64(val, &v) != NGX_OK
                || v < INT32_MIN || v > INT32_MAX)
            {
                return NGX_DECLINED;
            }
            out->alg = (int) v;

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT) - 1
                   && ngx_strncmp(n->data,
                                  NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT,
                                  n->len) == 0)
        {
            if (ngx_auth_webauthn_credential_atoi64(val, &v) != NGX_OK
                || v < 0 || v > (int64_t) UINT32_MAX)
            {
                return NGX_DECLINED;
            }
            out->sign_count = (uint32_t) v;

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_CREATED_AT) - 1
                   && ngx_strncmp(n->data,
                                  NGX_AUTH_WEBAUTHN_CRED_F_CREATED_AT,
                                  n->len) == 0)
        {
            if (ngx_auth_webauthn_credential_atoi64(val, &v) == NGX_OK) {
                out->created_at = v;
            }

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT) - 1
                   && ngx_strncmp(n->data,
                                  NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT,
                                  n->len) == 0)
        {
            if (ngx_auth_webauthn_credential_atoi64(val, &v) == NGX_OK) {
                out->last_used_at = v;
            }

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_AAGUID) - 1
                   && ngx_strncmp(n->data, NGX_AUTH_WEBAUTHN_CRED_F_AAGUID,
                                  n->len) == 0)
        {
            if (val->len == NGX_AUTH_WEBAUTHN_AAGUID_LEN) {
                ngx_memcpy(out->aaguid, val->data,
                           NGX_AUTH_WEBAUTHN_AAGUID_LEN);
                out->has_aaguid = 1;
            }

        } else if (n->len == sizeof(NGX_AUTH_WEBAUTHN_CRED_F_TRANSPORTS) - 1
                   && ngx_strncmp(n->data,
                                  NGX_AUTH_WEBAUTHN_CRED_F_TRANSPORTS,
                                  n->len) == 0)
        {
            out->transports = *val;
        }
    }

    /* A usable record needs a public key and an algorithm. */
    if (out->public_key.len == 0 || out->alg == 0) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_credential_put(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_auth_webauthn_credential_t *cred)
{
    ngx_str_t key;
    ngx_str_t index_key;
    ngx_uint_t npairs;
    int n;
    char alg_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    char sc_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    char ca_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    char lu_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    ngx_auth_webauthn_redis_pair_t pairs[NGX_AUTH_WEBAUTHN_CRED_MAX_PAIRS];

    if (redis == NULL || pool == NULL || prefix == NULL || cred == NULL
        || cred->credential_id.len == 0 || cred->user_id.len == 0)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_credential_record_key(pool, prefix,
                                                &cred->credential_id,
                                                &key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    npairs = 0;

    pairs[npairs].name.data = (u_char *) NGX_AUTH_WEBAUTHN_CRED_F_USER_ID;
    pairs[npairs].name.len = sizeof(NGX_AUTH_WEBAUTHN_CRED_F_USER_ID) - 1;
    pairs[npairs].value = cred->user_id;
    npairs++;

    pairs[npairs].name.data = (u_char *) NGX_AUTH_WEBAUTHN_CRED_F_PUBLIC_KEY;
    pairs[npairs].name.len = sizeof(NGX_AUTH_WEBAUTHN_CRED_F_PUBLIC_KEY) - 1;
    pairs[npairs].value = cred->public_key;
    npairs++;

    n = snprintf(alg_buf, sizeof(alg_buf), "%d", cred->alg);
    ngx_auth_webauthn_credential_num_pair(&pairs[npairs],
                                          NGX_AUTH_WEBAUTHN_CRED_F_ALG,
                                          sizeof(NGX_AUTH_WEBAUTHN_CRED_F_ALG) -
                                          1,
                                          alg_buf, n);
    npairs++;

    n = snprintf(sc_buf, sizeof(sc_buf), "%lu",
                 (unsigned long) cred->sign_count);
    ngx_auth_webauthn_credential_num_pair(&pairs[npairs],
                                          NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT,
                                          sizeof(
                                              NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT)
                                          - 1, sc_buf, n);
    npairs++;

    n = snprintf(ca_buf, sizeof(ca_buf), "%lld", (long long) cred->created_at);
    ngx_auth_webauthn_credential_num_pair(&pairs[npairs],
                                          NGX_AUTH_WEBAUTHN_CRED_F_CREATED_AT,
                                          sizeof(
                                              NGX_AUTH_WEBAUTHN_CRED_F_CREATED_AT)
                                          - 1, ca_buf, n);
    npairs++;

    n = snprintf(lu_buf, sizeof(lu_buf), "%lld",
                 (long long) cred->last_used_at);
    ngx_auth_webauthn_credential_num_pair(&pairs[npairs],
                                          NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT,
                                          sizeof(
                                              NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT)
                                          - 1, lu_buf, n);
    npairs++;

    if (cred->transports.len > 0) {
        pairs[npairs].name.data =
            (u_char *) NGX_AUTH_WEBAUTHN_CRED_F_TRANSPORTS;
        pairs[npairs].name.len =
            sizeof(NGX_AUTH_WEBAUTHN_CRED_F_TRANSPORTS) - 1;
        pairs[npairs].value = cred->transports;
        npairs++;
    }

    if (cred->has_aaguid) {
        pairs[npairs].name.data = (u_char *) NGX_AUTH_WEBAUTHN_CRED_F_AAGUID;
        pairs[npairs].name.len = sizeof(NGX_AUTH_WEBAUTHN_CRED_F_AAGUID) - 1;
        pairs[npairs].value.data = cred->aaguid;
        pairs[npairs].value.len = NGX_AUTH_WEBAUTHN_AAGUID_LEN;
        npairs++;
    }

    if (ngx_auth_webauthn_redis_hset(redis, &key, pairs, npairs) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Index the credential under its user for management / revocation. */
    if (ngx_auth_webauthn_credential_index_key(pool, prefix, &cred->user_id,
                                               &index_key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_redis_sadd(redis, &index_key, &cred->credential_id)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_credential_update_counter(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *credential_id,
    uint32_t new_count, int64_t last_used_at)
{
    ngx_str_t key;
    int n;
    char sc_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    char lu_buf[NGX_AUTH_WEBAUTHN_CRED_NUMBUF];
    ngx_auth_webauthn_redis_pair_t pairs[2];

    if (redis == NULL || pool == NULL || prefix == NULL
        || credential_id == NULL)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_credential_record_key(pool, prefix, credential_id,
                                                &key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    n = snprintf(sc_buf, sizeof(sc_buf), "%lu", (unsigned long) new_count);
    ngx_auth_webauthn_credential_num_pair(&pairs[0],
                                          NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT,
                                          sizeof(
                                              NGX_AUTH_WEBAUTHN_CRED_F_SIGN_COUNT)
                                          - 1, sc_buf, n);

    n = snprintf(lu_buf, sizeof(lu_buf), "%lld", (long long) last_used_at);
    ngx_auth_webauthn_credential_num_pair(&pairs[1],
                                          NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT,
                                          sizeof(
                                              NGX_AUTH_WEBAUTHN_CRED_F_LAST_USED_AT)
                                          - 1, lu_buf, n);

    return ngx_auth_webauthn_redis_hset(redis, &key, pairs, 2);
}


ngx_int_t
ngx_auth_webauthn_credential_delete(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *prefix, ngx_str_t *credential_id)
{
    ngx_str_t key;
    ngx_str_t index_key;
    ngx_int_t rc;
    ngx_auth_webauthn_credential_t cred;

    if (redis == NULL || pool == NULL || prefix == NULL
        || credential_id == NULL)
    {
        return NGX_ERROR;
    }

    /* Look up user_id first so we can also drop the index entry. */
    rc = ngx_auth_webauthn_credential_get(redis, pool, prefix, credential_id,
                                          &cred);
    if (rc != NGX_OK) {
        return rc;  /* NGX_DECLINED (absent) or NGX_ERROR */
    }

    if (ngx_auth_webauthn_credential_record_key(pool, prefix, credential_id,
                                                &key) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_auth_webauthn_redis_del(redis, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    if (cred.user_id.len > 0) {
        if (ngx_auth_webauthn_credential_index_key(pool, prefix,
                                                   &cred.user_id,
                                                   &index_key) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_auth_webauthn_redis_srem(redis, &index_key, credential_id)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
