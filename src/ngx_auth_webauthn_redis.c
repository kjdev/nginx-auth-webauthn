/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_redis.h"

#include <hiredis/hiredis.h>
#include <sys/time.h>
#include <stdio.h>


struct ngx_auth_webauthn_redis_s {
    redisContext *ctx;
    ngx_pool_t   *pool;
    ngx_log_t    *log;
};


/* Largest decimal an ngx_uint_t needs, plus sign and NUL. */
#define NGX_AUTH_WEBAUTHN_REDIS_NUMBUF  32


static struct timeval
ngx_auth_webauthn_redis_timeval(ngx_uint_t ms)
{
    struct timeval tv;

    tv.tv_sec = (time_t) (ms / 1000);
    tv.tv_usec = (suseconds_t) ((ms % 1000) * 1000);

    return tv;
}


/*
 * Issue one command via redisCommandArgv (binary-safe).  Returns the reply,
 * which the caller must freeReplyObject, or NULL on a connection-level error
 * (which is logged).  A REDIS_REPLY_ERROR is returned to the caller to inspect.
 */
static redisReply *
ngx_auth_webauthn_redis_exec(ngx_auth_webauthn_redis_t *redis, int argc,
    const char **argv, const size_t *argvlen)
{
    redisReply *reply;

    reply = redisCommandArgv(redis->ctx, argc, argv, argvlen);

    if (reply == NULL) {
        ngx_log_error(NGX_LOG_ERR, redis->log, 0,
                      "auth_webauthn: redis command failed: %s",
                      redis->ctx->errstr);
        return NULL;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        ngx_log_error(NGX_LOG_ERR, redis->log, 0,
                      "auth_webauthn: redis error reply: %s", reply->str);
    }

    return reply;
}


/* Copy src[0..len) into a fresh pool-allocated ngx_str_t. */
static ngx_int_t
ngx_auth_webauthn_redis_dup(ngx_pool_t *pool, const char *src, size_t len,
    ngx_str_t *dst)
{
    dst->len = len;

    if (len == 0) {
        dst->data = (u_char *) "";
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(pool, len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src, len);

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_redis_connect(ngx_pool_t *pool, ngx_log_t *log,
    ngx_auth_webauthn_redis_conf_t *conf, ngx_auth_webauthn_redis_t **out)
{
    char *host;
    char numbuf[NGX_AUTH_WEBAUTHN_REDIS_NUMBUF];
    int n;
    struct timeval tv;
    redisReply *reply;
    ngx_auth_webauthn_redis_t *redis;
    const char *argv[2];
    size_t argvlen[2];

    if (pool == NULL || conf == NULL || out == NULL || conf->host.len == 0) {
        return NGX_ERROR;
    }

    redis = ngx_pcalloc(pool, sizeof(ngx_auth_webauthn_redis_t));
    if (redis == NULL) {
        return NGX_ERROR;
    }

    redis->pool = pool;
    redis->log = log;

    /* hiredis needs a NUL-terminated host string. */
    host = ngx_pnalloc(pool, conf->host.len + 1);
    if (host == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(host, conf->host.data, conf->host.len);
    host[conf->host.len] = '\0';

    if (conf->timeout_ms > 0) {
        tv = ngx_auth_webauthn_redis_timeval(conf->timeout_ms);
        redis->ctx = redisConnectWithTimeout(host, conf->port, tv);
    } else {
        redis->ctx = redisConnect(host, conf->port);
    }

    if (redis->ctx == NULL || redis->ctx->err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_webauthn: redis connect to %s:%d failed: %s",
                      host, conf->port,
                      redis->ctx ? redis->ctx->errstr : "allocation failed");
        if (redis->ctx != NULL) {
            redisFree(redis->ctx);
            redis->ctx = NULL;
        }
        return NGX_ERROR;
    }

    if (conf->timeout_ms > 0) {
        tv = ngx_auth_webauthn_redis_timeval(conf->timeout_ms);
        (void) redisSetTimeout(redis->ctx, tv);
    }

    /* AUTH */
    if (conf->password.len > 0) {
        argv[0] = "AUTH";
        argvlen[0] = sizeof("AUTH") - 1;
        argv[1] = (const char *) conf->password.data;
        argvlen[1] = conf->password.len;

        reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            if (reply != NULL) {
                freeReplyObject(reply);
            }
            ngx_auth_webauthn_redis_close(redis);
            return NGX_ERROR;
        }
        freeReplyObject(reply);
    }

    /* SELECT */
    if (conf->db > 0) {
        n = snprintf(numbuf, sizeof(numbuf), "%lu", (unsigned long) conf->db);
        if (n < 0 || (size_t) n >= sizeof(numbuf)) {
            ngx_auth_webauthn_redis_close(redis);
            return NGX_ERROR;
        }

        argv[0] = "SELECT";
        argvlen[0] = sizeof("SELECT") - 1;
        argv[1] = numbuf;
        argvlen[1] = (size_t) n;

        reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
            if (reply != NULL) {
                freeReplyObject(reply);
            }
            ngx_auth_webauthn_redis_close(redis);
            return NGX_ERROR;
        }
        freeReplyObject(reply);
    }

    *out = redis;

    return NGX_OK;
}


void
ngx_auth_webauthn_redis_close(ngx_auth_webauthn_redis_t *redis)
{
    if (redis == NULL || redis->ctx == NULL) {
        return;
    }

    redisFree(redis->ctx);
    redis->ctx = NULL;
}


ngx_int_t
ngx_auth_webauthn_redis_hset(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_auth_webauthn_redis_pair_t *pairs, ngx_uint_t npairs)
{
    int argc;
    int i;
    ngx_uint_t p;
    ngx_int_t rc;
    const char **argv;
    size_t *argvlen;
    redisReply *reply;

    if (redis == NULL || redis->ctx == NULL || key == NULL
        || (npairs > 0 && pairs == NULL))
    {
        return NGX_ERROR;
    }

    if (npairs == 0) {
        return NGX_OK;
    }

    /* HSET key field value field value ... */
    argc = 2 + (int) (npairs * 2);

    argv = ngx_palloc(redis->pool, (size_t) argc * sizeof(char *));
    argvlen = ngx_palloc(redis->pool, (size_t) argc * sizeof(size_t));
    if (argv == NULL || argvlen == NULL) {
        return NGX_ERROR;
    }

    argv[0] = "HSET";
    argvlen[0] = sizeof("HSET") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;

    i = 2;
    for (p = 0; p < npairs; p++) {
        argv[i] = (const char *) pairs[p].name.data;
        argvlen[i] = pairs[p].name.len;
        i++;
        argv[i] = (const char *) pairs[p].value.data;
        argvlen[i] = pairs[p].value.len;
        i++;
    }

    reply = ngx_auth_webauthn_redis_exec(redis, argc, argv, argvlen);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        rc = NGX_ERROR;
    } else {
        rc = NGX_OK;
    }

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    return rc;
}


ngx_int_t
ngx_auth_webauthn_redis_hgetall(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key,
    ngx_auth_webauthn_redis_pair_t **pairs, ngx_uint_t *npairs)
{
    size_t i;
    size_t n;
    ngx_int_t rc;
    redisReply *reply;
    redisReply *name;
    redisReply *value;
    const char *argv[2];
    size_t argvlen[2];
    ngx_auth_webauthn_redis_pair_t *out;

    if (redis == NULL || redis->ctx == NULL || pool == NULL || key == NULL
        || pairs == NULL || npairs == NULL)
    {
        return NGX_ERROR;
    }

    *pairs = NULL;
    *npairs = 0;

    argv[0] = "HGETALL";
    argvlen[0] = sizeof("HGETALL") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;

    reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        if (reply != NULL) {
            freeReplyObject(reply);
        }
        return NGX_ERROR;
    }

    if (reply->type != REDIS_REPLY_ARRAY || reply->elements == 0) {
        /* Missing key: HGETALL returns an empty array. */
        freeReplyObject(reply);
        return NGX_OK;
    }

    rc = NGX_OK;
    n = reply->elements / 2;

    out = ngx_palloc(pool, n * sizeof(ngx_auth_webauthn_redis_pair_t));
    if (out == NULL) {
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        name = reply->element[i * 2];
        value = reply->element[i * 2 + 1];

        if (ngx_auth_webauthn_redis_dup(pool, name->str, name->len,
                                        &out[i].name) != NGX_OK
            || ngx_auth_webauthn_redis_dup(pool, value->str, value->len,
                                           &out[i].value) != NGX_OK)
        {
            rc = NGX_ERROR;
            break;
        }
    }

    freeReplyObject(reply);

    if (rc != NGX_OK) {
        return rc;
    }

    *pairs = out;
    *npairs = (ngx_uint_t) n;

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_redis_del(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key)
{
    ngx_int_t rc;
    redisReply *reply;
    const char *argv[2];
    size_t argvlen[2];

    if (redis == NULL || redis->ctx == NULL || key == NULL) {
        return NGX_ERROR;
    }

    argv[0] = "DEL";
    argvlen[0] = sizeof("DEL") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;

    reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
    rc = (reply != NULL && reply->type != REDIS_REPLY_ERROR)
         ? NGX_OK : NGX_ERROR;

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    return rc;
}


/* Shared body for the two-argument set commands SADD / SREM. */
static ngx_int_t
ngx_auth_webauthn_redis_set_op(ngx_auth_webauthn_redis_t *redis,
    const char *cmd, size_t cmdlen, ngx_str_t *key, ngx_str_t *member)
{
    ngx_int_t rc;
    redisReply *reply;
    const char *argv[3];
    size_t argvlen[3];

    if (redis == NULL || redis->ctx == NULL || key == NULL || member == NULL) {
        return NGX_ERROR;
    }

    argv[0] = cmd;
    argvlen[0] = cmdlen;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;
    argv[2] = (const char *) member->data;
    argvlen[2] = member->len;

    reply = ngx_auth_webauthn_redis_exec(redis, 3, argv, argvlen);
    rc = (reply != NULL && reply->type != REDIS_REPLY_ERROR)
         ? NGX_OK : NGX_ERROR;

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    return rc;
}


ngx_int_t
ngx_auth_webauthn_redis_sadd(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_str_t *member)
{
    return ngx_auth_webauthn_redis_set_op(redis, "SADD", sizeof("SADD") - 1,
                                          key, member);
}


ngx_int_t
ngx_auth_webauthn_redis_srem(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_str_t *member)
{
    return ngx_auth_webauthn_redis_set_op(redis, "SREM", sizeof("SREM") - 1,
                                          key, member);
}


ngx_int_t
ngx_auth_webauthn_redis_smembers(ngx_auth_webauthn_redis_t *redis,
    ngx_pool_t *pool, ngx_str_t *key, ngx_str_t **members, ngx_uint_t *nmembers)
{
    size_t i;
    size_t n;
    ngx_int_t rc;
    redisReply *reply;
    redisReply *member;
    const char *argv[2];
    size_t argvlen[2];
    ngx_str_t *out;

    if (redis == NULL || redis->ctx == NULL || pool == NULL || key == NULL
        || members == NULL || nmembers == NULL)
    {
        return NGX_ERROR;
    }

    *members = NULL;
    *nmembers = 0;

    argv[0] = "SMEMBERS";
    argvlen[0] = sizeof("SMEMBERS") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;

    reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        if (reply != NULL) {
            freeReplyObject(reply);
        }
        return NGX_ERROR;
    }

    if (reply->type != REDIS_REPLY_ARRAY || reply->elements == 0) {
        freeReplyObject(reply);
        return NGX_OK;
    }

    rc = NGX_OK;
    n = reply->elements;

    out = ngx_palloc(pool, n * sizeof(ngx_str_t));
    if (out == NULL) {
        freeReplyObject(reply);
        return NGX_ERROR;
    }

    for (i = 0; i < n; i++) {
        member = reply->element[i];
        if (ngx_auth_webauthn_redis_dup(pool, member->str, member->len,
                                        &out[i]) != NGX_OK)
        {
            rc = NGX_ERROR;
            break;
        }
    }

    freeReplyObject(reply);

    if (rc != NGX_OK) {
        return rc;
    }

    *members = out;
    *nmembers = (ngx_uint_t) n;

    return NGX_OK;
}


ngx_int_t
ngx_auth_webauthn_redis_expire(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_uint_t seconds)
{
    char numbuf[NGX_AUTH_WEBAUTHN_REDIS_NUMBUF];
    int n;
    ngx_int_t rc;
    redisReply *reply;
    const char *argv[3];
    size_t argvlen[3];

    if (redis == NULL || redis->ctx == NULL || key == NULL) {
        return NGX_ERROR;
    }

    n = snprintf(numbuf, sizeof(numbuf), "%lu", (unsigned long) seconds);
    if (n < 0 || (size_t) n >= sizeof(numbuf)) {
        return NGX_ERROR;
    }

    argv[0] = "EXPIRE";
    argvlen[0] = sizeof("EXPIRE") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;
    argv[2] = numbuf;
    argvlen[2] = (size_t) n;

    reply = ngx_auth_webauthn_redis_exec(redis, 3, argv, argvlen);
    rc = (reply != NULL && reply->type != REDIS_REPLY_ERROR)
         ? NGX_OK : NGX_ERROR;

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    return rc;
}


ngx_int_t
ngx_auth_webauthn_redis_set_ex(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_str_t *value, ngx_uint_t seconds)
{
    char numbuf[NGX_AUTH_WEBAUTHN_REDIS_NUMBUF];
    int n;
    ngx_int_t rc;
    redisReply *reply;
    const char *argv[5];
    size_t argvlen[5];

    if (redis == NULL || redis->ctx == NULL || key == NULL || value == NULL) {
        return NGX_ERROR;
    }

    n = snprintf(numbuf, sizeof(numbuf), "%lu", (unsigned long) seconds);
    if (n < 0 || (size_t) n >= sizeof(numbuf)) {
        return NGX_ERROR;
    }

    /* SET key value EX seconds */
    argv[0] = "SET";
    argvlen[0] = sizeof("SET") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;
    argv[2] = (const char *) value->data;
    argvlen[2] = value->len;
    argv[3] = "EX";
    argvlen[3] = sizeof("EX") - 1;
    argv[4] = numbuf;
    argvlen[4] = (size_t) n;

    reply = ngx_auth_webauthn_redis_exec(redis, 5, argv, argvlen);
    rc = (reply != NULL && reply->type != REDIS_REPLY_ERROR)
         ? NGX_OK : NGX_ERROR;

    if (reply != NULL) {
        freeReplyObject(reply);
    }

    return rc;
}


ngx_int_t
ngx_auth_webauthn_redis_getdel(ngx_auth_webauthn_redis_t *redis, ngx_str_t *key,
    ngx_uint_t *found)
{
    redisReply *reply;
    const char *argv[2];
    size_t argvlen[2];

    if (redis == NULL || redis->ctx == NULL || key == NULL || found == NULL) {
        return NGX_ERROR;
    }

    *found = 0;

    argv[0] = "GETDEL";
    argvlen[0] = sizeof("GETDEL") - 1;
    argv[1] = (const char *) key->data;
    argvlen[1] = key->len;

    reply = ngx_auth_webauthn_redis_exec(redis, 2, argv, argvlen);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        if (reply != NULL) {
            freeReplyObject(reply);
        }
        return NGX_ERROR;
    }

    /* A present key returns its (string) value; an absent / expired key
     * returns nil. */
    if (reply->type == REDIS_REPLY_STRING) {
        *found = 1;
    }

    freeReplyObject(reply);

    return NGX_OK;
}
