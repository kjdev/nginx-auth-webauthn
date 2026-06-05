/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_redis.h"

#include <stdlib.h>

/*
 * Redis tests need a live server, so they run only when WEBAUTHN_TEST_REDIS is
 * set to "host:port" (e.g. 127.0.0.1:6379).  Without it the suite stays green
 * with no Redis dependency.  Keys live under "webauthn:test:" and are removed
 * at the end.
 */

#define REDIS_TEST_KEY    "webauthn:test:redis:hash"
#define REDIS_TEST_SET    "webauthn:test:redis:set"


/* Parse WEBAUTHN_TEST_REDIS and open a connection; returns NULL when unset. */
static ngx_auth_webauthn_redis_t *
redis_from_env(ngx_pool_t *pool)
{
    char                            *spec;
    char                            *colon;
    ngx_auth_webauthn_redis_t       *redis = NULL;
    ngx_auth_webauthn_redis_conf_t   conf;

    spec = getenv("WEBAUTHN_TEST_REDIS");
    if (spec == NULL || *spec == '\0') {
        return NULL;
    }

    ngx_memzero(&conf, sizeof(conf));
    colon = strchr(spec, ':');

    if (colon != NULL) {
        conf.host.data = (u_char *) spec;
        conf.host.len = (size_t) (colon - spec);
        conf.port = atoi(colon + 1);
    } else {
        conf.host.data = (u_char *) spec;
        conf.host.len = strlen(spec);
        conf.port = 6379;
    }

    conf.db = 0;
    conf.timeout_ms = 1000;

    if (ngx_auth_webauthn_redis_connect(pool, NULL, &conf, &redis) != NGX_OK) {
        CHECK(0, "redis: connect to WEBAUTHN_TEST_REDIS");
        return NULL;
    }

    return redis;
}


void
run_redis_tests(void)
{
    ngx_pool_t                       *pool;
    ngx_auth_webauthn_redis_t        *redis;
    ngx_auth_webauthn_redis_pair_t   *pairs;
    ngx_auth_webauthn_redis_pair_t    set[2];
    ngx_str_t                        *members;
    ngx_str_t                         key = ngx_string(REDIS_TEST_KEY);
    ngx_str_t                         setkey = ngx_string(REDIS_TEST_SET);
    ngx_str_t                         m1 = ngx_string("alpha");
    ngx_str_t                         m2 = ngx_string("beta");
    /* a value with an embedded NUL exercises binary-safe argv */
    static const u_char               binval[] = { 0x00, 0xff, 0x10, 0x00, 0x7f };
    ngx_uint_t                        npairs;
    ngx_uint_t                        nmembers;
    ngx_int_t                         rc;

    pool = ngx_create_pool(8192, NULL);
    if (pool == NULL) {
        return;
    }

    redis = redis_from_env(pool);
    if (redis == NULL) {
        printf("skip - redis: WEBAUTHN_TEST_REDIS unset, skipping live tests\n");
        ngx_destroy_pool(pool);
        return;
    }

    /* HSET with a binary value, then HGETALL it back. */
    set[0].name = (ngx_str_t) ngx_string("text");
    set[0].value = (ngx_str_t) ngx_string("hello");
    set[1].name = (ngx_str_t) ngx_string("bin");
    set[1].value.data = (u_char *) binval;
    set[1].value.len = sizeof(binval);

    rc = ngx_auth_webauthn_redis_hset(redis, &key, set, 2);
    CHECK(rc == NGX_OK, "redis hset: NGX_OK");

    rc = ngx_auth_webauthn_redis_hgetall(redis, pool, &key, &pairs, &npairs);
    CHECK(rc == NGX_OK && npairs == 2, "redis hgetall: two pairs");

    /* Verify the binary value survived the round trip. */
    {
        ngx_uint_t  i;
        ngx_uint_t  found = 0;

        for (i = 0; i < npairs; i++) {
            if (pairs[i].name.len == 3
                && ngx_memcmp(pairs[i].name.data, "bin", 3) == 0)
            {
                found = (pairs[i].value.len == sizeof(binval)
                         && ngx_memcmp(pairs[i].value.data, binval,
                                sizeof(binval)) == 0);
            }
        }
        CHECK(found, "redis hgetall: binary value intact");
    }

    /* Missing key -> empty, not an error. */
    {
        ngx_str_t  missing = ngx_string("webauthn:test:redis:absent");
        rc = ngx_auth_webauthn_redis_hgetall(redis, pool, &missing, &pairs,
            &npairs);
        CHECK(rc == NGX_OK && npairs == 0, "redis hgetall missing: empty");
    }

    /* Set ops: SADD x2, SMEMBERS, SREM. */
    rc = ngx_auth_webauthn_redis_sadd(redis, &setkey, &m1);
    rc |= ngx_auth_webauthn_redis_sadd(redis, &setkey, &m2);
    CHECK(rc == NGX_OK, "redis sadd: NGX_OK");

    rc = ngx_auth_webauthn_redis_smembers(redis, pool, &setkey, &members,
        &nmembers);
    CHECK(rc == NGX_OK && nmembers == 2, "redis smembers: two members");

    rc = ngx_auth_webauthn_redis_srem(redis, &setkey, &m1);
    CHECK(rc == NGX_OK, "redis srem: NGX_OK");

    rc = ngx_auth_webauthn_redis_smembers(redis, pool, &setkey, &members,
        &nmembers);
    CHECK(rc == NGX_OK && nmembers == 1, "redis smembers after srem: one");

    /* EXPIRE then DEL. */
    rc = ngx_auth_webauthn_redis_expire(redis, &key, 60);
    CHECK(rc == NGX_OK, "redis expire: NGX_OK");

    rc = ngx_auth_webauthn_redis_del(redis, &key);
    rc |= ngx_auth_webauthn_redis_del(redis, &setkey);
    CHECK(rc == NGX_OK, "redis del: NGX_OK");

    ngx_auth_webauthn_redis_close(redis);
    ngx_destroy_pool(pool);
}
