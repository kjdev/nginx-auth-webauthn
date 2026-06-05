/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_credential.h"
#include "ngx_auth_webauthn_redis.h"

#include <stdlib.h>

/*
 * Like the redis tests, these run only when WEBAUTHN_TEST_REDIS=host:port is
 * set.  They drive a full credential lifecycle (put -> get -> update -> delete)
 * under the "webauthn:test:" key prefix and clean up afterwards.
 */

#define CRED_PREFIX  "webauthn:test:"


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
        return NULL;
    }

    return redis;
}


void
run_credential_tests(void)
{
    ngx_pool_t                      *pool;
    ngx_auth_webauthn_redis_t       *redis;
    ngx_str_t                        prefix = ngx_string(CRED_PREFIX);
    ngx_str_t                        cid = ngx_string("webauthn-test-cid-1");
    ngx_str_t                        index_key =
        ngx_string(CRED_PREFIX "user:testuser:creds");
    ngx_str_t                       *members;
    ngx_uint_t                       nmembers;
    ngx_int_t                        rc;
    static const u_char              der[] = { 0x30, 0x59, 0x00, 0x01, 0x02 };
    ngx_auth_webauthn_credential_t   cred;
    ngx_auth_webauthn_credential_t   got;

    pool = ngx_create_pool(8192, NULL);
    if (pool == NULL) {
        return;
    }

    redis = redis_from_env(pool);
    if (redis == NULL) {
        printf("skip - credential: WEBAUTHN_TEST_REDIS unset, "
               "skipping live tests\n");
        ngx_destroy_pool(pool);
        return;
    }

    /* Make sure no stale record lingers from a prior failed run. */
    (void) ngx_auth_webauthn_credential_delete(redis, pool, &prefix, &cid);

    ngx_memzero(&cred, sizeof(cred));
    cred.credential_id = cid;
    ngx_str_set(&cred.user_id, "testuser");
    cred.public_key.data = (u_char *) der;
    cred.public_key.len = sizeof(der);
    cred.alg = -7;
    cred.sign_count = 5;
    cred.created_at = 1729180000;
    cred.last_used_at = 1729180000;
    ngx_memset(cred.aaguid, 0xCD, NGX_AUTH_WEBAUTHN_AAGUID_LEN);
    cred.has_aaguid = 1;
    ngx_str_set(&cred.transports, "usb,nfc");

    rc = ngx_auth_webauthn_credential_put(redis, pool, &prefix, &cred);
    CHECK(rc == NGX_OK, "credential put: NGX_OK");

    rc = ngx_auth_webauthn_credential_get(redis, pool, &prefix, &cid, &got);
    CHECK(rc == NGX_OK, "credential get: NGX_OK");
    CHECK(got.user_id.len == 8 && ngx_memcmp(got.user_id.data, "testuser", 8)
              == 0, "credential get: user_id");
    CHECK(got.public_key.len == sizeof(der)
          && ngx_memcmp(got.public_key.data, der, sizeof(der)) == 0,
        "credential get: public_key (DER) intact");
    CHECK(got.alg == -7, "credential get: alg == -7");
    CHECK(got.sign_count == 5, "credential get: sign_count == 5");
    CHECK(got.created_at == 1729180000, "credential get: created_at");
    CHECK(got.has_aaguid && got.aaguid[0] == 0xCD,
        "credential get: aaguid intact");
    CHECK(got.transports.len == 7
          && ngx_memcmp(got.transports.data, "usb,nfc", 7) == 0,
        "credential get: transports");

    /* The credential id is indexed under the user. */
    rc = ngx_auth_webauthn_redis_smembers(redis, pool, &index_key, &members,
        &nmembers);
    CHECK(rc == NGX_OK && nmembers == 1, "credential put: user index has cid");

    /* Counter update. */
    rc = ngx_auth_webauthn_credential_update_counter(redis, pool, &prefix, &cid,
        42, 1729190000);
    CHECK(rc == NGX_OK, "credential update_counter: NGX_OK");

    rc = ngx_auth_webauthn_credential_get(redis, pool, &prefix, &cid, &got);
    CHECK(rc == NGX_OK && got.sign_count == 42,
        "credential update_counter: sign_count == 42");
    CHECK(got.last_used_at == 1729190000,
        "credential update_counter: last_used_at");

    /* Delete removes the record and the index entry. */
    rc = ngx_auth_webauthn_credential_delete(redis, pool, &prefix, &cid);
    CHECK(rc == NGX_OK, "credential delete: NGX_OK");

    rc = ngx_auth_webauthn_credential_get(redis, pool, &prefix, &cid, &got);
    CHECK(rc == NGX_DECLINED, "credential get after delete: NGX_DECLINED");

    rc = ngx_auth_webauthn_redis_smembers(redis, pool, &index_key, &members,
        &nmembers);
    CHECK(rc == NGX_OK && nmembers == 0,
        "credential delete: user index emptied");

    /* Deleting a non-existent credential reports absence. */
    rc = ngx_auth_webauthn_credential_delete(redis, pool, &prefix, &cid);
    CHECK(rc == NGX_DECLINED, "credential delete missing: NGX_DECLINED");

    ngx_auth_webauthn_redis_close(redis);
    ngx_destroy_pool(pool);
}
