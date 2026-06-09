/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "auth_webauthn_admin.h"
#include "ngx_auth_webauthn_credential.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>

enum {
    OPT_USER_ID = AUTH_WEBAUTHN_ADMIN_OPT_SUBCOMMAND_BASE
};


static void
ngx_auth_webauthn_admin_list_usage(FILE *out)
{
    fprintf(out,
            "usage: auth-webauthn-admin list --user-id=<id> [options]\n"
            "\n"
            "options:\n"
            "  --user-id=<id>            user whose credentials to list (required)\n"
            "  --redis=<host:port> ...   see 'auth-webauthn-admin --help'\n");
}


/* Build {prefix}user:{uid}:creds (mirrors the credential layer's index key). */
static ngx_int_t
ngx_auth_webauthn_admin_index_key(ngx_pool_t *pool, ngx_str_t *prefix,
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


int
auth_webauthn_admin_cmd_list(auth_webauthn_admin_ctx_t *ctx, int argc,
    char **argv)
{
    int c;
    ngx_str_t uid;
    ngx_str_t index_key;
    ngx_str_t *members;
    ngx_uint_t nmembers;
    ngx_uint_t i;
    char tbuf[24];
    const char *user_id = NULL;
    ngx_auth_webauthn_redis_t *redis;
    ngx_auth_webauthn_credential_t cred;

    static const struct option longopts[] = {
        { "user-id",        required_argument, NULL, OPT_USER_ID },
        { "redis",          required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS },
        { "redis-password", required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_PASSWORD },
        { "redis-db",       required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_DB },
        { "redis-timeout",  required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_TIMEOUT },
        { "key-prefix",     required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_KEY_PREFIX },
        { "help",           no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case OPT_USER_ID:
            user_id = optarg;
            break;

        case 'h':
            ngx_auth_webauthn_admin_list_usage(stdout);
            return AUTH_WEBAUTHN_ADMIN_EX_OK;

        case '?':
            return AUTH_WEBAUTHN_ADMIN_EX_USAGE;

        default:
            if (auth_webauthn_admin_parse_common_opt(ctx, c, optarg)
                == NGX_ERROR)
            {
                return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
            }
            break;
        }
    }

    if (user_id == NULL) {
        fprintf(stderr, "error: --user-id is required\n");
        return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
    }

    uid.data = (u_char *) user_id;
    uid.len = ngx_strlen(user_id);

    if (ngx_auth_webauthn_admin_index_key(ctx->pool, &ctx->key_prefix, &uid,
                                          &index_key) != NGX_OK)
    {
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (auth_webauthn_admin_connect(ctx, &redis) != NGX_OK) {
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_redis_smembers(redis, ctx->pool, &index_key,
                                         &members, &nmembers) != NGX_OK)
    {
        fprintf(stderr, "error: failed to read credential index\n");
        ngx_auth_webauthn_redis_close(redis);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    printf("%-43s %-6s %-11s %s\n",
           "CREDENTIAL_ID", "ALG", "SIGN_COUNT", "CREATED_AT");

    for (i = 0; i < nmembers; i++) {
        ngx_int_t rc;

        rc = ngx_auth_webauthn_credential_get(redis, ctx->pool,
                                              &ctx->key_prefix, &members[i],
                                              &cred);
        if (rc == NGX_OK) {
            printf("%-43.*s %-6s %-11lu %s\n",
                   (int) members[i].len, members[i].data,
                   auth_webauthn_admin_alg_name(cred.alg),
                   (unsigned long) cred.sign_count,
                   auth_webauthn_admin_fmt_time(cred.created_at, tbuf,
                                                sizeof(tbuf)));
        } else {
            /* Index points at a credential whose record is gone/unreadable. */
            printf("%-43.*s %-6s %-11s %s\n",
                   (int) members[i].len, members[i].data, "?", "?",
                   "(missing)");
        }
    }

    ngx_auth_webauthn_redis_close(redis);

    return AUTH_WEBAUTHN_ADMIN_EX_OK;
}
