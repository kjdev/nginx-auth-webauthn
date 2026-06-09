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
    OPT_CREDENTIAL_ID = AUTH_WEBAUTHN_ADMIN_OPT_SUBCOMMAND_BASE
};


static void
ngx_auth_webauthn_admin_revoke_usage(FILE *out)
{
    fprintf(out,
            "usage: auth-webauthn-admin revoke --credential-id=<id> [options]\n"
            "\n"
            "options:\n"
            "  --credential-id=<b64url>   credential to delete (required)\n"
            "  --redis=<host:port> ...    see 'auth-webauthn-admin --help'\n");
}


int
auth_webauthn_admin_cmd_revoke(auth_webauthn_admin_ctx_t *ctx, int argc,
    char **argv)
{
    int c;
    int rc;
    ngx_str_t cid;
    const char *credential_id = NULL;
    ngx_auth_webauthn_redis_t *redis;

    static const struct option longopts[] = {
        { "credential-id",  required_argument, NULL, OPT_CREDENTIAL_ID },
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
        case OPT_CREDENTIAL_ID:
            credential_id = optarg;
            break;

        case 'h':
            ngx_auth_webauthn_admin_revoke_usage(stdout);
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

    if (credential_id == NULL) {
        fprintf(stderr, "error: --credential-id is required\n");
        return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
    }

    cid.data = (u_char *) credential_id;
    cid.len = ngx_strlen(credential_id);

    if (auth_webauthn_admin_connect(ctx, &redis) != NGX_OK) {
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    rc = ngx_auth_webauthn_credential_delete(redis, ctx->pool,
                                             &ctx->key_prefix, &cid);

    ngx_auth_webauthn_redis_close(redis);

    if (rc == NGX_DECLINED) {
        fprintf(stderr, "error: no such credential\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }
    if (rc != NGX_OK) {
        fprintf(stderr, "error: failed to revoke credential\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    printf("revoked: cid=%.*s\n", (int) cid.len, cid.data);

    return AUTH_WEBAUTHN_ADMIN_EX_OK;
}
