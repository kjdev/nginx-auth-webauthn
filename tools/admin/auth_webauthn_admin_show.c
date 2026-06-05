/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "auth_webauthn_admin.h"
#include "ngx_auth_webauthn_credential.h"
#include "ngx_auth_webauthn_authdata.h"  /* NGX_AUTH_WEBAUTHN_AAGUID_LEN */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

enum {
    OPT_CREDENTIAL_ID = AUTH_WEBAUTHN_ADMIN_OPT_SUBCOMMAND_BASE
};


static void
ngx_auth_webauthn_admin_show_usage(FILE *out)
{
    fprintf(out,
        "usage: auth-webauthn-admin show --credential-id=<id> [options]\n"
        "\n"
        "options:\n"
        "  --credential-id=<b64url>   credential to display (required)\n"
        "  --redis=<host:port> ...    see 'auth-webauthn-admin --help'\n");
}


/* Format a 16-byte AAGUID as 8-4-4-4-12 hex (RFC 4122 textual UUID). */
static void
ngx_auth_webauthn_admin_aaguid_fmt(const u_char *g, char *buf)
{
    static const char  hex[] = "0123456789abcdef";
    static const int   dashes[] = { 4, 6, 8, 10 };  /* byte indices */
    size_t             i;
    size_t             j;
    size_t             d;

    j = 0;
    d = 0;
    for (i = 0; i < NGX_AUTH_WEBAUTHN_AAGUID_LEN; i++) {
        if (d < 4 && i == (size_t) dashes[d]) {
            buf[j++] = '-';
            d++;
        }
        buf[j++] = hex[g[i] >> 4];
        buf[j++] = hex[g[i] & 0x0f];
    }
    buf[j] = '\0';
}


int
auth_webauthn_admin_cmd_show(auth_webauthn_admin_ctx_t *ctx, int argc,
    char **argv)
{
    int                              c;
    ngx_int_t                        rc;
    ngx_str_t                        cid;
    char                             tbuf[24];
    char                             aaguid_buf[40];
    const char                      *credential_id = NULL;
    ngx_auth_webauthn_redis_t       *redis;
    ngx_auth_webauthn_credential_t   cred;

    static const struct option  longopts[] = {
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
            ngx_auth_webauthn_admin_show_usage(stdout);
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

    rc = ngx_auth_webauthn_credential_get(redis, ctx->pool, &ctx->key_prefix,
        &cid, &cred);

    ngx_auth_webauthn_redis_close(redis);

    if (rc == NGX_DECLINED) {
        fprintf(stderr, "error: no such credential\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }
    if (rc != NGX_OK) {
        fprintf(stderr, "error: failed to read credential\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    printf("credential_id: %.*s\n", (int) cid.len, cid.data);
    printf("user_id:       %.*s\n",
        (int) cred.user_id.len, cred.user_id.data);
    printf("alg:           %s (%d)\n",
        auth_webauthn_admin_alg_name(cred.alg), cred.alg);
    printf("sign_count:    %lu\n", (unsigned long) cred.sign_count);
    printf("created_at:    %s\n",
        auth_webauthn_admin_fmt_time(cred.created_at, tbuf, sizeof(tbuf)));
    printf("last_used_at:  %s\n",
        auth_webauthn_admin_fmt_time(cred.last_used_at, tbuf, sizeof(tbuf)));

    if (cred.has_aaguid) {
        ngx_auth_webauthn_admin_aaguid_fmt(cred.aaguid, aaguid_buf);
        printf("aaguid:        %s\n", aaguid_buf);
    } else {
        printf("aaguid:        -\n");
    }

    if (cred.transports.len > 0) {
        printf("transports:    %.*s\n",
            (int) cred.transports.len, cred.transports.data);
    } else {
        printf("transports:    -\n");
    }

    printf("public_key:    %lu bytes (DER SubjectPublicKeyInfo)\n",
        (unsigned long) cred.public_key.len);

    return AUTH_WEBAUTHN_ADMIN_EX_OK;
}
