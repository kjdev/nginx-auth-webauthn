/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "auth_webauthn_admin.h"
#include "ngx_auth_webauthn_cose.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

/* Read the whole file in one go; 16 MiB is far above any attestation JSON. */
#define AUTH_WEBAUTHN_ADMIN_FILE_MAX  (16 * 1024 * 1024)
#define AUTH_WEBAUTHN_ADMIN_READ_CHUNK  65536

static const ngx_str_t  ngx_auth_webauthn_admin_default_prefix =
    ngx_string("webauthn:");


static void
ngx_auth_webauthn_admin_usage(FILE *out)
{
    fprintf(out,
        "usage: auth-webauthn-admin <command> [options]\n"
        "\n"
        "commands:\n"
        "  register   register a credential from an AttestationResponse JSON\n"
        "  revoke     delete a credential by id\n"
        "  list       list a user's credentials\n"
        "  show       show one credential in detail\n"
        "\n"
        "common options (all commands):\n"
        "  --redis=<host:port>          Redis server (required)\n"
        "  --redis-password=<s|file:p>  Redis AUTH (literal or file:<path>)\n"
        "  --redis-db=<int>             Redis DB number (default 0)\n"
        "  --redis-timeout=<ms>         connect/command timeout (default %d)\n"
        "  --key-prefix=<string>        Redis key prefix (default \"%.*s\")\n"
        "\n"
        "  -h, --help                   show help; --version prints version\n"
        "\n"
        "run 'auth-webauthn-admin <command> --help' for per-command options\n",
        AUTH_WEBAUTHN_ADMIN_TIMEOUT_MS,
        (int) ngx_auth_webauthn_admin_default_prefix.len,
        ngx_auth_webauthn_admin_default_prefix.data);
}


const char *
auth_webauthn_admin_alg_name(int alg)
{
    switch (alg) {
    case NGX_AUTH_WEBAUTHN_COSE_ALG_ES256:
        return "ES256";
    case NGX_AUTH_WEBAUTHN_COSE_ALG_EDDSA:
        return "EdDSA";
    case NGX_AUTH_WEBAUTHN_COSE_ALG_RS256:
        return "RS256";
    default:
        return "unknown";
    }
}


const char *
auth_webauthn_admin_fmt_time(int64_t t, char *buf, size_t size)
{
    time_t     tt;
    struct tm  tm;

    if (t <= 0) {
        snprintf(buf, size, "-");
        return buf;
    }

    tt = (time_t) t;
    if (gmtime_r(&tt, &tm) == NULL
        || strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
    {
        snprintf(buf, size, "-");
    }

    return buf;
}


ngx_int_t
auth_webauthn_admin_read_file(ngx_pool_t *pool, const char *path,
    ngx_str_t *out)
{
    FILE    *fp;
    u_char  *buf;
    u_char  *nbuf;
    size_t   cap;
    size_t   len;
    size_t   n;

    if (pool == NULL || path == NULL || out == NULL) {
        return NGX_ERROR;
    }

    if (path[0] == '-' && path[1] == '\0') {
        fp = stdin;
    } else {
        fp = fopen(path, "rb");
        if (fp == NULL) {
            fprintf(stderr, "error: cannot open '%s'\n", path);
            return NGX_ERROR;
        }
    }

    cap = AUTH_WEBAUTHN_ADMIN_READ_CHUNK;
    len = 0;
    buf = ngx_palloc(pool, cap);
    if (buf == NULL) {
        goto failed;
    }

    for ( ;; ) {
        if (len == cap) {
            if (cap >= AUTH_WEBAUTHN_ADMIN_FILE_MAX) {
                fprintf(stderr, "error: input exceeds %d bytes\n",
                    AUTH_WEBAUTHN_ADMIN_FILE_MAX);
                goto failed;
            }
            cap *= 2;
            nbuf = ngx_palloc(pool, cap);
            if (nbuf == NULL) {
                goto failed;
            }
            ngx_memcpy(nbuf, buf, len);
            buf = nbuf;
        }

        n = fread(buf + len, 1, cap - len, fp);
        len += n;

        if (n == 0) {
            if (ferror(fp)) {
                fprintf(stderr, "error: read failed on '%s'\n", path);
                goto failed;
            }
            break;  /* EOF */
        }
    }

    if (fp != stdin) {
        fclose(fp);
    }

    /* NUL-terminate (one spare byte may require a grow). */
    if (len == cap) {
        nbuf = ngx_palloc(pool, cap + 1);
        if (nbuf == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(nbuf, buf, len);
        buf = nbuf;
    }
    buf[len] = '\0';

    out->data = buf;
    out->len = len;

    return NGX_OK;

failed:

    if (fp != stdin) {
        fclose(fp);
    }
    return NGX_ERROR;
}


/* Strip a single trailing "\r\n" / "\n" so file-stored passwords are usable. */
static void
ngx_auth_webauthn_admin_chomp(ngx_str_t *s)
{
    while (s->len > 0
           && (s->data[s->len - 1] == '\n' || s->data[s->len - 1] == '\r'))
    {
        s->len--;
    }
}


ngx_int_t
auth_webauthn_admin_parse_common_opt(auth_webauthn_admin_ctx_t *ctx, int opt,
    const char *arg)
{
    ngx_str_t   file;
    const char *colon;
    char       *end;
    long        v;

    switch (opt) {

    case AUTH_WEBAUTHN_ADMIN_OPT_REDIS:
        /* host:port, split on the last ':' (IPv6 literals are not expected
         * here; the sibling modules accept the same host:port form). */
        colon = strrchr(arg, ':');
        if (colon == NULL || colon == arg || colon[1] == '\0') {
            fprintf(stderr, "error: --redis expects <host>:<port>\n");
            return NGX_ERROR;
        }
        ctx->redis_host.data = (u_char *) arg;
        ctx->redis_host.len = (size_t) (colon - arg);
        v = strtol(colon + 1, &end, 10);
        if (*end != '\0' || v <= 0 || v > 65535) {
            fprintf(stderr, "error: --redis port out of range\n");
            return NGX_ERROR;
        }
        ctx->redis_port = (int) v;
        return NGX_OK;

    case AUTH_WEBAUTHN_ADMIN_OPT_REDIS_PASSWORD:
        if (strncmp(arg, "file:", 5) == 0) {
            if (auth_webauthn_admin_read_file(ctx->pool, arg + 5, &file)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_auth_webauthn_admin_chomp(&file);
            ctx->redis_password = file;
        } else {
            ctx->redis_password.data = (u_char *) arg;
            ctx->redis_password.len = ngx_strlen(arg);
        }
        return NGX_OK;

    case AUTH_WEBAUTHN_ADMIN_OPT_REDIS_DB:
        v = strtol(arg, &end, 10);
        if (*end != '\0' || v < 0 || v > 65535) {
            fprintf(stderr, "error: --redis-db out of range\n");
            return NGX_ERROR;
        }
        ctx->redis_db = (ngx_uint_t) v;
        return NGX_OK;

    case AUTH_WEBAUTHN_ADMIN_OPT_REDIS_TIMEOUT:
        v = strtol(arg, &end, 10);
        if (*end != '\0' || v < 0 || v > 600000) {
            fprintf(stderr, "error: --redis-timeout out of range (ms)\n");
            return NGX_ERROR;
        }
        ctx->redis_timeout_ms = (ngx_uint_t) v;
        return NGX_OK;

    case AUTH_WEBAUTHN_ADMIN_OPT_KEY_PREFIX:
        ctx->key_prefix.data = (u_char *) arg;
        ctx->key_prefix.len = ngx_strlen(arg);
        return NGX_OK;

    default:
        return NGX_DECLINED;
    }
}


ngx_int_t
auth_webauthn_admin_connect(auth_webauthn_admin_ctx_t *ctx,
    ngx_auth_webauthn_redis_t **out)
{
    ngx_auth_webauthn_redis_conf_t  conf;

    if (ctx->redis_host.len == 0 || ctx->redis_port == 0) {
        fprintf(stderr, "error: --redis=<host:port> is required\n");
        return NGX_ERROR;
    }

    ngx_memzero(&conf, sizeof(conf));
    conf.host = ctx->redis_host;
    conf.port = ctx->redis_port;
    conf.password = ctx->redis_password;
    conf.db = ctx->redis_db;
    conf.timeout_ms = ctx->redis_timeout_ms;

    if (ngx_auth_webauthn_redis_connect(ctx->pool, ctx->log, &conf, out)
        != NGX_OK)
    {
        fprintf(stderr, "error: cannot connect to Redis %.*s:%d\n",
            (int) ctx->redis_host.len, ctx->redis_host.data, ctx->redis_port);
        return NGX_ERROR;
    }

    return NGX_OK;
}


int
main(int argc, char **argv)
{
    int                        rc;
    const char                *cmd;
    ngx_log_t                  log;
    ngx_pool_t                *pool;
    auth_webauthn_admin_ctx_t  ctx;

    if (argc < 2) {
        ngx_auth_webauthn_admin_usage(stderr);
        return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
    }

    cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        ngx_auth_webauthn_admin_usage(stdout);
        return AUTH_WEBAUTHN_ADMIN_EX_OK;
    }

    if (strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0) {
        printf("auth-webauthn-admin %s\n", AUTH_WEBAUTHN_ADMIN_VERSION);
        return AUTH_WEBAUTHN_ADMIN_EX_OK;
    }

    ngx_memzero(&log, sizeof(log));
    log.log_level = NGX_LOG_ERR;

    pool = ngx_create_pool(4096, &log);
    if (pool == NULL) {
        fprintf(stderr, "error: out of memory\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    ngx_memzero(&ctx, sizeof(ctx));
    ctx.pool = pool;
    ctx.log = &log;
    ctx.redis_timeout_ms = AUTH_WEBAUTHN_ADMIN_TIMEOUT_MS;
    ctx.key_prefix = ngx_auth_webauthn_admin_default_prefix;

    /* Dispatch: hand the subcommand its own argv (argv[0] == command name) so
     * its getopt_long scan starts cleanly at the first option. */
    if (strcmp(cmd, "register") == 0) {
        rc = auth_webauthn_admin_cmd_register(&ctx, argc - 1, argv + 1);

    } else if (strcmp(cmd, "revoke") == 0) {
        rc = auth_webauthn_admin_cmd_revoke(&ctx, argc - 1, argv + 1);

    } else if (strcmp(cmd, "list") == 0) {
        rc = auth_webauthn_admin_cmd_list(&ctx, argc - 1, argv + 1);

    } else if (strcmp(cmd, "show") == 0) {
        rc = auth_webauthn_admin_cmd_show(&ctx, argc - 1, argv + 1);

    } else {
        fprintf(stderr, "error: unknown command '%s'\n\n", cmd);
        ngx_auth_webauthn_admin_usage(stderr);
        rc = AUTH_WEBAUTHN_ADMIN_EX_USAGE;
    }

    ngx_destroy_pool(pool);

    return rc;
}
