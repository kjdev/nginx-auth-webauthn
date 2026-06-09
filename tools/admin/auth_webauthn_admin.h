/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * auth_webauthn_admin.h - shared surface for the auth-webauthn-admin CLI.
 *
 * The CLI registers / revokes / lists / shows WebAuthn credentials in Redis.
 * It links the registration-path subset of the shared src/ngx_auth_webauthn_*
 * layer through the ngx_compat shim (no nginx runtime).  This header carries
 * the connection context the subcommands share and the few helpers they reuse
 * (Redis connect, common-option parsing, COSE alg display names).
 */

#ifndef AUTH_WEBAUTHN_ADMIN_H
#define AUTH_WEBAUTHN_ADMIN_H

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_redis.h"

#define AUTH_WEBAUTHN_ADMIN_VERSION  "0.1.0"

/* Default Redis command/connect timeout when --redis-timeout is absent. */
#define AUTH_WEBAUTHN_ADMIN_TIMEOUT_MS  100

/* Process exit codes (BSD-style sysexits subset). */
#define AUTH_WEBAUTHN_ADMIN_EX_OK     0
#define AUTH_WEBAUTHN_ADMIN_EX_FAIL   1  /* runtime error (Redis, parse, ...) */
#define AUTH_WEBAUTHN_ADMIN_EX_USAGE  2  /* bad invocation / missing option */


/*
 * Connection + global settings, filled from the common options and shared by
 * every subcommand.  pool owns all allocations; log writes to stderr.
 */
typedef struct {
    ngx_pool_t *pool;
    ngx_log_t  *log;

    ngx_str_t   redis_host;
    int         redis_port;
    ngx_str_t   redis_password;   /* len 0 skips AUTH */
    ngx_uint_t  redis_db;
    ngx_uint_t  redis_timeout_ms;

    ngx_str_t   key_prefix;       /* default "webauthn:" */
} auth_webauthn_admin_ctx_t;


/*
 * Common long options shared by all subcommands.  Subcommands splice these
 * into their own getopt_long table starting at this value so their private
 * options keep distinct codes.
 */
enum {
    AUTH_WEBAUTHN_ADMIN_OPT_REDIS = 0x100,
    AUTH_WEBAUTHN_ADMIN_OPT_REDIS_PASSWORD,
    AUTH_WEBAUTHN_ADMIN_OPT_REDIS_DB,
    AUTH_WEBAUTHN_ADMIN_OPT_REDIS_TIMEOUT,
    AUTH_WEBAUTHN_ADMIN_OPT_KEY_PREFIX,
    AUTH_WEBAUTHN_ADMIN_OPT_SUBCOMMAND_BASE  /* subcommand options start here */
};


/* Subcommand entry points (return an AUTH_WEBAUTHN_ADMIN_EX_* code). */
int auth_webauthn_admin_cmd_register(auth_webauthn_admin_ctx_t *ctx,
    int argc, char **argv);
int auth_webauthn_admin_cmd_revoke(auth_webauthn_admin_ctx_t *ctx,
    int argc, char **argv);
int auth_webauthn_admin_cmd_list(auth_webauthn_admin_ctx_t *ctx,
    int argc, char **argv);
int auth_webauthn_admin_cmd_show(auth_webauthn_admin_ctx_t *ctx,
    int argc, char **argv);


/*
 * Interpret one common long option (the AUTH_WEBAUTHN_ADMIN_OPT_* values).
 * Returns NGX_OK when opt was a recognised common option (ctx updated),
 * NGX_DECLINED when opt is not a common option (the caller handles it),
 * NGX_ERROR on a malformed value (a message is printed to stderr).
 */
ngx_int_t auth_webauthn_admin_parse_common_opt(auth_webauthn_admin_ctx_t *ctx,
    int opt, const char *arg);

/*
 * Open the Redis connection described by ctx.  *out owns the handle, which the
 * caller closes with ngx_auth_webauthn_redis_close.  Returns NGX_OK, or
 * NGX_ERROR after printing a diagnostic (missing --redis, connect failure).
 */
ngx_int_t auth_webauthn_admin_connect(auth_webauthn_admin_ctx_t *ctx,
    ngx_auth_webauthn_redis_t **out);

/* COSE alg id -> display name ("ES256" / "EdDSA" / "RS256" / "unknown"). */
const char *auth_webauthn_admin_alg_name(int alg);

/*
 * Format a unix timestamp as ISO 8601 UTC ("2026-04-17T10:00:00Z") into buf
 * (at least 21 bytes).  A non-positive t yields "-".  Returns buf.
 */
const char *auth_webauthn_admin_fmt_time(int64_t t, char *buf, size_t size);

/*
 * Read an entire file (or stdin when path is "-") into a pool buffer.  out is
 * NUL-terminated for convenience; out->len excludes the terminator.  Returns
 * NGX_OK, or NGX_ERROR after printing a diagnostic to stderr.
 */
ngx_int_t auth_webauthn_admin_read_file(ngx_pool_t *pool, const char *path,
    ngx_str_t *out);

#endif /* AUTH_WEBAUTHN_ADMIN_H */
