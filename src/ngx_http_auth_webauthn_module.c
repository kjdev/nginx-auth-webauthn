/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_webauthn_assertion.h"
#include "ngx_auth_webauthn_credential.h"
#include "ngx_auth_webauthn_redis.h"
#include "ngx_auth_webauthn_challenge.h"

#include <nxe_json.h>
#include <nxe_jwx.h>

#include <openssl/rand.h>
#include <openssl/pem.h>


#define NGX_AUTH_WEBAUTHN_JTI_LEN  16  /* random bytes for the JWT jti */

/* Bound the POST body the verify handler will buffer (a PublicKeyCredential
 * JSON; far smaller in practice). */
#define NGX_AUTH_WEBAUTHN_MAX_BODY  (64 * 1024)

/* jwt_alg families: HMAC keys verify with a raw secret, asymmetric keys with
 * a derived public PEM. */
#define NGX_AUTH_WEBAUTHN_JWT_HMAC  0
#define NGX_AUTH_WEBAUTHN_JWT_ASYM  1

/* userVerification policy: the value is both advertised in the challenge JSON
 * and, for "required", enforced on the asserted UV flag during verify. */
#define NGX_AUTH_WEBAUTHN_UV_REQUIRED    0
#define NGX_AUTH_WEBAUTHN_UV_PREFERRED   1
#define NGX_AUTH_WEBAUTHN_UV_DISCOURAGED 2


typedef struct {
    ngx_str_t                 name;
    ngx_http_complex_value_t  value;
} ngx_http_auth_webauthn_header_t;


typedef struct {
    ngx_str_t    rp_id;
    ngx_str_t    rp_name;
    ngx_array_t *origins;              /* ngx_str_t */
    time_t       challenge_ttl;        /* seconds */
    ngx_uint_t   user_verification;    /* NGX_AUTH_WEBAUTHN_UV_* */
    ngx_uint_t   rate_limit_max;       /* 0 disables challenge rate limiting */
    time_t       rate_limit_window;    /* seconds; the INCR counter's TTL */

    ngx_str_t    redis_url;            /* "<host>:<port>", for messages */
    ngx_str_t    redis_host;
    ngx_int_t    redis_port;
    ngx_str_t    redis_password;
    ngx_uint_t   redis_db;
    ngx_msec_t   redis_timeout;
    ngx_str_t    redis_key_prefix;

    ngx_str_t    jwt_secret_file;
    ngx_str_t    jwt_secret;           /* HMAC secret, or PEM private key */
    ngx_str_t    jwt_pub_pem;          /* derived public PEM (asym verify) */
    ngx_str_t    jwt_alg;              /* "HS256" / "RS256" / "ES256" */
    ngx_uint_t   jwt_alg_family;
    time_t       jwt_ttl;              /* seconds */
    ngx_str_t    cookie_name;
    ngx_str_t    cookie_domain;
    ngx_str_t    cookie_path;
    ngx_flag_t   cookie_secure;
    ngx_uint_t   cookie_samesite;      /* index into samesite names */

    ngx_uint_t   clone_detection;      /* NGX_AUTH_WEBAUTHN_CLONE_* */

    ngx_flag_t   auth;
    ngx_str_t    signin_url;
    ngx_array_t *set_headers;          /* ngx_http_auth_webauthn_header_t */
    ngx_flag_t   challenge_handler;
    ngx_flag_t   verify_handler;
} ngx_http_auth_webauthn_loc_conf_t;


typedef struct {
    ngx_str_t   user_id;
    ngx_str_t   credential_id;
    ngx_str_t   auth_status;           /* static literal */
    time_t      jwt_exp;
    ngx_uint_t  has_exp;
} ngx_http_auth_webauthn_ctx_t;


extern ngx_module_t ngx_http_auth_webauthn_module;


/* lifecycle */
static ngx_int_t ngx_http_auth_webauthn_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_webauthn_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_auth_webauthn_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_webauthn_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/* phase / content handlers */
static ngx_int_t ngx_http_auth_webauthn_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_webauthn_challenge_content(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_webauthn_verify_content(ngx_http_request_t *r);

/* directive parsers */
static char *ngx_http_auth_webauthn_conf_set_origin(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_set_header(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_redis(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_redis_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_jwt_alg(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_rate_limit(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_challenge_handler(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_webauthn_conf_set_verify_handler(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* variable handler */
static ngx_int_t ngx_http_auth_webauthn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_conf_enum_t ngx_http_auth_webauthn_clone_enum[] = {
    { ngx_string("strict"), NGX_AUTH_WEBAUTHN_CLONE_STRICT },
    { ngx_string("lax"),    NGX_AUTH_WEBAUTHN_CLONE_LAX },
    { ngx_string("off"),    NGX_AUTH_WEBAUTHN_CLONE_OFF },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t ngx_http_auth_webauthn_samesite_enum[] = {
    { ngx_string("strict"), 0 },
    { ngx_string("lax"),    1 },
    { ngx_string("none"),   2 },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t ngx_http_auth_webauthn_uv_enum[] = {
    { ngx_string("required"),    NGX_AUTH_WEBAUTHN_UV_REQUIRED },
    { ngx_string("preferred"),   NGX_AUTH_WEBAUTHN_UV_PREFERRED },
    { ngx_string("discouraged"), NGX_AUTH_WEBAUTHN_UV_DISCOURAGED },
    { ngx_null_string, 0 }
};

static const char *ngx_http_auth_webauthn_samesite_name[] = {
    "Strict", "Lax", "None"
};


static ngx_command_t ngx_http_auth_webauthn_commands[] = {

    { ngx_string("auth_webauthn_rp_id"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, rp_id),
      NULL },

    { ngx_string("auth_webauthn_rp_name"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, rp_name),
      NULL },

    { ngx_string("auth_webauthn_origin"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_1MORE,
      ngx_http_auth_webauthn_conf_set_origin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_challenge_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, challenge_ttl),
      NULL },

    { ngx_string("auth_webauthn_user_verification"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, user_verification),
      ngx_http_auth_webauthn_uv_enum },

    { ngx_string("auth_webauthn_challenge_rate_limit"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE12,
      ngx_http_auth_webauthn_conf_set_rate_limit,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_redis"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_webauthn_conf_set_redis,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_redis_password"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_webauthn_conf_set_redis_password,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_redis_db"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, redis_db),
      NULL },

    { ngx_string("auth_webauthn_redis_timeout"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, redis_timeout),
      NULL },

    { ngx_string("auth_webauthn_redis_key_prefix"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, redis_key_prefix),
      NULL },

    { ngx_string("auth_webauthn_jwt_secret_file"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, jwt_secret_file),
      NULL },

    { ngx_string("auth_webauthn_jwt_alg"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_http_auth_webauthn_conf_set_jwt_alg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_jwt_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, jwt_ttl),
      NULL },

    { ngx_string("auth_webauthn_jwt_cookie_name"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, cookie_name),
      NULL },

    { ngx_string("auth_webauthn_jwt_cookie_domain"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, cookie_domain),
      NULL },

    { ngx_string("auth_webauthn_jwt_cookie_path"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, cookie_path),
      NULL },

    { ngx_string("auth_webauthn_jwt_cookie_secure"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, cookie_secure),
      NULL },

    { ngx_string("auth_webauthn_jwt_cookie_samesite"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, cookie_samesite),
      ngx_http_auth_webauthn_samesite_enum },

    { ngx_string("auth_webauthn_clone_detection"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
      NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, clone_detection),
      ngx_http_auth_webauthn_clone_enum },

    { ngx_string("auth_webauthn"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, auth),
      NULL },

    { ngx_string("auth_webauthn_signin_url"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, signin_url),
      NULL },

    { ngx_string("auth_webauthn_set_header"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
      ngx_http_auth_webauthn_conf_set_set_header,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_webauthn_challenge_handler"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_auth_webauthn_conf_set_challenge_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, challenge_handler),
      NULL },

    { ngx_string("auth_webauthn_verify_handler"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_auth_webauthn_conf_set_verify_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_webauthn_loc_conf_t, verify_handler),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_auth_webauthn_module_ctx = {
    ngx_http_auth_webauthn_preconfiguration,   /* preconfiguration */
    ngx_http_auth_webauthn_postconfiguration,  /* postconfiguration */
    NULL,                                      /* create main conf */
    NULL,                                      /* init main conf */
    NULL,                                      /* create srv conf */
    NULL,                                      /* merge srv conf */
    ngx_http_auth_webauthn_create_loc_conf,    /* create loc conf */
    ngx_http_auth_webauthn_merge_loc_conf      /* merge loc conf */
};


ngx_module_t ngx_http_auth_webauthn_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_webauthn_module_ctx,
    ngx_http_auth_webauthn_commands,
    NGX_HTTP_MODULE,
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* === NGINX variables === */

static ngx_http_variable_t ngx_http_auth_webauthn_vars[] = {
    { ngx_string("webauthn_user_id"), NULL,
      ngx_http_auth_webauthn_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("webauthn_credential_id"), NULL,
      ngx_http_auth_webauthn_variable, 1, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("webauthn_auth_status"), NULL,
      ngx_http_auth_webauthn_variable, 2, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("webauthn_jwt_exp"), NULL,
      ngx_http_auth_webauthn_variable, 3, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_auth_webauthn_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_webauthn_ctx_t *ctx;
    ngx_str_t value;
    u_char *p;

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_webauthn_module);

    if (ctx == NULL) {
        if (data == 2) {
            ngx_str_set(&value, "unauthenticated");
            goto found_static;
        }
        v->not_found = 1;
        return NGX_OK;
    }

    switch (data) {
    case 0:
        value = ctx->user_id;
        break;
    case 1:
        value = ctx->credential_id;
        break;
    case 2:
        value = ctx->auth_status;
        break;
    case 3:
        if (!ctx->has_exp) {
            v->not_found = 1;
            return NGX_OK;
        }
        p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }
        value.data = p;
        value.len = ngx_sprintf(p, "%T", ctx->jwt_exp) - p;
        break;
    default:
        v->not_found = 1;
        return NGX_OK;
    }

    if (value.len == 0 || value.data == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

found_static:

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = value.len;
    v->data = value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_webauthn_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_auth_webauthn_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_webauthn_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_auth_webauthn_access_handler;

    return NGX_OK;
}


static void *
ngx_http_auth_webauthn_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_webauthn_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_webauthn_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * ngx_pcalloc zeroes str/ptr fields; the rest are set to UNSET so
     * merge can apply defaults or inherit a parent value.
     */
    conf->origins = NGX_CONF_UNSET_PTR;
    conf->challenge_ttl = NGX_CONF_UNSET;
    conf->user_verification = NGX_CONF_UNSET_UINT;
    conf->rate_limit_max = NGX_CONF_UNSET_UINT;
    conf->rate_limit_window = NGX_CONF_UNSET;
    conf->redis_port = NGX_CONF_UNSET;
    conf->redis_db = NGX_CONF_UNSET_UINT;
    conf->redis_timeout = NGX_CONF_UNSET_MSEC;
    conf->jwt_alg_family = NGX_CONF_UNSET_UINT;
    conf->jwt_ttl = NGX_CONF_UNSET;
    conf->cookie_secure = NGX_CONF_UNSET;
    conf->cookie_samesite = NGX_CONF_UNSET_UINT;
    conf->clone_detection = NGX_CONF_UNSET_UINT;
    conf->auth = NGX_CONF_UNSET;
    conf->set_headers = NGX_CONF_UNSET_PTR;
    conf->challenge_handler = NGX_CONF_UNSET;
    conf->verify_handler = NGX_CONF_UNSET;

    return conf;
}


/* Read a whole file into out (pool-allocated). */
static ngx_int_t
ngx_http_auth_webauthn_read_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *out)
{
    ngx_file_t file;
    ngx_file_info_t fi;
    ssize_t n;
    ngx_str_t full;

    full = *path;
    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = full;
    file.log = cf->log;

    file.fd = ngx_open_file(full.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "auth_webauthn: cannot open \"%V\"", &full);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    out->len = (size_t) ngx_file_size(&fi);
    out->data = ngx_pnalloc(cf->pool, out->len);
    if (out->data == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, out->data, out->len, 0);
    ngx_close_file(file.fd);

    if (n == NGX_ERROR || (size_t) n != out->len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_webauthn: cannot read \"%V\"", &full);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Strip a single trailing newline (HMAC secrets stored as a text line). */
static void
ngx_http_auth_webauthn_chomp(ngx_str_t *s)
{
    while (s->len > 0
           && (s->data[s->len - 1] == '\n' || s->data[s->len - 1] == '\r'))
    {
        s->len--;
    }
}


/* Derive a public-key PEM from a PEM private key (asymmetric jwt verify). */
static ngx_int_t
ngx_http_auth_webauthn_derive_pub_pem(ngx_conf_t *cf, ngx_str_t *priv,
    ngx_str_t *out)
{
    BIO *in, *mem;
    EVP_PKEY *pkey;
    BUF_MEM *bptr;
    ngx_int_t rc = NGX_ERROR;

    in = BIO_new_mem_buf(priv->data, (int) priv->len);
    if (in == NULL) {
        return NGX_ERROR;
    }
    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (pkey == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auth_webauthn: jwt_secret_file is not a PEM "
                           "private key");
        return NGX_ERROR;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }
    if (PEM_write_bio_PUBKEY(mem, pkey) == 1) {
        BIO_get_mem_ptr(mem, &bptr);
        out->data = ngx_pnalloc(cf->pool, bptr->length);
        if (out->data != NULL) {
            ngx_memcpy(out->data, bptr->data, bptr->length);
            out->len = bptr->length;
            rc = NGX_OK;
        }
    }

    BIO_free(mem);
    EVP_PKEY_free(pkey);
    return rc;
}


static char *
ngx_http_auth_webauthn_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_webauthn_loc_conf_t *prev = parent;
    ngx_http_auth_webauthn_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->rp_id, prev->rp_id, "");
    ngx_conf_merge_str_value(conf->rp_name, prev->rp_name, "");
    ngx_conf_merge_ptr_value(conf->origins, prev->origins, NULL);
    ngx_conf_merge_sec_value(conf->challenge_ttl, prev->challenge_ttl, 60);
    ngx_conf_merge_uint_value(conf->user_verification, prev->user_verification,
                              NGX_AUTH_WEBAUTHN_UV_PREFERRED);
    ngx_conf_merge_uint_value(conf->rate_limit_max, prev->rate_limit_max, 0);
    ngx_conf_merge_sec_value(conf->rate_limit_window, prev->rate_limit_window,
                             60);

    ngx_conf_merge_str_value(conf->redis_url, prev->redis_url, "");
    ngx_conf_merge_str_value(conf->redis_host, prev->redis_host, "");
    ngx_conf_merge_value(conf->redis_port, prev->redis_port, 0);
    ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
    ngx_conf_merge_uint_value(conf->redis_db, prev->redis_db, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 100);
    ngx_conf_merge_str_value(conf->redis_key_prefix, prev->redis_key_prefix,
                             "webauthn:");

    ngx_conf_merge_str_value(conf->jwt_secret_file, prev->jwt_secret_file, "");
    ngx_conf_merge_str_value(conf->jwt_secret, prev->jwt_secret, "");
    ngx_conf_merge_str_value(conf->jwt_pub_pem, prev->jwt_pub_pem, "");
    ngx_conf_merge_str_value(conf->jwt_alg, prev->jwt_alg, "HS256");
    ngx_conf_merge_uint_value(conf->jwt_alg_family, prev->jwt_alg_family,
                              NGX_AUTH_WEBAUTHN_JWT_HMAC);
    ngx_conf_merge_sec_value(conf->jwt_ttl, prev->jwt_ttl, 3600);
    ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name,
                             "webauthn_session");
    ngx_conf_merge_str_value(conf->cookie_domain, prev->cookie_domain, "");
    ngx_conf_merge_str_value(conf->cookie_path, prev->cookie_path, "/");
    ngx_conf_merge_value(conf->cookie_secure, prev->cookie_secure, 1);
    ngx_conf_merge_uint_value(conf->cookie_samesite, prev->cookie_samesite, 0);

    ngx_conf_merge_uint_value(conf->clone_detection, prev->clone_detection,
                              NGX_AUTH_WEBAUTHN_CLONE_STRICT);

    ngx_conf_merge_value(conf->auth, prev->auth, 0);
    ngx_conf_merge_str_value(conf->signin_url, prev->signin_url, "");
    ngx_conf_merge_ptr_value(conf->set_headers, prev->set_headers, NULL);
    ngx_conf_merge_value(conf->challenge_handler, prev->challenge_handler, 0);
    ngx_conf_merge_value(conf->verify_handler, prev->verify_handler, 0);

    /*
     * Load the JWT key once a location actually mints (verify) or checks
     * (auth) session tokens.  Inherited locations reuse the parent's
     * already-loaded ngx_str_t through the merge above, so the file is read
     * once per distinct setting.
     */
    if ((conf->auth || conf->verify_handler)
        && conf->jwt_secret.len == 0
        && conf->jwt_secret_file.len > 0)
    {
        if (ngx_http_auth_webauthn_read_file(cf, &conf->jwt_secret_file,
                                             &conf->jwt_secret) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (conf->jwt_alg_family == NGX_AUTH_WEBAUTHN_JWT_HMAC) {
            ngx_http_auth_webauthn_chomp(&conf->jwt_secret);
            if (conf->jwt_secret.len < 32) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "auth_webauthn: HMAC jwt secret must be at "
                                   "least 32 bytes");
                return NGX_CONF_ERROR;
            }
        } else {
            if (ngx_http_auth_webauthn_derive_pub_pem(cf, &conf->jwt_secret,
                                                      &conf->jwt_pub_pem)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    return NGX_CONF_OK;
}


/* === directive parsers === */

static char *
ngx_http_auth_webauthn_conf_set_origin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value, *origin;
    ngx_uint_t i;

    if (wlcf->origins == NGX_CONF_UNSET_PTR) {
        wlcf->origins = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (wlcf->origins == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        origin = ngx_array_push(wlcf->origins);
        if (origin == NULL) {
            return NGX_CONF_ERROR;
        }
        *origin = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_set_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value;
    ngx_http_auth_webauthn_header_t *hdr;
    ngx_http_compile_complex_value_t ccv;

    if (wlcf->set_headers == NGX_CONF_UNSET_PTR) {
        wlcf->set_headers = ngx_array_create(cf->pool, 4,
                                             sizeof(
                                                 ngx_http_auth_webauthn_header_t));
        if (wlcf->set_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    hdr = ngx_array_push(wlcf->set_headers);
    if (hdr == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(hdr, sizeof(ngx_http_auth_webauthn_header_t));
    hdr->name = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &hdr->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_redis(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value;
    u_char *colon;
    ngx_int_t port;

    value = cf->args->elts;

    if (wlcf->redis_host.len) {
        return "is duplicate";
    }

    wlcf->redis_url = value[1];

    colon = (u_char *) ngx_strlchr(value[1].data,
                                   value[1].data + value[1].len, ':');
    if (colon == NULL || colon == value[1].data
        || colon == value[1].data + value[1].len - 1)
    {
        return "expects <host>:<port>";
    }

    wlcf->redis_host.data = value[1].data;
    wlcf->redis_host.len = (size_t) (colon - value[1].data);

    port = ngx_atoi(colon + 1,
                    value[1].len - (size_t) (colon + 1 - value[1].data));
    if (port == NGX_ERROR || port <= 0 || port > 65535) {
        return "has an invalid port";
    }
    wlcf->redis_port = port;

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_redis_password(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value, path;

    value = cf->args->elts;

    if (ngx_strncmp(value[1].data, "file:", 5) == 0) {
        path.data = value[1].data + 5;
        path.len = value[1].len - 5;
        if (ngx_http_auth_webauthn_read_file(cf, &path, &wlcf->redis_password)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
        ngx_http_auth_webauthn_chomp(&wlcf->redis_password);
    } else {
        wlcf->redis_password = value[1];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_jwt_alg(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "HS256") == 0) {
        wlcf->jwt_alg_family = NGX_AUTH_WEBAUTHN_JWT_HMAC;
    } else if (ngx_strcmp(value[1].data, "RS256") == 0
               || ngx_strcmp(value[1].data, "ES256") == 0)
    {
        wlcf->jwt_alg_family = NGX_AUTH_WEBAUTHN_JWT_ASYM;
    } else {
        return "must be one of HS256, RS256, ES256";
    }

    wlcf->jwt_alg = value[1];

    return NGX_CONF_OK;
}


/*
 * auth_webauthn_challenge_rate_limit off | <max> [<window>]
 *
 * "off" (or max 0) disables limiting.  Otherwise <max> challenge issues are
 * allowed per <window> (a time value, default 60s) per client IP.
 */
static char *
ngx_http_auth_webauthn_conf_set_rate_limit(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_int_t max;
    time_t window;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        wlcf->rate_limit_max = 0;
        return NGX_CONF_OK;
    }

    max = ngx_atoi(value[1].data, value[1].len);
    if (max == NGX_ERROR || max <= 0) {
        return "expects \"off\" or a positive <max> count";
    }
    wlcf->rate_limit_max = (ngx_uint_t) max;

    if (cf->args->nelts == 3) {
        window = ngx_parse_time(&value[2], 1);
        if (window == (time_t) NGX_ERROR || window <= 0) {
            return "has an invalid <window>";
        }
        wlcf->rate_limit_window = window;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_challenge_handler(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (wlcf->challenge_handler) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_auth_webauthn_challenge_content;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_webauthn_conf_set_verify_handler(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf = conf;
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (wlcf->verify_handler) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_auth_webauthn_verify_content;
    }

    return NGX_CONF_OK;
}


/* === small response helpers === */

static ngx_int_t
ngx_http_auth_webauthn_send_json(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body)
{
    ngx_buf_t *b;
    ngx_chain_t out;

    r->headers_out.status = status;
    r->headers_out.content_length_n = body->len;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    b = ngx_create_temp_buf(r->pool, body->len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, body->data, body->len);
    b->last = b->pos + body->len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;

    {
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    return ngx_http_output_filter(r, &out);
}


/* JSON-escape a string value (handles ", \, and control bytes incl. \n). */
static ngx_str_t
ngx_http_auth_webauthn_json_escape(ngx_pool_t *pool, ngx_str_t *src)
{
    static u_char hex[] = "0123456789abcdef";
    ngx_str_t out = { 0, NULL };
    u_char *p;
    size_t i;

    p = ngx_pnalloc(pool, src->len * 6);
    if (p == NULL) {
        return out;
    }
    out.data = p;

    for (i = 0; i < src->len; i++) {
        u_char c = src->data[i];

        switch (c) {
        case '"':  *p++ = '\\'; *p++ = '"';  break;
        case '\\': *p++ = '\\'; *p++ = '\\'; break;
        case '\n': *p++ = '\\'; *p++ = 'n';  break;
        case '\r': *p++ = '\\'; *p++ = 'r';  break;
        case '\t': *p++ = '\\'; *p++ = 't';  break;
        default:
            if (c < 0x20) {
                *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                *p++ = hex[(c >> 4) & 0xf];
                *p++ = hex[c & 0xf];
            } else {
                *p++ = c;
            }
        }
    }

    out.len = (size_t) (p - out.data);
    return out;
}


/* base64url-encode src into a pool-allocated string. */
static ngx_int_t
ngx_http_auth_webauthn_b64url(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(pool, ngx_base64_encoded_length(src->len));
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64url(dst, src);
    return NGX_OK;
}


/* === challenge content handler === */

/* userVerification policy values, indexed by NGX_AUTH_WEBAUTHN_UV_*. */
static ngx_str_t ngx_http_auth_webauthn_uv_names[] = {
    ngx_string("required"),
    ngx_string("preferred"),
    ngx_string("discouraged"),
};

/* JSON overhead per allowCredentials entry: {"type":"public-key","id":""}, */
#define NGX_AUTH_WEBAUTHN_ALLOWCRED_OVERHEAD  32


/*
 * Per-client-IP rate limit for challenge issuance, backed by a Redis INCR
 * counter with a per-window TTL.  Returns NGX_OK when within the quota (or
 * when the counter could not be evaluated: fail-open, since challenge issuance
 * already depends on the same Redis), NGX_DECLINED when the quota is exceeded.
 *
 * Every request reaching this point is counted, including ones later rejected
 * at the quota or that go on to fail challenge issuance: this is a deliberate
 * fixed-window design.  The TTL is set only on the first hit of a window (see
 * ngx_auth_webauthn_redis_incr_expire), so repeated requests never extend the
 * lockout -- the window always expires `rate_limit_window` seconds after the
 * first request.  Counting rejected/failed requests therefore inflates only
 * the counter integer, never the lockout duration, while keeping the counter
 * a single atomic INCR with no check-then-act race.
 */
static ngx_int_t
ngx_http_auth_webauthn_rate_limit(ngx_http_request_t *r,
    ngx_auth_webauthn_redis_t *redis,
    ngx_http_auth_webauthn_loc_conf_t *wlcf)
{
    ngx_str_t key, ip;
    ngx_int_t count;
    u_char *p;

    if (wlcf->rate_limit_max == 0) {
        return NGX_OK;
    }

    ip = r->connection->addr_text;

    /* {prefix}ratelimit:challenge:{ip} */
    key.len = wlcf->redis_key_prefix.len
              + (sizeof("ratelimit:challenge:") - 1) + ip.len;
    key.data = ngx_pnalloc(r->pool, key.len);
    if (key.data == NULL) {
        return NGX_OK;   /* fail-open */
    }
    p = ngx_cpymem(key.data, wlcf->redis_key_prefix.data,
                   wlcf->redis_key_prefix.len);
    p = ngx_cpymem(p, "ratelimit:challenge:",
                   sizeof("ratelimit:challenge:") - 1);
    ngx_memcpy(p, ip.data, ip.len);

    if (ngx_auth_webauthn_redis_incr_expire(redis, &key,
                                            (ngx_uint_t) wlcf->rate_limit_window,
                                            &count) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "auth_webauthn: rate-limit counter unavailable, "
                      "allowing challenge");
        return NGX_OK;   /* fail-open */
    }

    if ((ngx_uint_t) count > wlcf->rate_limit_max) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_webauthn_challenge_content(ngx_http_request_t *r)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf;
    ngx_auth_webauthn_redis_t *redis = NULL;
    ngx_auth_webauthn_redis_conf_t rconf;
    u_char challenge[NGX_AUTH_WEBAUTHN_CHALLENGE_LEN];
    ngx_str_t raw, b64, body, uid, index_key, *creds, *uv;
    ngx_uint_t ncreds = 0, i;
    ngx_int_t rc;
    size_t size, sum = 0;
    u_char *p;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_webauthn_module);

    if (wlcf->rp_id.len == 0 || wlcf->redis_host.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_webauthn: challenge handler needs "
                      "auth_webauthn_rp_id and auth_webauthn_redis");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memzero(&rconf, sizeof(rconf));
    rconf.host = wlcf->redis_host;
    rconf.port = (int) wlcf->redis_port;
    rconf.password = wlcf->redis_password;
    rconf.db = wlcf->redis_db;
    rconf.timeout_ms = wlcf->redis_timeout;

    if (ngx_auth_webauthn_redis_connect(r->pool, r->connection->log, &rconf,
                                        &redis) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_auth_webauthn_rate_limit(r, redis, wlcf) == NGX_DECLINED) {
        ngx_auth_webauthn_redis_close(redis);
        return NGX_HTTP_TOO_MANY_REQUESTS;
    }

    rc = ngx_auth_webauthn_challenge_issue(redis, r->pool,
                                           &wlcf->redis_key_prefix,
                                           wlcf->challenge_ttl, challenge);
    if (rc != NGX_OK) {
        ngx_auth_webauthn_redis_close(redis);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * allowCredentials: when a user_id query arg resolves to registered
     * credentials, list their (base64url) ids so non-discoverable
     * authenticators can be selected.  An absent, unknown, or empty user_id
     * all yield [] -- the endpoint never reveals whether a user exists.
     */
    if (ngx_http_arg(r, (u_char *) "user_id", 7, &uid) == NGX_OK
        && uid.len > 0)
    {
        index_key.len = wlcf->redis_key_prefix.len
                        + (sizeof("user:") - 1) + uid.len
                        + (sizeof(":creds") - 1);
        index_key.data = ngx_pnalloc(r->pool, index_key.len);
        if (index_key.data == NULL) {
            ngx_auth_webauthn_redis_close(redis);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        p = ngx_cpymem(index_key.data, wlcf->redis_key_prefix.data,
                       wlcf->redis_key_prefix.len);
        p = ngx_cpymem(p, "user:", sizeof("user:") - 1);
        p = ngx_cpymem(p, uid.data, uid.len);
        ngx_memcpy(p, ":creds", sizeof(":creds") - 1);

        if (ngx_auth_webauthn_redis_smembers(redis, r->pool, &index_key,
                                             &creds, &ncreds) != NGX_OK)
        {
            ngx_auth_webauthn_redis_close(redis);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_auth_webauthn_redis_close(redis);

    raw.data = challenge;
    raw.len = NGX_AUTH_WEBAUTHN_CHALLENGE_LEN;
    if (ngx_http_auth_webauthn_b64url(r->pool, &raw, &b64) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < ncreds; i++) {
        sum += creds[i].len;
    }

    uv = &ngx_http_auth_webauthn_uv_names[wlcf->user_verification];

    size = 160 + b64.len + wlcf->rp_id.len + uv->len
           + ncreds * NGX_AUTH_WEBAUTHN_ALLOWCRED_OVERHEAD + sum;
    body.data = ngx_pnalloc(r->pool, size);
    if (body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_sprintf(body.data,
                    "{\"challenge\":\"%V\",\"rpId\":\"%V\",\"timeout\":%T,"
                    "\"userVerification\":\"%V\",\"allowCredentials\":[",
                    &b64, &wlcf->rp_id, (time_t) (wlcf->challenge_ttl * 1000),
                    uv);
    for (i = 0; i < ncreds; i++) {
        p = ngx_sprintf(p, "%s{\"type\":\"public-key\",\"id\":\"%V\"}",
                        i == 0 ? "" : ",", &creds[i]);
    }
    *p++ = ']';
    *p++ = '}';
    body.len = (size_t) (p - body.data);

    return ngx_http_auth_webauthn_send_json(r, NGX_HTTP_OK, &body);
}


/* === verify content handler === */

static ngx_int_t
ngx_http_auth_webauthn_verify_fail(ngx_http_request_t *r)
{
    ngx_str_t body = ngx_string("{\"ok\":false,\"error\":\"E_ASSERTION\"}");

    return ngx_http_auth_webauthn_send_json(r, NGX_HTTP_UNAUTHORIZED, &body);
}


/* Concatenate the buffered request body into one contiguous ngx_str_t. */
static ngx_int_t
ngx_http_auth_webauthn_read_body(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_chain_t *cl;
    size_t len = 0;
    u_char *p;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_ERROR;
    }

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        len += (size_t) (cl->buf->last - cl->buf->pos);
        if (cl->buf->in_file) {
            return NGX_ERROR;   /* body spilled to disk: raise the buffer size */
        }
    }

    if (len == 0 || len > NGX_AUTH_WEBAUTHN_MAX_BODY) {
        return NGX_ERROR;
    }

    out->data = ngx_pnalloc(r->pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    p = out->data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_cpymem(p, cl->buf->pos,
                       (size_t) (cl->buf->last - cl->buf->pos));
    }
    out->len = len;

    return NGX_OK;
}


/* Pull a string field, base64url-decode it into a pool buffer. */
static ngx_int_t
ngx_http_auth_webauthn_b64url_field(ngx_pool_t *pool, nxe_json_t *obj,
    const char *name, ngx_str_t *out)
{
    ngx_str_t enc, src;

    if (nxe_json_object_get_string(obj, name, &enc, pool) != NGX_OK
        || enc.len == 0)
    {
        return NGX_ERROR;
    }

    out->data = ngx_pnalloc(pool, ngx_base64_decoded_length(enc.len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    src.data = enc.data;
    src.len = enc.len;
    if (ngx_decode_base64url(out, &src) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * The body post-handler: runs the full 13-step verification, mints a JWT on
 * success, and finalizes the request.  Failures collapse to a uniform 401.
 */
static void
ngx_http_auth_webauthn_verify_done(ngx_http_request_t *r)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf;
    ngx_auth_webauthn_redis_t *redis = NULL;
    ngx_auth_webauthn_redis_conf_t rconf;
    ngx_auth_webauthn_credential_t cred;
    ngx_auth_webauthn_assertion_t assertion;
    ngx_auth_webauthn_assertion_cred_t acred;
    ngx_auth_webauthn_assertion_policy_t policy;
    ngx_auth_webauthn_assertion_result_t result;
    nxe_json_t *root = NULL, *response;
    ngx_str_t body, id, challenge_b64, challenge_raw, src;
    ngx_str_t claims, jwt, sub_esc, cookie;
    ngx_str_t alg, jti_raw, jti_b64;
    u_char jti[NGX_AUTH_WEBAUTHN_JTI_LEN];
    ngx_int_t rc;
    time_t now;
    u_char *p;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_webauthn_module);

    if (wlcf->rp_id.len == 0
        || wlcf->redis_host.len == 0 || wlcf->jwt_secret.len == 0
        || wlcf->origins == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_webauthn: verify handler is missing required "
                      "directives");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_auth_webauthn_read_body(r, &body) != NGX_OK) {
        ngx_http_finalize_request(r, ngx_http_auth_webauthn_verify_fail(r));
        return;
    }

    root = nxe_json_parse_untrusted(&body, r->pool);
    if (root == NULL || !nxe_json_is_object(root)) {
        goto reject;
    }

    /* id is the base64url credential id == the Redis key suffix. */
    if (nxe_json_object_get_string(root, "id", &id, r->pool) != NGX_OK
        || id.len == 0)
    {
        goto reject;
    }

    response = nxe_json_object_get(root, "response");
    if (response == NULL || !nxe_json_is_object(response)) {
        goto reject;
    }

    ngx_memzero(&assertion, sizeof(assertion));
    if (ngx_http_auth_webauthn_b64url_field(r->pool, response,
                                            "clientDataJSON",
                                            &assertion.client_data_json) !=
        NGX_OK
        || ngx_http_auth_webauthn_b64url_field(r->pool, response,
                                               "authenticatorData",
                                               &assertion.authenticator_data) !=
        NGX_OK
        || ngx_http_auth_webauthn_b64url_field(r->pool, response,
                                               "signature",
                                               &assertion.signature) != NGX_OK)
    {
        goto reject;
    }

    /* Extract the challenge named inside clientDataJSON (consumed below). */
    {
        nxe_json_t *cdj = nxe_json_parse_untrusted(&assertion.client_data_json,
                                                   r->pool);
        if (cdj == NULL || !nxe_json_is_object(cdj)
            || nxe_json_object_get_string(cdj, "challenge", &challenge_b64,
                                          r->pool) != NGX_OK)
        {
            goto reject;
        }
    }

    challenge_raw.data = ngx_pnalloc(r->pool,
                                     ngx_base64_decoded_length(
                                         challenge_b64.len));
    if (challenge_raw.data == NULL) {
        goto reject;
    }
    src.data = challenge_b64.data;
    src.len = challenge_b64.len;
    if (ngx_decode_base64url(&challenge_raw, &src) != NGX_OK) {
        goto reject;
    }

    /* Open the Redis connection shared by the challenge consume below and the
     * credential lookup that follows. */
    ngx_memzero(&rconf, sizeof(rconf));
    rconf.host = wlcf->redis_host;
    rconf.port = (int) wlcf->redis_port;
    rconf.password = wlcf->redis_password;
    rconf.db = wlcf->redis_db;
    rconf.timeout_ms = wlcf->redis_timeout;

    if (ngx_auth_webauthn_redis_connect(r->pool, r->connection->log, &rconf,
                                        &redis) != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Atomically consume the challenge named inside clientDataJSON (GETDEL). */
    if (ngx_auth_webauthn_challenge_consume(redis, r->pool,
                                            &wlcf->redis_key_prefix,
                                            challenge_raw.data,
                                            challenge_raw.len) != NGX_OK)
    {
        /* unknown / expired / already used */
        goto reject_redis;
    }

    /* Fetch the stored credential from Redis. */
    ngx_memzero(&cred, sizeof(cred));
    rc = ngx_auth_webauthn_credential_get(redis, r->pool,
                                          &wlcf->redis_key_prefix, &id, &cred);
    if (rc != NGX_OK) {
        /* DECLINED (missing) and ERROR both collapse to a uniform 401 to
         * avoid a credential-existence oracle. */
        goto reject_redis;
    }

    /* Run the cryptographic verification. */
    ngx_memzero(&acred, sizeof(acred));
    acred.public_key = cred.public_key;
    acred.alg = cred.alg;
    acred.sign_count = cred.sign_count;

    ngx_memzero(&policy, sizeof(policy));
    policy.rp_id = wlcf->rp_id;
    policy.expected_challenge = challenge_raw;
    policy.allowed_origins = wlcf->origins->elts;
    policy.norigins = wlcf->origins->nelts;
    policy.require_uv =
        (wlcf->user_verification == NGX_AUTH_WEBAUTHN_UV_REQUIRED);
    policy.clone_detection = wlcf->clone_detection;

    ngx_memzero(&result, sizeof(result));
    rc = ngx_auth_webauthn_assertion_verify(r->pool, &assertion, &acred,
                                            &policy, &result);
    if (rc != NGX_OK) {
        goto reject_redis;
    }

    /* Persist the advanced sign counter. */
    now = ngx_time();
    (void) ngx_auth_webauthn_credential_update_counter(redis, r->pool,
                                                       &wlcf->redis_key_prefix,
                                                       &id,
                                                       result.auth_sign_count,
                                                       now);

    ngx_auth_webauthn_redis_close(redis);
    redis = NULL;

    /* Mint the session JWT. */
    if (RAND_bytes(jti, sizeof(jti)) != 1) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    jti_raw.data = jti;
    jti_raw.len = sizeof(jti);
    if (ngx_http_auth_webauthn_b64url(r->pool, &jti_raw, &jti_b64) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    sub_esc = ngx_http_auth_webauthn_json_escape(r->pool, &cred.user_id);
    if (sub_esc.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    claims.data = ngx_pnalloc(r->pool, 256 + sub_esc.len + id.len
                              + wlcf->rp_id.len + jti_b64.len);
    if (claims.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    p = ngx_sprintf(claims.data,
                    "{\"iss\":\"nginx-webauthn\",\"aud\":\"%V\",\"sub\":\"%V\","
                    "\"cid\":\"%V\",\"iat\":%T,\"exp\":%T,\"jti\":\"%V\"}",
                    &wlcf->rp_id, &sub_esc, &id, now, now + wlcf->jwt_ttl,
                    &jti_b64);
    claims.len = (size_t) (p - claims.data);

    alg = wlcf->jwt_alg;
    if (nxe_jwx_encode(r->pool, &alg, NULL, &claims, &wlcf->jwt_secret, &jwt)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_webauthn: failed to mint session token");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Set-Cookie. */
    cookie.data = ngx_pnalloc(r->pool, wlcf->cookie_name.len + jwt.len
                              + wlcf->cookie_path.len + wlcf->cookie_domain.len
                              + 128);
    if (cookie.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    p = ngx_sprintf(cookie.data, "%V=%V; HttpOnly; SameSite=%s; Path=%V",
                    &wlcf->cookie_name, &jwt,
                    ngx_http_auth_webauthn_samesite_name[wlcf->cookie_samesite],
                    &wlcf->cookie_path);
    if (wlcf->cookie_secure) {
        p = ngx_cpymem(p, "; Secure", sizeof("; Secure") - 1);
    }
    if (wlcf->cookie_domain.len) {
        p = ngx_sprintf(p, "; Domain=%V", &wlcf->cookie_domain);
    }
    p = ngx_sprintf(p, "; Max-Age=%T", (time_t) wlcf->jwt_ttl);
    cookie.len = (size_t) (p - cookie.data);

    {
        ngx_table_elt_t *set_cookie = ngx_list_push(&r->headers_out.headers);
        if (set_cookie == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        set_cookie->hash = 1;
        ngx_str_set(&set_cookie->key, "Set-Cookie");
        set_cookie->value = cookie;
        set_cookie->next = NULL;
    }

    /* Success body. */
    {
        ngx_str_t out;
        out.data = ngx_pnalloc(r->pool, 64 + sub_esc.len);
        if (out.data == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        p = ngx_sprintf(out.data, "{\"ok\":true,\"user_id\":\"%V\",\"exp\":%T}",
                        &sub_esc, now + wlcf->jwt_ttl);
        out.len = (size_t) (p - out.data);

        ngx_http_finalize_request(r,
                                  ngx_http_auth_webauthn_send_json(r,
                                                                   NGX_HTTP_OK,
                                                                   &out));
    }
    return;

reject_redis:

    if (redis != NULL) {
        ngx_auth_webauthn_redis_close(redis);
    }

reject:

    ngx_http_finalize_request(r, ngx_http_auth_webauthn_verify_fail(r));
}


static ngx_int_t
ngx_http_auth_webauthn_verify_content(ngx_http_request_t *r)
{
    ngx_int_t rc;

    if (!(r->method & NGX_HTTP_POST)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_read_client_request_body(r,
                                           ngx_http_auth_webauthn_verify_done);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


/* === access phase gate === */

/* Build a one-key JWKS for HS verify, or a keyval doc for asym verify. */
static nxe_jwx_jwks_t *
ngx_http_auth_webauthn_build_jwks(ngx_http_request_t *r,
    ngx_http_auth_webauthn_loc_conf_t *wlcf)
{
    ngx_str_t doc;
    u_char *p;

    if (wlcf->jwt_alg_family == NGX_AUTH_WEBAUTHN_JWT_HMAC) {
        ngx_str_t k_b64;

        if (ngx_http_auth_webauthn_b64url(r->pool, &wlcf->jwt_secret, &k_b64)
            != NGX_OK)
        {
            return NULL;
        }
        doc.data = ngx_pnalloc(r->pool, 64 + k_b64.len + wlcf->jwt_alg.len);
        if (doc.data == NULL) {
            return NULL;
        }
        p = ngx_sprintf(doc.data,
                        "{\"keys\":[{\"kty\":\"oct\",\"k\":\"%V\","
                        "\"alg\":\"%V\"}]}", &k_b64, &wlcf->jwt_alg);
        doc.len = (size_t) (p - doc.data);

        return nxe_jwx_jwks_parse(&doc, r->pool);
    }

    /* Asymmetric: keyval map of one PEM public key. */
    {
        ngx_str_t pem_esc;

        pem_esc = ngx_http_auth_webauthn_json_escape(r->pool,
                                                     &wlcf->jwt_pub_pem);
        if (pem_esc.data == NULL) {
            return NULL;
        }
        doc.data = ngx_pnalloc(r->pool, 24 + pem_esc.len);
        if (doc.data == NULL) {
            return NULL;
        }
        p = ngx_sprintf(doc.data, "{\"webauthn\":\"%V\"}", &pem_esc);
        doc.len = (size_t) (p - doc.data);

        return nxe_jwx_jwks_parse_keyval(&doc, r->pool);
    }
}


static ngx_int_t
ngx_http_auth_webauthn_unauthorized(ngx_http_request_t *r,
    ngx_http_auth_webauthn_loc_conf_t *wlcf)
{
    ngx_table_elt_t *location;

    if (wlcf->signin_url.len == 0) {
        return NGX_HTTP_UNAUTHORIZED;
    }

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = wlcf->signin_url;
    location->next = NULL;

    r->headers_out.location = location;

    return NGX_HTTP_MOVED_TEMPORARILY;
}


/* Apply auth_webauthn_set_header values to the upstream request. */
static ngx_int_t
ngx_http_auth_webauthn_apply_headers(ngx_http_request_t *r,
    ngx_http_auth_webauthn_loc_conf_t *wlcf)
{
    ngx_http_auth_webauthn_header_t *hdrs;
    ngx_table_elt_t *h;
    ngx_str_t value;
    ngx_uint_t i;

    if (wlcf->set_headers == NULL) {
        return NGX_OK;
    }

    hdrs = wlcf->set_headers->elts;
    for (i = 0; i < wlcf->set_headers->nelts; i++) {
        if (ngx_http_complex_value(r, &hdrs[i].value, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        h->hash = 1;
        h->key = hdrs[i].name;
        h->value = value;
        h->lowcase_key = h->key.data;
        h->next = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_webauthn_access_handler(ngx_http_request_t *r)
{
    ngx_http_auth_webauthn_loc_conf_t *wlcf;
    ngx_http_auth_webauthn_ctx_t *ctx;
    nxe_jwx_token_t *token;
    nxe_jwx_jwks_t *jwks;
    nxe_json_t *payload;
    ngx_str_t cookie_name, cookie_val, sub;
    int64_t exp;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_webauthn_module);

    if (!wlcf->auth) {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_webauthn_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_str_set(&ctx->auth_status, "unauthenticated");
    ngx_http_set_ctx(r, ctx, ngx_http_auth_webauthn_module);

    if (wlcf->jwt_secret.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_webauthn: auth_webauthn on requires "
                      "auth_webauthn_jwt_secret_file");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cookie_name = wlcf->cookie_name;
    if (r->headers_in.cookie == NULL
        || ngx_http_parse_cookie_lines(r, r->headers_in.cookie,
                                       &cookie_name, &cookie_val) == NULL)
    {
        return ngx_http_auth_webauthn_unauthorized(r, wlcf);
    }

    token = nxe_jwx_decode(&cookie_val, r->pool);
    if (token == NULL) {
        ngx_str_set(&ctx->auth_status, "invalid");
        return ngx_http_auth_webauthn_unauthorized(r, wlcf);
    }

    jwks = ngx_http_auth_webauthn_build_jwks(r, wlcf);
    if (jwks == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (nxe_jwx_jws_verify(token, jwks, r->pool) != NGX_OK) {
        ngx_str_set(&ctx->auth_status, "invalid");
        return ngx_http_auth_webauthn_unauthorized(r, wlcf);
    }

    payload = nxe_jwx_token_payload(token);
    if (payload == NULL) {
        ngx_str_set(&ctx->auth_status, "invalid");
        return ngx_http_auth_webauthn_unauthorized(r, wlcf);
    }

    /* Registered-claim policy: enforce exp ourselves (nxe-jwx does not). */
    if (nxe_jwx_claims_get_integer(payload, "exp", &exp) != NGX_OK
        || exp <= (int64_t) ngx_time())
    {
        ngx_str_set(&ctx->auth_status, "expired");
        return ngx_http_auth_webauthn_unauthorized(r, wlcf);
    }
    ctx->jwt_exp = (time_t) exp;
    ctx->has_exp = 1;

    if (nxe_jwx_claims_get_string(payload, "sub", &sub) == NGX_OK) {
        ctx->user_id.data = ngx_pnalloc(r->pool, sub.len);
        if (ctx->user_id.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(ctx->user_id.data, sub.data, sub.len);
        ctx->user_id.len = sub.len;
    }

    {
        ngx_str_t cid;
        if (nxe_jwx_claims_get_string(payload, "cid", &cid) == NGX_OK) {
            ctx->credential_id.data = ngx_pnalloc(r->pool, cid.len);
            if (ctx->credential_id.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(ctx->credential_id.data, cid.data, cid.len);
            ctx->credential_id.len = cid.len;
        }
    }

    ngx_str_set(&ctx->auth_status, "authenticated");

    if (ngx_http_auth_webauthn_apply_headers(r, wlcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
