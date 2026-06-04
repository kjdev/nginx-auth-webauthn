/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_compat.h - minimal nginx core surface for the standalone CLI.
 *
 * The shared src/ngx_auth_webauthn_*.c sources and the nxe-json submodule
 * are written against the nginx core API (ngx_pool_t / ngx_str_t /
 * ngx_log_error / ngx_*_base64url), the same as every sibling module.  The
 * auth-webauthn-admin CLI has no nginx runtime, so it links this shim, which
 * provides a malloc-backed ngx_pool_t and the handful of ngx core helpers the
 * shared code depends on.  ngx_core.h / ngx_config.h in this directory shadow
 * the real nginx headers and redirect here.
 *
 * Behaviour that crosses the CLI/module boundary (notably base64url and the
 * base64 length macros) matches nginx core exactly so credential data written
 * by the CLI round-trips through the module bit-for-bit.
 */

#ifndef NGX_COMPAT_H
#define NGX_COMPAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


/* --- basic types --- */

typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef intptr_t ngx_flag_t;

#define NGX_OK          0
#define NGX_ERROR       (-1)
#define NGX_DECLINED    (-5)

#define NGX_MAX_INT_T_VALUE  INTPTR_MAX

#ifndef NULL
#define NULL ((void *) 0)
#endif

#define ngx_inline  inline


/* --- ngx_str_t --- */

typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string     { 0, NULL }

#define ngx_str_set(str, text)                                               \
        (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text

#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL


/* --- forward declarations --- */

typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s ngx_log_t;
typedef struct ngx_pool_large_s ngx_pool_large_t;


/* --- ngx_log_t (minimal) --- */

#define NGX_LOG_STDERR  0
#define NGX_LOG_EMERG   1
#define NGX_LOG_ALERT   2
#define NGX_LOG_CRIT    3
#define NGX_LOG_ERR     4
#define NGX_LOG_WARN    5
#define NGX_LOG_NOTICE  6
#define NGX_LOG_INFO    7
#define NGX_LOG_DEBUG   8

struct ngx_log_s {
    ngx_uint_t  log_level;
};

#define ngx_log_error(level, log, err, ...)                                  \
        do {                                                                 \
            (void) (err);                                                    \
            if ((log) != NULL                                                \
                && (ngx_uint_t) (level) <= (log)->log_level)                 \
            {                                                                \
                fprintf(stderr, "[ngx_compat] ");                            \
                fprintf(stderr, __VA_ARGS__);                                \
                fprintf(stderr, "\n");                                       \
            }                                                                \
        } while (0)


/* --- ngx_pool_t (malloc-backed) --- */

typedef struct ngx_pool_cleanup_s ngx_pool_cleanup_t;
typedef void (*ngx_pool_cleanup_pt)(void *data);

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt  handler;
    void                *data;
    ngx_pool_cleanup_t  *next;
};

struct ngx_pool_large_s {
    ngx_pool_large_t *next;
    void             *alloc;
};

struct ngx_pool_s {
    ngx_pool_large_t   *large;
    ngx_pool_cleanup_t *cleanup;
    ngx_log_t          *log;
};

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void        ngx_destroy_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
ngx_int_t  ngx_pfree(ngx_pool_t *pool, void *p);

ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size);


/* --- memory / string macros --- */

#define ngx_memcmp(s1, s2, n)   memcmp(s1, s2, n)
#define ngx_memcpy(dst, src, n) memcpy(dst, src, n)
#define ngx_memzero(buf, n)     memset(buf, 0, n)
#define ngx_memset(buf, c, n)   memset(buf, c, n)
#define ngx_strlen(s)           strlen((const char *) (s))
#define ngx_strncmp(s1, s2, n)  strncmp((const char *) (s1),                 \
                                        (const char *) (s2), n)
#define ngx_strcmp(s1, s2)      strcmp((const char *) (s1),                  \
                                       (const char *) (s2))


/* --- base64 / base64url ---
 *
 * Length macros use nginx core's exact definitions so a buffer sized here is
 * identical to one sized inside the module.  base64url uses the URL-safe
 * alphabet with no '=' padding, matching ngx_encode_base64url /
 * ngx_decode_base64url.
 */

#define ngx_base64_encoded_length(len)  (((len) + 2) / 3 * 4)
#define ngx_base64_decoded_length(len)  (((len) + 3) / 4 * 3)

void      ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);


#endif /* NGX_COMPAT_H */
