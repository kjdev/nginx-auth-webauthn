/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * ngx_compat.c - implementation of the nginx core shim for the CLI.
 *
 * Every allocation is tracked in the pool's "large" list so ngx_destroy_pool
 * releases it; cleanup handlers run in LIFO order, like nginx core.  This lets
 * the shared sources allocate exactly as they do under nginx while the CLI
 * stays leak-free under AddressSanitizer.
 */

#include "ngx_compat.h"

#include <stdarg.h>
#include <stdlib.h>


/*
 * Emulate nginx's ngx_log_error for the CLI / unit-test builds.  nginx parses
 * its own format specifiers in ngx_vslprintf; the host vfprintf does not, so
 * rewrite the numeric size specifiers the shared code actually uses into C99
 * forms that read each argument with the matching width:
 *
 *   %uz (size_t)     -> %zu
 *   %ui (ngx_uint_t) -> %zu   (uintptr_t, same width as size_t on LP64)
 *   %z  (ssize_t)    -> %zd
 *   %i  (ngx_int_t)  -> %zd
 *
 * Everything else (%s, %d, %.*s, ...) is already valid for vfprintf and is
 * copied through untouched.  Pointer/string specifiers like %V consume two
 * arguments and cannot be expressed by a pure format rewrite; the shared code
 * does not use them, so they are intentionally unsupported.
 */
void
ngx_compat_log_error(ngx_uint_t level, ngx_log_t *log, ngx_int_t err,
    const char *fmt, ...)
{
    va_list      args;
    const char  *p;
    char        *q;
    char         buf[512];

    (void) err;

    if (log == NULL || level > log->log_level) {
        return;
    }

    q = buf;
    for (p = fmt; *p != '\0' && q < buf + sizeof(buf) - 3; p++) {
        if (*p != '%') {
            *q++ = *p;
            continue;
        }

        if (p[1] == 'u' && (p[2] == 'z' || p[2] == 'i')) {  /* %uz / %ui */
            *q++ = '%';
            *q++ = 'z';
            *q++ = 'u';
            p += 2;

        } else if (p[1] == 'z' || p[1] == 'i') {            /* %z / %i */
            *q++ = '%';
            *q++ = 'z';
            *q++ = 'd';
            p += 1;

        } else {
            *q++ = *p;  /* '%' itself; a standard specifier follows verbatim */
        }
    }
    *q = '\0';

    fputs("[ngx_compat] ", stderr);
    va_start(args, fmt);
    vfprintf(stderr, buf, args);
    va_end(args);
    fputc('\n', stderr);
}


ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t *pool;

    (void) size;

    pool = malloc(sizeof(ngx_pool_t));
    if (pool == NULL) {
        return NULL;
    }

    pool->large = NULL;
    pool->cleanup = NULL;
    pool->log = log;

    return pool;
}


void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_large_t *l, *next;
    ngx_pool_cleanup_t *c, *cnext;

    if (pool == NULL) {
        return;
    }

    /* Run cleanup handlers in LIFO order, like nginx core. */
    for (c = pool->cleanup; c != NULL; c = cnext) {
        cnext = c->next;
        if (c->handler != NULL) {
            c->handler(c->data);
        }
        free(c);
    }

    for (l = pool->large; l != NULL; l = next) {
        next = l->next;
        free(l->alloc);
        free(l);
    }

    free(pool);
}


ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    ngx_pool_cleanup_t *c;

    if (pool == NULL) {
        return NULL;
    }

    c = malloc(sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size > 0) {
        c->data = malloc(size);
        if (c->data == NULL) {
            free(c);
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = pool->cleanup;
    pool->cleanup = c;

    return c;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    ngx_pool_large_t *large;

    p = malloc(size);
    if (p == NULL) {
        return NULL;
    }

    large = malloc(sizeof(ngx_pool_large_t));
    if (large == NULL) {
        free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return ngx_palloc(pool, size);
}


void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p != NULL) {
        ngx_memzero(p, size);
    }

    return p;
}


ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t *l, **prev;

    if (pool == NULL) {
        return NGX_ERROR;
    }

    prev = &pool->large;
    for (l = pool->large; l != NULL; l = l->next) {
        if (l->alloc == p) {
            *prev = l->next;
            free(l->alloc);
            free(l);
            return NGX_OK;
        }
        prev = &l->next;
    }

    return NGX_ERROR;
}


/*
 * base64url encoder.  URL-safe alphabet, no '=' padding.  Port of nginx
 * core's ngx_encode_base64_internal with padding disabled, so output is
 * byte-for-byte identical to the module's ngx_encode_base64url.
 */
void
ngx_encode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    static const u_char basis[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    u_char *d, *s;
    size_t len;

    s = src->data;
    d = dst->data;
    len = src->len;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }
    }

    dst->len = (size_t) (d - dst->data);
}


static int
ngx_compat_b64url_char(u_char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }
    return -1;
}


/*
 * base64url decoder.  Tolerates missing or trailing '=' padding and the
 * URL-safe '-' / '_' alphabet.  Rejects any other byte.
 */
ngx_int_t
ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    size_t i;
    int v;
    u_char *out;
    int bits = 0;
    int buf = 0;

    out = dst->data;
    dst->len = 0;

    for (i = 0; i < src->len; i++) {
        u_char ch = src->data[i];

        if (ch == '=') {
            continue;
        }

        v = ngx_compat_b64url_char(ch);
        if (v < 0) {
            return NGX_ERROR;
        }

        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            *out++ = (u_char) ((buf >> bits) & 0xff);
        }
    }

    dst->len = (size_t) (out - dst->data);
    return NGX_OK;
}
