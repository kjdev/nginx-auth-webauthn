/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_HASH_H
#define NGX_AUTH_WEBAUTHN_HASH_H

#include <ngx_config.h>
#include <ngx_core.h>

/* SHA-256 digest length in bytes (rpIdHash size, signedData hash) */
#define NGX_AUTH_WEBAUTHN_SHA256_LEN  32

/*
 * Compute SHA-256 over data[0..len) and write the 32-byte digest to out.
 * out must point to a buffer of at least NGX_AUTH_WEBAUTHN_SHA256_LEN bytes.
 * A len of 0 is valid (digest of the empty input); data may be NULL only
 * when len is 0.
 *
 * Returns NGX_OK on success, NGX_ERROR on failure (OpenSSL error,
 * out == NULL, or data == NULL with len > 0).
 */
ngx_int_t ngx_auth_webauthn_hash_sha256(const u_char *data, size_t len,
    u_char *out);

#endif /* NGX_AUTH_WEBAUTHN_HASH_H */
