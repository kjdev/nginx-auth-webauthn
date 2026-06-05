/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_CLIENTDATA_H
#define NGX_AUTH_WEBAUTHN_CLIENTDATA_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * Parse and verify a clientDataJSON byte string (WebAuthn level 2, 7.2
 * step-by-step; see docs/ARCHITECTURE.md 6.2).
 *
 * The input is parsed as untrusted JSON (DoS-bounded) and checked against:
 *   - type     == expected_type            (e.g. "webauthn.get")
 *   - challenge, base64url-decoded, equals expected_challenge byte-for-byte
 *   - origin   matches one of allowed_origins exactly
 *   - crossOrigin, when present, is not true
 *
 * origins are passed as a plain array (ptr + count) rather than ngx_array_t
 * so the verifier carries no nginx-runtime dependency; the module handler
 * passes arr->elts / arr->nelts.  expected_challenge is the raw challenge
 * bytes (the 32-byte value issued into the challenge store).
 *
 * Returns NGX_OK when every check passes, NGX_DECLINED on a parse failure or
 * any mismatch (an authentication rejection), NGX_ERROR on a NULL argument or
 * internal allocation failure.
 */
ngx_int_t ngx_auth_webauthn_clientdata_verify(ngx_pool_t *pool,
    const u_char *data, size_t len,
    ngx_str_t *expected_type, ngx_str_t *expected_challenge,
    ngx_str_t *allowed_origins, ngx_uint_t norigins);

#endif /* NGX_AUTH_WEBAUTHN_CLIENTDATA_H */
