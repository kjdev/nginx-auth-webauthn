/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#ifndef NGX_AUTH_WEBAUTHN_COSE_H
#define NGX_AUTH_WEBAUTHN_COSE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>

/* Supported COSE algorithm identifiers (docs/ARCHITECTURE.md 6.6) */
#define NGX_AUTH_WEBAUTHN_COSE_ALG_ES256   (-7)
#define NGX_AUTH_WEBAUTHN_COSE_ALG_EDDSA   (-8)
#define NGX_AUTH_WEBAUTHN_COSE_ALG_RS256   (-257)


/*
 * Decode a COSE_Key (RFC 8152) from cose[0..cose_len) into an OpenSSL public
 * EVP_PKEY.  Supported key types: EC2/ES256 (P-256), OKP/EdDSA (Ed25519),
 * RSA/RS256.  Requires OpenSSL 3.0+.
 *
 * On success *pkey owns a new key the caller must free with EVP_PKEY_free,
 * and *alg holds the COSE algorithm identifier.
 *
 * Returns NGX_OK on success, NGX_DECLINED when the key is well-formed CBOR but
 * uses an unsupported type / curve / algorithm, NGX_ERROR on a NULL argument,
 * malformed CBOR, or an OpenSSL failure.
 */
ngx_int_t ngx_auth_webauthn_cose_to_pkey(const u_char *cose, size_t cose_len,
    EVP_PKEY **pkey, int *alg);


/*
 * Convenience over ngx_auth_webauthn_cose_to_pkey: encode the public key as a
 * DER SubjectPublicKeyInfo (i2d_PUBKEY output, the Redis storage form;
 * docs/ARCHITECTURE.md 6.7).  der is allocated from pool.
 *
 * Same return-value contract as ngx_auth_webauthn_cose_to_pkey, plus NGX_ERROR
 * if pool or der is NULL or allocation fails.
 */
ngx_int_t ngx_auth_webauthn_cose_to_der(ngx_pool_t *pool, const u_char *cose,
    size_t cose_len, ngx_str_t *der, int *alg);

#endif /* NGX_AUTH_WEBAUTHN_COSE_H */
