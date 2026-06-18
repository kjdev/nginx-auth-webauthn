/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_auth_webauthn_assertion.h"
#include "ngx_auth_webauthn_clientdata.h"
#include "ngx_auth_webauthn_hash.h"

#include <openssl/evp.h>
#include <openssl/x509.h>


/*
 * Decide whether the received sign counter is acceptable under the policy.
 * Returns NGX_OK to allow, NGX_DECLINED to reject as a possible clone.
 */
static ngx_int_t
ngx_auth_webauthn_assertion_check_counter(ngx_uint_t policy, uint32_t auth,
    uint32_t stored)
{
    if (policy == NGX_AUTH_WEBAUTHN_CLONE_OFF) {
        return NGX_OK;
    }

    /* Authenticators without a counter report 0 forever; allow that. */
    if (auth == 0 && stored == 0) {
        return NGX_OK;
    }

    if (auth > stored) {
        return NGX_OK;
    }

    /* Non-increasing counter: a clone signal. */
    if (policy == NGX_AUTH_WEBAUTHN_CLONE_LAX) {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/*
 * Verify the assertion signature over signedData with the credential's public
 * key.  Returns NGX_OK on a valid signature, NGX_DECLINED on a bad signature,
 * NGX_ERROR on a key-load or OpenSSL error.
 */
static ngx_int_t
ngx_auth_webauthn_assertion_check_signature(
    ngx_auth_webauthn_assertion_cred_t *cred, const u_char *signed_data,
    size_t signed_len, ngx_str_t *signature)
{
    const u_char *der;
    const EVP_MD *md;
    EVP_PKEY *pkey;
    EVP_MD_CTX *ctx;
    ngx_int_t rc;
    int ret;

    switch (cred->alg) {
    case -7:    /* ES256 */
    case -257:  /* RS256 */
        md = EVP_sha256();
        break;
    case -8:    /* EdDSA (Ed25519, PureEdDSA): no pre-hash */
        md = NULL;
        break;
    default:
        return NGX_ERROR;
    }

    der = cred->public_key.data;
    pkey = d2i_PUBKEY(NULL, &der, (long) cred->public_key.len);
    if (pkey == NULL) {
        return NGX_ERROR;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1) {
        /*
         * One-shot verify works for ECDSA, RSA and Ed25519 alike (Ed25519
         * requires it).  ES256 signatures arrive DER-encoded and are passed
         * through unchanged.
         */
        ret = EVP_DigestVerify(ctx, signature->data, signature->len,
                               signed_data, signed_len);

        if (ret == 1) {
            rc = NGX_OK;
        } else if (ret == 0) {
            rc = NGX_DECLINED;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return rc;
}


ngx_int_t
ngx_auth_webauthn_assertion_verify(ngx_pool_t *pool,
    ngx_auth_webauthn_assertion_t *assertion,
    ngx_auth_webauthn_assertion_cred_t *cred,
    ngx_auth_webauthn_assertion_policy_t *policy,
    ngx_auth_webauthn_assertion_result_t *result)
{
    u_char rp_id_hash[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    u_char *signed_data;
    size_t signed_len;
    ngx_str_t expected_type = ngx_string("webauthn.get");
    ngx_int_t rc;
    ngx_auth_webauthn_authdata_t ad;

    if (pool == NULL || assertion == NULL || cred == NULL || policy == NULL
        || result == NULL
        || (policy->norigins > 0 && policy->allowed_origins == NULL))
    {
        return NGX_ERROR;
    }

    /* clientData: type / challenge / origin / crossOrigin */
    rc = ngx_auth_webauthn_clientdata_verify(pool,
                                             assertion->client_data_json.data,
                                             assertion->client_data_json.len,
                                             &expected_type,
                                             &policy->expected_challenge,
                                             policy->allowed_origins,
                                             policy->norigins);
    if (rc != NGX_OK) {
        return rc;
    }

    /* authData binary structure */
    rc = ngx_auth_webauthn_authdata_parse(assertion->authenticator_data.data,
                                          assertion->authenticator_data.len,
                                          &ad);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Assertions carry no attested credential data or extensions. */
    if (ad.flags & (NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT
                    | NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_ED))
    {
        return NGX_DECLINED;
    }

    /* rpIdHash == SHA-256(rpId) */
    if (ngx_auth_webauthn_hash_sha256(policy->rp_id.data, policy->rp_id.len,
                                      rp_id_hash) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_memcmp(rp_id_hash, ad.rp_id_hash, NGX_AUTH_WEBAUTHN_SHA256_LEN)
        != 0)
    {
        return NGX_DECLINED;
    }

    /* User Present is mandatory; User Verified is policy-driven. */
    if ((ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UP) == 0) {
        return NGX_DECLINED;
    }

    if (policy->require_uv
        && (ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UV) == 0)
    {
        return NGX_DECLINED;
    }

    /* Sign-counter clone detection */
    if (ngx_auth_webauthn_assertion_check_counter(policy->clone_detection,
                                                  ad.sign_count,
                                                  cred->sign_count) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* signedData = authenticatorData || SHA-256(clientDataJSON) */
    signed_len = assertion->authenticator_data.len
                 + NGX_AUTH_WEBAUTHN_SHA256_LEN;

    signed_data = ngx_pnalloc(pool, signed_len);
    if (signed_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(signed_data, assertion->authenticator_data.data,
               assertion->authenticator_data.len);

    if (ngx_auth_webauthn_hash_sha256(assertion->client_data_json.data,
                                      assertion->client_data_json.len,
                                      signed_data +
                                      assertion->authenticator_data.len) !=
        NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = ngx_auth_webauthn_assertion_check_signature(cred, signed_data,
                                                     signed_len,
                                                     &assertion->signature);
    if (rc != NGX_OK) {
        return rc;
    }

    result->auth_sign_count = ad.sign_count;

    return NGX_OK;
}
