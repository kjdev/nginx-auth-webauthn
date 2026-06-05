/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "auth_webauthn_admin.h"
#include "ngx_auth_webauthn_attestation.h"
#include "ngx_auth_webauthn_authdata.h"
#include "ngx_auth_webauthn_cose.h"
#include "ngx_auth_webauthn_hash.h"
#include "ngx_auth_webauthn_credential.h"
#include "nxe_json.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

/* Number of credential-id bytes echoed back on success (privacy). */
#define AUTH_WEBAUTHN_ADMIN_CID_ECHO  12

enum {
    OPT_USER_ID = AUTH_WEBAUTHN_ADMIN_OPT_SUBCOMMAND_BASE,
    OPT_RESPONSE_FILE,
    OPT_RP_ID,
    OPT_REQUIRE_ATTESTATION,
    OPT_ORIGIN,
    OPT_TRANSPORTS
};


static void
ngx_auth_webauthn_admin_register_usage(FILE *out)
{
    fprintf(out,
        "usage: auth-webauthn-admin register [options]\n"
        "\n"
        "options:\n"
        "  --user-id=<id>                 application user id (required)\n"
        "  --response-file=<path>         AttestationResponse JSON; '-' reads\n"
        "                                 stdin (required)\n"
        "  --rp-id=<domain>               expected RP ID (required)\n"
        "  --require-attestation=none|packed\n"
        "                                 attestation level (default none)\n"
        "  --origin=<url>                 accepted but not verified here\n"
        "  --transports=<csv>             override transports (usb,nfc,...)\n"
        "  --redis=<host:port> ...        see 'auth-webauthn-admin --help'\n");
}


/* Decode a base64url string member of obj into a pool buffer. */
static ngx_int_t
ngx_auth_webauthn_admin_decode_member(ngx_pool_t *pool, nxe_json_t *obj,
    const char *key, ngx_str_t *out)
{
    ngx_str_t    enc;
    nxe_json_t  *node;

    node = nxe_json_object_get(obj, key);
    if (node == NULL || nxe_json_string(node, &enc) != NGX_OK) {
        fprintf(stderr, "error: response.%s missing or not a string\n", key);
        return NGX_ERROR;
    }

    out->data = ngx_palloc(pool, ngx_base64_decoded_length(enc.len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(out, &enc) != NGX_OK) {
        fprintf(stderr, "error: response.%s is not valid base64url\n", key);
        return NGX_ERROR;
    }

    return NGX_OK;
}


int
auth_webauthn_admin_cmd_register(auth_webauthn_admin_ctx_t *ctx, int argc,
    char **argv)
{
    int                              c;
    int                              alg;
    int                              rc;
    ngx_uint_t                       require;
    ngx_str_t                        body;
    ngx_str_t                        client_data;
    ngx_str_t                        att_obj;
    ngx_str_t                        rp_id;
    ngx_str_t                        cdh_str;
    ngx_str_t                        cid_enc;
    ngx_str_t                        der;
    nxe_json_t                      *json;
    nxe_json_t                      *response;
    u_char                           cdh[NGX_AUTH_WEBAUTHN_SHA256_LEN];
    const char                      *user_id = NULL;
    const char                      *response_file = NULL;
    const char                      *rp_id_arg = NULL;
    const char                      *require_arg = NULL;
    const char                      *transports = NULL;
    ngx_auth_webauthn_attestation_t  att;
    ngx_auth_webauthn_authdata_t     ad;
    ngx_auth_webauthn_redis_t       *redis;
    ngx_auth_webauthn_credential_t   cred;

    static const struct option  longopts[] = {
        { "user-id",             required_argument, NULL, OPT_USER_ID },
        { "response-file",       required_argument, NULL, OPT_RESPONSE_FILE },
        { "rp-id",               required_argument, NULL, OPT_RP_ID },
        { "require-attestation", required_argument, NULL,
          OPT_REQUIRE_ATTESTATION },
        { "origin",              required_argument, NULL, OPT_ORIGIN },
        { "transports",          required_argument, NULL, OPT_TRANSPORTS },
        { "redis",               required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS },
        { "redis-password",      required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_PASSWORD },
        { "redis-db",            required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_DB },
        { "redis-timeout",       required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_REDIS_TIMEOUT },
        { "key-prefix",          required_argument, NULL,
          AUTH_WEBAUTHN_ADMIN_OPT_KEY_PREFIX },
        { "help",                no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case OPT_USER_ID:             user_id = optarg; break;
        case OPT_RESPONSE_FILE:       response_file = optarg; break;
        case OPT_RP_ID:               rp_id_arg = optarg; break;
        case OPT_REQUIRE_ATTESTATION: require_arg = optarg; break;
        case OPT_ORIGIN:              /* accepted, not verified here */ break;
        case OPT_TRANSPORTS:          transports = optarg; break;

        case 'h':
            ngx_auth_webauthn_admin_register_usage(stdout);
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

    if (user_id == NULL || response_file == NULL || rp_id_arg == NULL) {
        fprintf(stderr,
            "error: --user-id, --response-file and --rp-id are required\n");
        return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
    }

    require = NGX_AUTH_WEBAUTHN_ATT_NONE;
    if (require_arg != NULL) {
        if (strcmp(require_arg, "packed") == 0) {
            require = NGX_AUTH_WEBAUTHN_ATT_PACKED;
        } else if (strcmp(require_arg, "none") != 0) {
            fprintf(stderr,
                "error: --require-attestation expects none|packed\n");
            return AUTH_WEBAUTHN_ADMIN_EX_USAGE;
        }
    }

    if (auth_webauthn_admin_read_file(ctx->pool, response_file, &body)
        != NGX_OK)
    {
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    /* Attestation responses are externally produced: parse with DoS limits. */
    json = nxe_json_parse_untrusted(&body, ctx->pool);
    if (json == NULL) {
        fprintf(stderr, "error: response file is not valid JSON\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    response = nxe_json_object_get(json, "response");
    if (response == NULL || !nxe_json_is_object(response)) {
        fprintf(stderr, "error: missing 'response' object\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_admin_decode_member(ctx->pool, response,
            "clientDataJSON", &client_data) != NGX_OK
        || ngx_auth_webauthn_admin_decode_member(ctx->pool, response,
            "attestationObject", &att_obj) != NGX_OK)
    {
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_attestation_parse(ctx->pool, att_obj.data,
            att_obj.len, &att) != NGX_OK)
    {
        fprintf(stderr, "error: cannot parse attestationObject\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_authdata_parse(att.auth_data.data, att.auth_data.len,
            &ad) != NGX_OK)
    {
        fprintf(stderr, "error: cannot parse authenticatorData\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (!(ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT)
        || ad.credential_id.len == 0 || ad.cose_public_key.len == 0)
    {
        fprintf(stderr,
            "error: authenticatorData carries no attested credential\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_hash_sha256(client_data.data, client_data.len, cdh)
        != NGX_OK)
    {
        fprintf(stderr, "error: clientDataJSON hashing failed\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    rp_id.data = (u_char *) rp_id_arg;
    rp_id.len = ngx_strlen(rp_id_arg);
    cdh_str.data = cdh;
    cdh_str.len = sizeof(cdh);

    rc = ngx_auth_webauthn_attestation_verify(ctx->pool, &att, &rp_id,
        &cdh_str, require);
    if (rc != NGX_OK) {
        fprintf(stderr, "error: attestation verification failed "
            "(fmt=%.*s, require=%s)\n",
            (int) att.fmt.len, att.fmt.data,
            require == NGX_AUTH_WEBAUTHN_ATT_PACKED ? "packed" : "none");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    if (ngx_auth_webauthn_cose_to_der(ctx->pool, ad.cose_public_key.data,
            ad.cose_public_key.len, &der, &alg) != NGX_OK)
    {
        fprintf(stderr, "error: unsupported or malformed COSE public key\n");
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    /* Encode the raw credential id to base64url for use as the Redis key. */
    cid_enc.data = ngx_palloc(ctx->pool,
        ngx_base64_encoded_length(ad.credential_id.len));
    if (cid_enc.data == NULL) {
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }
    ngx_encode_base64url(&cid_enc, &ad.credential_id);

    ngx_memzero(&cred, sizeof(cred));
    cred.credential_id = cid_enc;
    cred.user_id.data = (u_char *) user_id;
    cred.user_id.len = ngx_strlen(user_id);
    cred.public_key = der;
    cred.alg = alg;
    cred.sign_count = ad.sign_count;
    cred.created_at = (int64_t) time(NULL);
    cred.last_used_at = 0;
    ngx_memcpy(cred.aaguid, ad.aaguid, NGX_AUTH_WEBAUTHN_AAGUID_LEN);
    cred.has_aaguid = 1;
    if (transports != NULL) {
        cred.transports.data = (u_char *) transports;
        cred.transports.len = ngx_strlen(transports);
    }

    if (auth_webauthn_admin_connect(ctx, &redis) != NGX_OK) {
        nxe_json_free(json);
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    rc = ngx_auth_webauthn_credential_put(redis, ctx->pool, &ctx->key_prefix,
        &cred);

    ngx_auth_webauthn_redis_close(redis);
    nxe_json_free(json);

    if (rc != NGX_OK) {
        fprintf(stderr, "error: failed to store credential in Redis\n");
        return AUTH_WEBAUTHN_ADMIN_EX_FAIL;
    }

    printf("registered: cid=%.*s%s alg=%s\n",
        (int) (cid_enc.len < AUTH_WEBAUTHN_ADMIN_CID_ECHO
               ? cid_enc.len : AUTH_WEBAUTHN_ADMIN_CID_ECHO),
        cid_enc.data,
        cid_enc.len > AUTH_WEBAUTHN_ADMIN_CID_ECHO ? "..." : "",
        auth_webauthn_admin_alg_name(alg));

    return AUTH_WEBAUTHN_ADMIN_EX_OK;
}
