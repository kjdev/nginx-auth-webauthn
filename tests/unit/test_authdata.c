/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 */

#include "test.h"
#include "ngx_auth_webauthn_authdata.h"


/* 37-byte assertion authData: rpIdHash(32) | flags(0x05 UP|UV) | signCount(7) */
static const u_char  authdata_assertion[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x05,                    /* flags: UP | UV */
    0x00, 0x00, 0x00, 0x07   /* signCount = 7 */
};

/*
 * Attestation authData: 37-byte prefix (flags 0x45 = UP|AT) | aaguid(16)
 * | credIdLen(4) | credId(4 bytes) | a 3-byte COSE-key placeholder.
 */
static const u_char  authdata_attestation[] = {
    /* rpIdHash */
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0x45,                    /* flags: UP | AT */
    0x00, 0x00, 0x00, 0x00,  /* signCount = 0 */
    /* aaguid */
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    0x00, 0x04,              /* credentialIdLength = 4 */
    0x11, 0x22, 0x33, 0x44,  /* credentialId */
    0xde, 0xad, 0xbe         /* COSE key placeholder (rest of buffer) */
};


static void
test_authdata_assertion(void)
{
    ngx_auth_webauthn_authdata_t  ad;
    ngx_int_t                     rc;

    rc = ngx_auth_webauthn_authdata_parse(authdata_assertion,
        sizeof(authdata_assertion), &ad);

    CHECK(rc == NGX_OK, "authdata assertion: parses");
    CHECK(ad.flags == 0x05, "authdata assertion: flags");
    CHECK((ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_UP) != 0,
        "authdata assertion: UP set");
    CHECK((ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT) == 0,
        "authdata assertion: AT clear");
    CHECK(ad.sign_count == 7, "authdata assertion: signCount");
    CHECK(ad.rp_id_hash[0] == 0x00 && ad.rp_id_hash[31] == 0x1f,
        "authdata assertion: rpIdHash bounds");
    CHECK(ad.credential_id.len == 0 && ad.credential_id.data == NULL,
        "authdata assertion: no attested cred data");
}


static void
test_authdata_attestation(void)
{
    ngx_auth_webauthn_authdata_t  ad;
    ngx_int_t                     rc;

    rc = ngx_auth_webauthn_authdata_parse(authdata_attestation,
        sizeof(authdata_attestation), &ad);

    CHECK(rc == NGX_OK, "authdata attestation: parses");
    CHECK((ad.flags & NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT) != 0,
        "authdata attestation: AT set");
    CHECK(ad.aaguid[0] == 0xf0 && ad.aaguid[15] == 0xff,
        "authdata attestation: aaguid");
    CHECK(ad.credential_id.len == 4,
        "authdata attestation: credId length");
    CHECK(ad.credential_id.data[0] == 0x11 && ad.credential_id.data[3] == 0x44,
        "authdata attestation: credId bytes");
    CHECK(ad.cose_public_key.len == 3,
        "authdata attestation: cose key is remaining bytes");
    CHECK(ad.cose_public_key.data[0] == 0xde,
        "authdata attestation: cose key bytes");
}


static void
test_authdata_too_short(void)
{
    ngx_auth_webauthn_authdata_t  ad;
    ngx_int_t                     rc;

    rc = ngx_auth_webauthn_authdata_parse(authdata_assertion, 36, &ad);
    CHECK(rc == NGX_DECLINED, "authdata short: NGX_DECLINED below 37 bytes");
}


static void
test_authdata_credid_overflow(void)
{
    ngx_auth_webauthn_authdata_t  ad;
    u_char                        buf[55];
    ngx_int_t                     rc;

    /* AT set, credentialIdLength claims more bytes than the buffer holds */
    ngx_memzero(buf, sizeof(buf));
    buf[32] = NGX_AUTH_WEBAUTHN_AUTHDATA_FLAG_AT;
    buf[53] = 0xff;   /* credIdLen high byte */
    buf[54] = 0xff;   /* credIdLen = 65535 */

    rc = ngx_auth_webauthn_authdata_parse(buf, sizeof(buf), &ad);
    CHECK(rc == NGX_DECLINED, "authdata overflow: NGX_DECLINED on credId len");
}


static void
test_authdata_null_out(void)
{
    ngx_int_t  rc;

    rc = ngx_auth_webauthn_authdata_parse(authdata_assertion,
        sizeof(authdata_assertion), NULL);
    CHECK(rc == NGX_ERROR, "authdata NULL out: NGX_ERROR");
}


void
run_authdata_tests(void)
{
    test_authdata_assertion();
    test_authdata_attestation();
    test_authdata_too_short();
    test_authdata_credid_overflow();
    test_authdata_null_out();
}
