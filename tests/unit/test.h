/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * Shared harness for the ngx_auth_webauthn unit tests.  Each module under
 * test contributes a run_*_tests() entry point; test_main.c owns the counters
 * and main().  Plain assert-style checks, no external test framework.
 */

#ifndef NGX_AUTH_WEBAUTHN_TEST_H
#define NGX_AUTH_WEBAUTHN_TEST_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <string.h>

extern int  tests_run;
extern int  tests_failed;

#define CHECK(cond, label)                                                   \
    do {                                                                     \
        tests_run++;                                                         \
        if (cond) {                                                          \
            printf("ok   - %s\n", (label));                                  \
        } else {                                                             \
            tests_failed++;                                                  \
            printf("FAIL - %s\n", (label));                                  \
        }                                                                    \
    } while (0)

/* Hex-encode in[0..n) into out (out must hold n*2 + 1 bytes). */
void to_hex(const u_char *in, size_t n, char *out);

void run_hash_tests(void);
void run_authdata_tests(void);
void run_clientdata_tests(void);
void run_cose_tests(void);
void run_assertion_tests(void);

#endif /* NGX_AUTH_WEBAUTHN_TEST_H */
