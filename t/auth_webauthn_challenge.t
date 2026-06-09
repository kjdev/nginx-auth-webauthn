use lib 't/lib';
use Test::Nginx::Socket 'no_plan';
use WebAuthn;

no_shuffle();

# The challenge handler stores the nonce in Redis (SET ... EX), so the whole
# file needs a live Redis. TAP-skip when it is absent. Avoid plan(skip_all),
# which conflicts with no_plan; emit the TAP skip-all line directly and exit
# via POSIX::_exit to avoid END (a double plan).
unless (WebAuthn::redis_up()) {
    print "1..0 # SKIP Redis 127.0.0.1:6379 not available\n";
    require POSIX;
    POSIX::_exit(0);
}

run_tests();

__DATA__

=== challenge: 200 and JSON shape
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- request
GET /webauthn/challenge
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body_like: ^\{"challenge":"[A-Za-z0-9_-]{43}","rpId":"localhost","timeout":60000,"userVerification":"preferred","allowCredentials":\[\]\}$



=== challenge: challenge_ttl is reflected in timeout
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_challenge_ttl 30;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- request
GET /webauthn/challenge
--- error_code: 200
--- response_body_like: "timeout":30000,
