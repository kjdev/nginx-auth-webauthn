use lib 't/lib';
use Test::Nginx::Socket 'no_plan';
use WebAuthn;

no_shuffle();
run_tests();

__DATA__

=== challenge: 200 and JSON shape
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
