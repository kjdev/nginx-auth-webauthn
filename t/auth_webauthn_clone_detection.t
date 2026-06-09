use lib 't/lib';
use Test::Nginx::Socket 'no_plan';
use WebAuthn;

no_shuffle();

# TAP-skip the whole file when Redis is absent. Avoid plan(skip_all), which
# conflicts with no_plan; instead emit the TAP skip-all line directly and exit
# via POSIX::_exit to avoid END (a double plan).
unless (WebAuthn::redis_up()) {
    print "1..0 # SKIP Redis 127.0.0.1:6379 not available\n";
    require POSIX;
    POSIX::_exit(0);
}

our ($CID, $KEY) = WebAuthn::keygen();

run_tests();

__DATA__

=== clone strict: sign_count advance is 200 (stored 0 -> 5)
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_clone_detection strict;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, sign_count => 5)
--- error_code: 200



=== clone strict: sign_count regression is 401 (stored 5 > 3, no flushall)
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_clone_detection strict;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, sign_count => 3)
--- error_code: 401



=== clone lax: advance is 200 (stored 0 -> 5)
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_clone_detection lax;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, sign_count => 5)
--- error_code: 200



=== clone lax: regression is still 200 (warning only, no flushall)
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_clone_detection lax;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, sign_count => 3)
--- error_code: 200
