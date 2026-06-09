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

=== verify: valid Assertion yields 200 + Set-Cookie + user
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
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
--- response_headers_like
Set-Cookie: webauthn_session=[A-Za-z0-9_.-]+; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
--- response_body_like: ^\{"ok":true,"user_id":"alice","exp":\d+\}$



=== verify: empty body is 401
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- request
POST /webauthn/verify
--- error_code: 401
--- response_body_like: "ok":false,"error":"E_ASSERTION"



=== verify: malformed JSON is 401
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- more_headers
Content-Type: application/json
--- request
POST /webauthn/verify
this-is-not-json
--- error_code: 401



=== verify: unissued challenge is 401
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID,
                         challenge => WebAuthn::rand_challenge())
--- error_code: 401



=== verify: userVerification required rejects an assertion without the UV flag
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_user_verification required;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, no_uv => 1)
--- error_code: 401
--- response_body_like: "ok":false,"error":"E_ASSERTION"



=== verify: userVerification required accepts an assertion with the UV flag
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    auth_webauthn_user_verification required;
    location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
    location = /webauthn/verify   { auth_webauthn_verify_handler on; }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- more_headers
Content-Type: application/json
--- request_eval
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, sign_count => 7)
--- error_code: 200
--- response_body_like: ^\{"ok":true,"user_id":"alice","exp":\d+\}$
