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

=== security: origin mismatch is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, bad_origin => 1)
--- error_code: 401



=== security: rpIdHash mismatch is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, bad_rpid => 1)
--- error_code: 401



=== security: tampered signature is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
WebAuthn::verify_request(key => $main::KEY, cid => $main::CID, tamper_sig => 1)
--- error_code: 401



=== security: reusing a challenge makes the second attempt 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
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
my $b = WebAuthn::assertion_body(key => $main::KEY, cid => $main::CID,
                                 sign_count => 9);
my $st = WebAuthn::post_verify($b);
die "replay setup: first POST expected 200, got " . ($st // "?")
    unless defined $st && $st == 200;
"POST /webauthn/verify\n$b"
--- error_code: 401
