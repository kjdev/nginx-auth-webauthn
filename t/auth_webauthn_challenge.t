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

our ($CID, $KEY) = WebAuthn::keygen();

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



=== challenge: user_id returns the user's allowCredentials
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "alice", cid => $main::CID, key => $main::KEY);
--- request
GET /webauthn/challenge?user_id=alice
--- error_code: 200
--- response_body_like: "allowCredentials":\[\{"type":"public-key","id":"[A-Za-z0-9_-]+"\}\]\}$



=== challenge: unknown user_id yields an empty allowCredentials (no oracle)
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
--- request
GET /webauthn/challenge?user_id=nobody
--- error_code: 200
--- response_body_like: "allowCredentials":\[\]\}$



=== challenge: percent-encoded user_id is decoded before the Redis lookup
# The admin CLI stores the credential under the decoded id "a@b.com", while the
# client sends it percent-encoded ("a%40b.com"). The handler must decode the
# query arg so the index key matches and allowCredentials is non-empty.
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
    WebAuthn::seed(user => "a\@b.com", cid => $main::CID, key => $main::KEY);
--- request
GET /webauthn/challenge?user_id=a%40b.com
--- error_code: 200
--- response_body_like: "allowCredentials":\[\{"type":"public-key","id":"[A-Za-z0-9_-]+"\}\]\}$



=== challenge: userVerification policy is reflected
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_user_verification required;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- request
GET /webauthn/challenge
--- error_code: 200
--- response_body_like: "userVerification":"required",



=== challenge: rate limit returns 429 past the quota
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_challenge_rate_limit 2 60;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
--- pipelined_requests eval
["GET /webauthn/challenge", "GET /webauthn/challenge", "GET /webauthn/challenge"]
--- error_code eval
[200, 200, 429]



=== challenge: rate-limit counter carries a positive TTL (no orphan)
# INCR and EXPIRE run as one atomic Redis script, so the counter is never left
# without an expiry. Issue one request (counter -> 1, TTL set), then assert via
# redis-cli that the key has a positive TTL rather than -1 (which would lock the
# IP out forever). no_shuffle keeps this block after the issuing request below.
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_challenge_rate_limit 5 60;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    system("redis-cli -p 6379 flushall >/dev/null 2>&1");
--- request
GET /webauthn/challenge
--- error_code: 200
--- response_body_like: "challenge"



=== challenge: assert the TTL set by the previous request
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    location = /webauthn/challenge {
        auth_webauthn_challenge_handler on;
    }
--- init
    my $ttl = `redis-cli -p 6379 TTL webauthn:ratelimit:challenge:127.0.0.1`;
    chomp $ttl;
    Test::More::cmp_ok($ttl + 0, '>', 0,
        'rate-limit counter has a positive TTL (no orphan)');
--- request
GET /webauthn/challenge
--- error_code: 200
