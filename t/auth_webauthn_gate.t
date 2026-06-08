use lib 't/lib';
use Test::Nginx::Socket 'no_plan';
use WebAuthn;

no_shuffle();
run_tests();

__DATA__

=== gate: valid JWT Cookie yields 200 + exposed user variables
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
        add_header X-WebAuthn-User $webauthn_user_id always;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- more_headers eval
"Cookie: webauthn_session=" . WebAuthn::mint_jwt(sub => "alice")
--- request
GET /protected.txt
--- error_code: 200
--- response_headers
X-WebAuthn-User: alice
--- response_body_like: SECRET-OK



=== gate: no Cookie is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- request
GET /protected.txt
--- error_code: 401



=== gate: expired JWT is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- more_headers eval
"Cookie: webauthn_session=" . WebAuthn::mint_jwt(sub => "alice", exp => time - 10)
--- request
GET /protected.txt
--- error_code: 401



=== gate: alg=none JWT is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- more_headers eval
"Cookie: webauthn_session=" . WebAuthn::mint_jwt(sub => "alice", alg => "none")
--- request
GET /protected.txt
--- error_code: 401



=== gate: tampered-signature JWT is 401
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- more_headers eval
"Cookie: webauthn_session=" . WebAuthn::mint_jwt(sub => "alice", tamper => 1)
--- request
GET /protected.txt
--- error_code: 401



=== gate: unauthenticated with signin_url set is a 302 redirect
--- http_config
    auth_webauthn_challenge_zone webauthn:1m;
--- config
    include $TEST_NGINX_CONF_DIR/server.conf;
    auth_webauthn_jwt_secret_file $TEST_NGINX_CONF_DIR/jwt.key;
    location = /protected.txt {
        root html;
        auth_webauthn on;
        auth_webauthn_signin_url /login;
    }
--- user_files
>>> protected.txt
SECRET-OK
--- request
GET /protected.txt
--- error_code: 302
--- response_headers_like
Location: https?://[^/]+/login
