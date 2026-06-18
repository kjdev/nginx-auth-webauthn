#!/bin/sh
# Generate the session-JWT HMAC secret at container start, so a real secret is
# never committed to the repository (a committed sample secret lets anyone forge
# a valid session JWT and bypass WebAuthn entirely). Run by the nginx official
# entrypoint via /docker-entrypoint.d before nginx starts.
#
# A fresh random secret on each start is fine for an example: existing session
# cookies simply stop validating after a restart.
set -e

key_file=/etc/nginx/webauthn/jwt.key

if [ ! -s "$key_file" ]; then
    mkdir -p "$(dirname "$key_file")"
    # No openssl CLI in the runtime image; read 32 random bytes from the kernel
    # and hex-encode them with busybox od.
    head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' > "$key_file"
    chmod 600 "$key_file"
    echo "$0: generated a random session-JWT secret at $key_file"
fi
