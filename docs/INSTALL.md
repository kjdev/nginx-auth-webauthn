# Installation Guide

## Prerequisites

JSON processing and JWT processing are handled by the bundled git submodules (`nxe-json` / `nxe-jwx`), which depend on jansson and OpenSSL respectively. See the clone steps below for fetching the submodules. System libraries you must provide:

- [OpenSSL](https://www.openssl.org/) (>=3.0) — signature verification, JWT signing, hashing, and randomness. COSE public-key conversion uses the OpenSSL 3.0 API (`EVP_PKEY_fromdata` family)
- [jansson](https://www.digip.org/jansson/) — JSON parser (the actual dependency of nxe-json)
- [hiredis](https://github.com/redis/hiredis) (>=1.0) — Redis client
- [libcbor](https://github.com/PJK/libcbor) (>=0.10) — required **only for the bundled CLI** (parsing attestationObject / COSE). Not needed to build the NGINX module itself
- NGINX (>=1.22) — source code

### Package installation examples

#### Debian/Ubuntu

```bash
apt-get install -y libssl-dev libjansson-dev libhiredis-dev libcbor-dev
```

#### RHEL/CentOS/Fedora

```bash
dnf install -y openssl-devel jansson-devel hiredis-devel libcbor-devel
```

#### Alpine Linux

```bash
apk add --no-cache openssl-dev jansson-dev hiredis-dev libcbor-dev
```

### Redis server

Redis 6.x or later (or Valkey) is required for operation and testing. During development, starting it with Docker is the easiest approach.

```bash
docker run --rm -d -p 6379:6379 --name webauthn-redis redis:7-alpine
```

## Building from source

### Step 1: Clone the repository

Because it includes `nxe-json` / `nxe-jwx` as submodules, clone with `--recursive`.

```bash
git clone --recursive https://github.com/kjdev/nginx-auth-webauthn
cd nginx-auth-webauthn
```

If you have already cloned it, fetch the submodules.

```bash
git submodule update --init --recursive
```

### Step 2: Build the NGINX module

Obtain the nginx source matching the version you use and configure within the source tree. A dynamic module (`--add-dynamic-module`) is recommended. Refer to the output of `nginx -V` for the configure arguments so they match your running nginx.

```bash
# Dynamic linking (recommended)
./configure --with-compat --add-dynamic-module=/path/to/nginx-auth-webauthn
make modules
# Produces: objs/ngx_http_auth_webauthn_module.so

# Static linking
./configure --add-module=/path/to/nginx-auth-webauthn
make
```

Load a dynamic module explicitly at the top of `nginx.conf`:

```nginx
load_module modules/ngx_http_auth_webauthn_module.so;
```

When built with `--with-compat`, the module can also be loaded into other nginx builds (including NGINX Plus) that were built with the same `--with-compat`.

### Step 3: Build the bundled CLI

```bash
cd tools/admin && make
```

This produces `tools/admin/auth-webauthn-admin`. To install it (the default `PREFIX` is `/usr/local`):

```bash
make install                      # to /usr/local/bin (requires privileges)
make install PREFIX=$HOME/.local  # to a user directory
```

## Verifying operation

Steps to verify operation after building:

1. Start Redis
2. Configure NGINX with the `auth_webauthn` directives (see [EXAMPLES.md](EXAMPLES.md) for configuration examples)
3. Register a test credential with the CLI (the registration Python sample `examples/register/` is also available)
4. Authenticate from the browser using `examples/login/`

To try the full E2E in one shot with docker compose: `cd examples && docker compose up --build` (http://localhost:8080).

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Related documents

- [README.md](../README.md) — Overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md) — Directive reference
- [ADMIN_TOOL.md](ADMIN_TOOL.md) — `auth-webauthn-admin` CLI reference
