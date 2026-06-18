package WebAuthn;

# Integration test helper. Uses pure Perl plus shell-outs to existing tools
# (t/data/webauthn_tool.py, auth-webauthn-admin) to perform ceremonies that
# involve a dynamic challenge and to mint JWTs for gate verification.

use strict;
use warnings;

use IO::Socket::INET;
use File::Temp ();
use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(hmac_sha256);
use Test::Nginx::Util ();

my $RP_ID  = 'localhost';
my $ORIGIN = 'http://localhost:8080';
my $REDIS  = '127.0.0.1:6379';

# Keep File::Temp objects alive for the whole process: their paths are handed
# out and used later, but the secret key files must still be removed when the
# test process exits (File::Temp unlinks on destruction by default).
my @TEMP_FILES;

sub _tool { return "$ENV{TEST_NGINX_DATA_DIR}/webauthn_tool.py"; }
sub _admin { return $ENV{TEST_NGINX_ADMIN_BIN}; }
sub _port { return $Test::Nginx::Util::ServerPort; }

sub _b64url {
    my $s = encode_base64($_[0], '');
    $s =~ tr{+/}{-_};
    $s =~ s/=+$//;
    return $s;
}

# A 32-byte base64url challenge not issued by the server (for unknown/expired tests).
sub rand_challenge {
    my $raw = join '', map { chr(int(rand(256))) } 1 .. 32;
    return _b64url($raw);
}

# True if 6379 is listening. Used to decide whether to skip Redis-dependent blocks.
sub redis_up {
    my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 6379,
                                  Proto => 'tcp', Timeout => 0.3);
    return 0 unless $s;
    close $s;
    return 1;
}

# Generate an ES256 key + credential id. Returns ($cid, $key_pem_path).
# The key file is kept alive via @TEMP_FILES and removed at process exit.
sub keygen {
    my $tmp = File::Temp->new(SUFFIX => '.pem');
    push @TEMP_FILES, $tmp;
    my $key = $tmp->filename;
    my $cid = `python3 @{[_tool]} keygen --out $key`;
    die "keygen failed" if $? != 0;
    chomp $cid;
    return ($cid, $key);
}

# Generate an attestation and seed it into Redis via the admin CLI register.
sub seed {
    my (%opt) = @_;
    my $user = $opt{user} // 'alice';
    my $cid  = $opt{cid}  or die "seed: cid required";
    my $key  = $opt{key}  or die "seed: key required";

    my $att = File::Temp->new(SUFFIX => '.json');
    push @TEMP_FILES, $att;
    my $att_path = $att->filename;
    system("python3 @{[_tool]} attestation --key $key --cid $cid"
           . " --rp-id $RP_ID --origin $ORIGIN > $att_path") == 0
        or die "attestation failed";

    my $rc = system(_admin, 'register', "--user-id=$user",
                    "--response-file=$att_path", "--rp-id=$RP_ID",
                    '--redis', $REDIS);
    die "admin register failed (rc=$rc)" if $rc != 0;
    return 1;
}

# Fetch one challenge from the running server and return it as a base64url string.
sub fetch_challenge {
    my $port = _port();
    my $sock = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                     PeerPort => $port, Proto => 'tcp',
                                     Timeout => 2)
        or die "challenge fetch: connect $port failed: $!";
    print $sock "GET /webauthn/challenge HTTP/1.0\r\n"
              . "Host: localhost\r\n\r\n";
    local $/;
    my $resp = <$sock>;
    close $sock;
    my ($body) = $resp =~ /\r\n\r\n(.*)$/s;
    my ($ch) = ($body // '') =~ /"challenge"\s*:\s*"([^"]+)"/;
    die "challenge not found in response" unless $ch;
    return $ch;
}

# Build the POST body (Assertion JSON string) for /webauthn/verify.
# opt: key, cid (required), sign_count, type, bad_origin, bad_rpid, tamper_sig,
#      challenge (fetched via fetch_challenge when omitted).
sub assertion_body {
    my (%opt) = @_;
    my $key = $opt{key} or die "assertion_body: key required";
    my $cid = $opt{cid} or die "assertion_body: cid required";
    my $ch  = $opt{challenge} // fetch_challenge();

    my @args = ('python3', _tool(), 'assertion', '--key', $key,
                '--cid', $cid, '--rp-id', $RP_ID, '--origin', $ORIGIN,
                '--challenge', $ch);
    push @args, '--sign-count', $opt{sign_count} if defined $opt{sign_count};
    push @args, '--type', $opt{type}             if defined $opt{type};
    push @args, '--bad-origin'                   if $opt{bad_origin};
    push @args, '--bad-rpid'                     if $opt{bad_rpid};
    push @args, '--tamper-sig'                   if $opt{tamper_sig};
    push @args, '--no-uv'                        if $opt{no_uv};

    open(my $p, '-|', @args) or die "assertion spawn failed: $!";
    local $/;
    my $body = <$p>;
    close $p;
    die "assertion failed" if $? != 0;
    chomp $body;
    return $body;
}

# Build an Assertion and return it as "POST /webauthn/verify\n<body>"
# (for Test::Nginx's `--- request_eval`, evaluated at runtime after the server starts).
sub verify_request {
    my (%opt) = @_;
    my $body = assertion_body(%opt);
    return "POST /webauthn/verify\n$body";
}

# POST a verify body to the running server and return the HTTP status code.
# Used for the "first consumption" step of replay tests.
sub post_verify {
    my ($body) = @_;
    my $port = _port();
    my $sock = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                     PeerPort => $port, Proto => 'tcp',
                                     Timeout => 2)
        or die "post_verify: connect $port failed: $!";
    print $sock "POST /webauthn/verify HTTP/1.0\r\n"
              . "Host: localhost\r\n"
              . "Content-Type: application/json\r\n"
              . "Content-Length: " . length($body) . "\r\n\r\n"
              . $body;
    local $/;
    my $resp = <$sock>;
    close $sock;
    my ($status) = $resp =~ m{^HTTP/\d\.\d\s+(\d+)};
    return $status;
}

# Contents of jwt_secret_file (t/conf/jwt.key). The HS256 HMAC key.
sub secret {
    my $path = "$ENV{TEST_NGINX_CONF_DIR}/jwt.key";
    open(my $fh, '<', $path) or die "open $path: $!";
    local $/;
    my $s = <$fh>;
    close $fh;
    $s =~ s/\s+$//;
    return $s;
}

# Mint an HS256 session JWT. Used for gate (access_handler) verification.
# opt: sub, cid, exp (absolute epoch, defaults to now+3600), alg ('HS256'|'none'),
#      aud (defaults to 'localhost'), iss (defaults to 'nginx-webauthn'),
#      tamper (corrupt the last byte of the signature).
sub mint_jwt {
    my (%opt) = @_;
    my $alg = $opt{alg} // 'HS256';
    my $now = time;
    my $exp = defined $opt{exp} ? $opt{exp} : $now + 3600;
    my $sub = $opt{sub} // 'alice';
    my $cid = $opt{cid} // 'Y3JlZA';
    my $aud = $opt{aud} // 'localhost';
    my $iss = $opt{iss} // 'nginx-webauthn';

    my $header  = qq({"alg":"$alg","typ":"JWT"});
    my $payload = qq({"iss":"$iss","aud":"$aud","sub":"$sub",)
                . qq("cid":"$cid","iat":$now,"exp":$exp,"jti":"dGVzdGp0aQ"});

    my $signing = _b64url($header) . '.' . _b64url($payload);

    if ($alg eq 'none') {
        return $signing . '.';
    }

    my $raw = hmac_sha256($signing, secret());
    if ($opt{tamper}) {
        # Flip a whole byte before encoding. Corrupting the last base64url
        # character would only change padding bits ~1/16 of the time, leaving
        # the decoded HMAC (and thus the signature) unchanged.
        substr($raw, 0, 1) = chr(ord(substr($raw, 0, 1)) ^ 0xFF);
    }
    return "$signing." . _b64url($raw);
}

1;
