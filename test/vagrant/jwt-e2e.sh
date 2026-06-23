#!/bin/sh
# JWT forward-auth end-to-end test, fully local in the VM (the source gate is
# REMOTE_ADDR, which for a localhost curl is 127.0.0.1). Run as root in the VM.
set -e
H=/home/vagrant/os-sso/test/vagrant
W=/tmp/jwt-e2e
GUI=https://127.0.0.1
HDR='X-Auth-Request-Jwt'
pass=0; fail=0
mkdir -p "$W"

echo ">>> generating RSA keypair"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$W/priv.pem" 2>/dev/null
openssl rsa -in "$W/priv.pem" -pubout -out "$W/pub.pem" 2>/dev/null

code() { # method url [header]  -> prints http_code
    if [ -n "$3" ]; then
        curl -ks -o /dev/null -w '%{http_code}' -H "$3" "$2"
    else
        curl -ks -o /dev/null -w '%{http_code}' "$2"
    fi
}
check() { # label expected actual
    if [ "$2" = "$3" ]; then echo "  PASS $1 ($3)"; pass=$((pass+1));
    else echo "  FAIL $1 (expected $2, got $3)"; fail=$((fail+1)); fi
}

# --- positive: trusted source + valid token -----------------------------------
echo ">>> case 1: valid token from trusted 127.0.0.1"
JWT_TRUSTED='127.0.0.1' JWT_PUBKEY="$(cat "$W/pub.pem")" php "$H/add_jwt_authserver.php" >/dev/null
TOKEN=$(PRIV="$W/priv.pem" php "$H/sign_jwt.php")
c=$(code GET "$GUI/api/sso/jwt/login?provider=jwttest" "$HDR: $TOKEN")
check "valid token -> 302 redirect" 302 "$c"
if php "$H/dump_user.php" jwtuser 2>/dev/null | grep -q 'uid='; then
    echo "  PASS user 'jwtuser' provisioned in config.xml"; pass=$((pass+1))
else
    echo "  FAIL user 'jwtuser' not provisioned"; fail=$((fail+1)); fi

# --- session works: reuse the cookie on an authenticated page -----------------
echo ">>> case 2: established session reaches an authenticated page"
curl -ks -c "$W/jar" -o /dev/null -H "$HDR: $TOKEN" "$GUI/api/sso/jwt/login?provider=jwttest"
# /api/core/menu/search needs a session; 200 = authenticated, 40x = not.
c=$(curl -ks -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")
check "session cookie authenticated" 200 "$c"

# --- negative: untrusted source ----------------------------------------------
echo ">>> case 3: same token but source not in trusted list -> rejected"
JWT_TRUSTED='10.99.0.0/16' JWT_PUBKEY="$(cat "$W/pub.pem")" php "$H/add_jwt_authserver.php" >/dev/null
c=$(code GET "$GUI/api/sso/jwt/login?provider=jwttest" "$HDR: $TOKEN")
check "untrusted source -> 400" 400 "$c"

# --- negative: tampered token (signature) ------------------------------------
echo ">>> case 4: tampered token -> rejected"
JWT_TRUSTED='127.0.0.1' JWT_PUBKEY="$(cat "$W/pub.pem")" php "$H/add_jwt_authserver.php" >/dev/null
BAD="${TOKEN}x"
c=$(code GET "$GUI/api/sso/jwt/login?provider=jwttest" "$HDR: $BAD")
check "bad signature -> 400" 400 "$c"

# --- negative: wrong audience -------------------------------------------------
echo ">>> case 5: token with wrong aud -> rejected"
WRONGAUD=$(PRIV="$W/priv.pem" JWT_AUD='someone-else' php "$H/sign_jwt.php")
c=$(code GET "$GUI/api/sso/jwt/login?provider=jwttest" "$HDR: $WRONGAUD")
check "wrong aud -> 400" 400 "$c"

# --- negative: no header ------------------------------------------------------
echo ">>> case 6: no token header -> rejected"
c=$(code GET "$GUI/api/sso/jwt/login?provider=jwttest")
check "missing header -> 400" 400 "$c"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
