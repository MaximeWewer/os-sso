#!/usr/bin/env bash
# End-to-end test of the OIDC browser flow and the surrounding features, driven from
# the HOST (it is the side that has the forwarded WebGUI port and resolves the IdP
# hostname -- inside the VM, "localhost:8444" is nothing).
#
# Prerequisites:
#   an IdP stack from test/idp, set up with a matching SP_BASE
#   vagrant up                                                        (SSO_GUI_PORT matching)
#   an '<idp>' oidc auth server registered in the VM (see add_authserver.php)
#
# Usage: SSO_GUI_PORT=8444 ./oidc.sh            (or through ./run-all.sh)
set -uo pipefail
cd "$(dirname "$0")"

PORT="${SSO_GUI_PORT:-8443}"
# The lab can be reached two ways: the NAT-forwarded port, or the host-only address
# (test/Vagrantfile). SSO_GUI_URL picks; it must match the provider Base URL, or the
# callback lands on a different origin than the login and the session is not found.
GUI="${SSO_GUI_URL:-https://localhost:$PORT}"
IDP="${IDP:-keycloak}"
PROVIDER="${SSO_PROVIDER:-keycloak}"
IDP_USER="${IDP_USER:-kctest}"
IDP_PASS="${IDP_PASS:-Test12345!}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0; fail=0

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || ko "$1 (expected $2, got $3)"; }
# Run as root in the VM. The command goes through "sh -c" so globs expand as root:
# the os-sso state directories are 0700, so the vagrant user cannot even expand a
# path inside them (which is the point).
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }
# Core redirects an unauthenticated caller to the login page (302) rather than
# answering 403, so "is this session live" is 200-or-not, not a specific code.
authed(){ [ "$(curl -sk -b "$1" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")" = "200" ]; }
is_live(){ authed "$1" && ok "$2" || ko "$2 (session is not authenticated)"; }
not_live(){ authed "$1" && ko "$2 (session still authenticated)" || ok "$2"; }

# The whole browser ceremony, IdP dialect included, lives in lib/idp_login.py.
login() {
    python3 "$(dirname "$0")/lib/idp_login.py" --gui "$GUI" --provider "$PROVIDER" \
        --protocol oidc --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" \
        --jar "$1" 2>/dev/null | tail -1
}

echo "=== os-sso OIDC end-to-end ($GUI, idp=$IDP, provider=$PROVIDER) ==="

# --- 1. the ceremony itself --------------------------------------------------
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
echo ">>> case 1: full browser login"
check "callback -> 302" 302 "$(login "$W/jar")"
is_live "$W/jar" "session reaches an authenticated API"

# --- 2. the authorization request ---------------------------------------------
echo ">>> case 2: authorization request parameters"
AUTHZ=$(curl -sk -o /dev/null -w '%{redirect_url}' "$GUI/api/sso/oidc/login?provider=$PROVIDER")
# Percent-encode $GUI the way it appears inside the authorization URL, so the
# assertion follows SSO_GUI_URL instead of assuming one deployment.
GUI_ENC=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]+"/api/sso/oidc/callback",safe=""))' "$GUI")
case "$AUTHZ" in
    *"redirect_uri=$GUI_ENC"*) ok "redirect_uri built from the configured Base URL" ;;
    *) ko "redirect_uri (got: $(echo "$AUTHZ" | tr '&' '\n' | grep redirect_uri))" ;;
esac
case "$AUTHZ" in *code_challenge_method=S256*) ok "PKCE S256 requested" ;; *) ko "no PKCE challenge" ;; esac
case "$AUTHZ" in *state=*nonce=*|*nonce=*state=*) ok "state + nonce present" ;; *) ko "state/nonce missing" ;; esac

# --- 3. Host header hardening --------------------------------------------------
echo ">>> case 3: a forged Host header cannot steer the redirect_uri"
FORGED=$(curl -sk -H 'Host: evil.example' -o /dev/null -w '%{redirect_url}' \
    "$GUI/api/sso/oidc/login?provider=$PROVIDER")
case "$FORGED" in
    *evil.example*) ko "forged Host reached the IdP redirect_uri" ;;
    *) ok "forged Host ignored (Base URL wins)" ;;
esac
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_base_url=" >/dev/null
FORGED2=$(curl -sk -H 'Host: evil.example' -o /dev/null -w '%{redirect_url}' \
    "$GUI/api/sso/oidc/login?provider=$PROVIDER")
case "$FORGED2" in
    *evil.example*) ko "forged Host accepted when no Base URL is configured" ;;
    *) ok "forged Host refused by the auto-detect fallback too" ;;
esac
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_base_url=$GUI" >/dev/null

# --- 4. diagnostics ------------------------------------------------------------
echo ">>> case 4: diagnostics API (authenticated)"
curl -sk -b "$W/jar" -o "$W/prov.json" -w '' "$GUI/api/sso/diagnostics/providers"
grep -q '"name":' "$W/prov.json" && ok "providers listed" || ko "providers endpoint ($(head -c 120 "$W/prov.json"))"
grep -qE 'oidc.{0,2}callback' "$W/prov.json" && ok "IdP URLs reported" || ko "no IdP URLs in the payload"
curl -sk -b "$W/jar" -o "$W/check.json" "$GUI/api/sso/diagnostics/check/$PROVIDER"
grep -q '"status":"ok"' "$W/check.json" && ok "live IdP check ok" || ko "IdP check ($(head -c 160 "$W/check.json"))"
grep -q '"signing_keys":[1-9]' "$W/check.json" && ok "JWKS keys counted" || ko "no signing keys reported"
curl -sk -b "$W/jar" -o "$W/sess.json" "$GUI/api/sso/diagnostics/sessions"
grep -q "$IDP_USER" "$W/sess.json" && ok "the open session is listed" || ko "session not listed ($(head -c 160 "$W/sess.json"))"
check "diagnostics page renders" 200 \
    "$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/ui/sso/diagnostics")"
check "settings page renders" 200 \
    "$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/ui/sso/settings")"
check "settings API returns the model" 200 \
    "$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/api/sso/settings/get")"
ANON=$(curl -sk -o "$W/anon.json" -w '%{http_code}' "$GUI/api/sso/diagnostics/providers")
if [ "$ANON" != "200" ] || ! grep -q '"name":' "$W/anon.json"; then
    ok "diagnostics not served without a session ($ANON)"
else
    ko "diagnostics served to an anonymous caller"
fi

# --- 5. logout CSRF guard ------------------------------------------------------
echo ">>> case 5: logout is not triggerable cross-site"
curl -sk -b "$W/jar" -H 'Sec-Fetch-Site: cross-site' -o "$W/logout.html" \
    -w '' "$GUI/api/sso/logout"
grep -q 'logout_token' "$W/logout.html" && ok "cross-site logout asks for confirmation" \
    || ko "cross-site logout was not intercepted"
check "same-origin logout proceeds" 302 \
    "$(curl -sk -b "$W/jar" -H 'Sec-Fetch-Site: same-origin' -o /dev/null -w '%{http_code}' "$GUI/api/sso/logout")"

# --- 6. rate limiting ----------------------------------------------------------
echo ">>> case 6: pre-auth rate limit"
limited=0
for _ in $(seq 1 26); do
    c=$(curl -sk -o /dev/null -w '%{http_code}' "$GUI/api/sso/oidc/login?provider=$PROVIDER")
    [ "$c" = "400" ] && limited=$((limited+1))
done
[ "$limited" -gt 0 ] && ok "login throttled after the window filled ($limited refused of 26)" \
    || ko "no throttling observed"
# Drop the buckets: the cases below each need to log in, and the window is 60s.
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null

# --- 7. required groups + deprovisioning ---------------------------------------
echo ">>> case 7: required-groups gate"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups=nobody-has-this" >/dev/null
check "login refused when the group is missing" 400 "$(login "$W/jar2")"
not_live "$W/jar2" "no session was opened"

echo ">>> case 8: deprovisioning on a refused login"
# Provision the account with NO privileged group first: os-sso refuses to disable a
# privileged one (anti-lockout), which is asserted separately below.
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups= sso_default_groups= sso_deprovision=0" >/dev/null
vm "php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null
login "$W/jar3" >/dev/null
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups=nobody-has-this sso_deprovision=1" >/dev/null
login "$W/jar3b" >/dev/null
DUMP=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php $IDP_USER")
case "$DUMP" in
    *disabled=1*) ok "the refused account was disabled ($DUMP)" ;;
    *) ko "account not disabled ($DUMP)" ;;
esac

echo ">>> case 8b: a privileged account is never deprovisioned (anti-lockout)"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups= sso_default_groups=admins sso_deprovision=0" >/dev/null
vm "php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null
login "$W/jar3c" >/dev/null
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups=nobody-has-this sso_deprovision=1" >/dev/null
login "$W/jar3d" >/dev/null
DUMP=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php $IDP_USER")
case "$DUMP" in
    *disabled=0*) ok "the admins-group account was left enabled ($DUMP)" ;;
    *) ko "a privileged account was disabled ($DUMP)" ;;
esac
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups= sso_deprovision=0" >/dev/null
vm "php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null

# --- 9. absolute session lifetime ----------------------------------------------
echo ">>> case 9: maximum session lifetime"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_session_lifetime=1" >/dev/null
check "login ok with a 1s lifetime" 302 "$(login "$W/jar4")"
is_live "$W/jar4" "the fresh session authenticates"
sleep 2
vm "/usr/local/opnsense/scripts/OPNsense/SSO/expire_sessions.php"
not_live "$W/jar4" "the expired session no longer authenticates"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_session_lifetime=0" >/dev/null

# --- 10. back-channel logout ----------------------------------------------------
echo ">>> case 10: back-channel logout endpoint"
check "garbage logout_token refused" 400 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -d 'logout_token=not-a-jwt' "$GUI/api/sso/oidc/backchannel?provider=$PROVIDER")"
check "no logout_token refused" 400 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$GUI/api/sso/oidc/backchannel?provider=$PROVIDER")"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
