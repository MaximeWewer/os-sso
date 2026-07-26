#!/usr/bin/env bash
# Captive Portal SSO from the client's side, driven from the host.
#
# test/e2e/cp.sh calls the authorizer directly to exercise its gates; this one walks
# the path a captive client actually walks: the portal login link, the IdP, and back
# to a confirmation page -- with the client's own address authorized in the zone.
#
# Prerequisites: a captive portal zone bound to the SSO provider (test/e2e/cp.sh
# creates zone 0 bound to "keycloak"), a running VM, and an IdP stack.
#
# Usage: SSO_GUI_PORT=8444 ./portal.sh
set -uo pipefail
cd "$(dirname "$0")"

PORT="${SSO_GUI_PORT:-8443}"
GUI="https://localhost:$PORT"
IDP="${IDP:-keycloak}"
PROVIDER="${SSO_PROVIDER:-keycloak}"
IDP_USER="${IDP_USER:-kctest}"
IDP_PASS="${IDP_PASS:-Test12345!}"
ZONE="${CP_ZONE:-0}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0; fail=0

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || ko "$1 (expected $2, got $3)"; }
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }

portal_login() { # $1 = zone, $2 = original destination, $3 = body file
    python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol oidc \
        --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$W/jar" \
        --start-url "$GUI/api/sso/oidc/login?provider=$PROVIDER&cp=$1&cpurl=$2" \
        --body "$3" 2>/dev/null | tail -1
}

echo "=== os-sso Captive Portal from a client browser ($GUI, idp=$IDP, zone=$ZONE) ==="

echo ">>> case 1: the portal page lists the SSO providers"
curl -sk -o "$W/prov.json" "$GUI/api/sso/portal/providers"
grep -q 'login_uri' "$W/prov.json" && ok "providers endpoint answers the portal" \
    || ko "no providers ($(head -c 120 "$W/prov.json"))"

echo ">>> case 2: a real SSO login authorizes this client in the zone"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
check "login ends on the portal confirmation page" 200 \
    "$(portal_login "$ZONE" 'example.com/welcome' "$W/done.html")"
grep -q 'Connected' "$W/done.html" 2>/dev/null && ok "page confirms network access" \
    || ko "unexpected confirmation page"
grep -q 'http://example.com/welcome' "$W/done.html" 2>/dev/null \
    && ok "the original destination is offered as a link" \
    || ko "the destination was not carried through"
vm "grep -a 'os-sso cp: authorized' /var/log/system/*.log | tail -1" | grep -q "zone $ZONE" \
    && ok "the firewall logged the authorization" || ko "no authorization in the log"

echo ">>> case 3: an unbound zone is refused"
# Zone 9 does not exist in the lab, so the zone lookup itself must reject it.
check "unknown zone refused" 400 "$(portal_login 9 '' "$W/nope.html")"

echo ">>> case 4: a crafted destination cannot retarget the bounce"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
portal_login "$ZONE" 'javascript:alert(1)' "$W/evil.html" >/dev/null
grep -q 'javascript:' "$W/evil.html" 2>/dev/null \
    && ko "a javascript: destination survived into the page" \
    || ok "the javascript: destination was dropped"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
