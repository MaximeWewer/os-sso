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
# The lab can be reached two ways: the NAT-forwarded port, or the host-only address
# (test/Vagrantfile). SSO_GUI_URL picks; it must match the provider Base URL, or the
# callback lands on a different origin than the login and the session is not found.
GUI="${SSO_GUI_URL:-https://localhost:$PORT}"
IDP="${IDP:-keycloak}"
PROVIDER="${SSO_PROVIDER:-keycloak}"
IDP_USER="${IDP_USER:-kctest}"
IDP_PASS="${IDP_PASS:-Test12345!}"
# A zone bound to the provider under test: the zone<->provider binding is a gate, so
# a zone that lists another provider would (correctly) refuse this login.
ZONE=""
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

echo "=== os-sso Captive Portal from a client browser ($GUI, idp=$IDP) ==="

ZONE=$(vm "env CP_DESC=sso-portal-$PROVIDER CP_AUTH=$PROVIDER php /home/vagrant/os-sso/test/vagrant/add_cp_zone.php")
case "$ZONE" in
    [0-9]*) echo ">>> using captive portal zone $ZONE (bound to $PROVIDER)" ;;
    *) echo "  FAIL could not create a captive portal zone ($ZONE)"; exit 1 ;;
esac

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
# Match this zone specifically rather than the last authorization in a log every
# other suite also writes to. grep -av COMMAND: sudo logs our own probe into the
# very file we are reading.
HITS=$(vm "grep -a os-sso /var/log/system/system_*.log | grep -av COMMAND | grep -ac \"in zone $ZONE from\"")
[ "${HITS:-0}" -gt 0 ] 2>/dev/null \
    && ok "the firewall logged the authorization for zone $ZONE" \
    || ko "no authorization for zone $ZONE in the log (hits=$HITS)"

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
