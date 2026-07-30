#!/bin/sh
# Captive Portal SSO end-to-end test (VM-local). Validates the providers API and the
# CaptivePortalAuthorizer security gates, then attempts a real configd allow.
set -e
H=/home/vagrant/os-sso/test/vagrant
GUI=https://127.0.0.1
pass=0; fail=0

echo ">>> case A: /api/sso/portal/providers returns the cp providers"
code=$(curl -ks -o /tmp/cp-prov.json -w '%{http_code}' "$GUI/api/sso/portal/providers")
if [ "$code" = "200" ] && grep -q 'login_uri' /tmp/cp-prov.json; then
    echo "  PASS providers endpoint 200 + JSON ($(grep -o 'login_uri' /tmp/cp-prov.json | wc -l | tr -d ' ') entries)"; pass=$((pass+1))
else
    echo "  FAIL providers endpoint (code=$code)"; fail=$((fail+1)); fi

# The portal page lives on port 8000+zoneid, so it IS a different origin and does need
# CORS -- but only the firewall's own portal origins get it. A wildcard used to let any
# site on the internet read which authentication servers this firewall has.
echo ">>> case A2: CORS is reflected for a portal origin only"
acao() { curl -ksI ${1:+-H "Origin: $1"} "$GUI/api/sso/portal/providers" \
    | grep -i 'access-control-allow-origin' | tr -d '\r' | sed 's/^[^:]*: *//'; }
own=$(acao "https://127.0.0.1:8000")
foreign=$(acao "https://evil.example")
none=$(acao "")
if [ "$own" = "https://127.0.0.1:8000" ]; then
    echo "  PASS a portal origin is reflected ($own)"; pass=$((pass+1))
else
    echo "  FAIL portal origin not reflected (got '$own')"; fail=$((fail+1)); fi
if [ -z "$foreign" ]; then
    echo "  PASS a foreign origin gets no CORS header"; pass=$((pass+1))
else
    echo "  FAIL foreign origin was allowed ($foreign)"; fail=$((fail+1)); fi
if [ -z "$none" ]; then
    echo "  PASS no Origin means no CORS header"; pass=$((pass+1))
else
    echo "  FAIL a header was sent without an Origin ($none)"; fail=$((fail+1)); fi

echo ">>> creating CP zones (bound to keycloak; one with enforce-group)"
ZONE_OK=$(CP_DESC='sso-cp-test' CP_AUTH='keycloak' php "$H/add_cp_zone.php")
ZONE_ENF=$(CP_DESC='sso-cp-enforce' CP_AUTH='keycloak' CP_ENFORCE='admins' php "$H/add_cp_zone.php")
echo "  zone(ok)=$ZONE_OK  zone(enforce)=$ZONE_ENF"

echo ">>> case B: authorizer security gates + real allow"
php "$H/cp_test.php" "$ZONE_OK" "$ZONE_ENF"
rc=$?

# fold cp_test result into the tally
res=$(php "$H/cp_test.php" "$ZONE_OK" "$ZONE_ENF" 2>/dev/null | sed -n 's/^RESULT \([0-9]*\) passed, \([0-9]*\) failed/\1 \2/p')
p2=$(echo "$res" | cut -d' ' -f1); f2=$(echo "$res" | cut -d' ' -f2)
pass=$((pass + ${p2:-0})); fail=$((fail + ${f2:-0}))

# An enabled zone intercepts http/https on the LAN interface -- the origin the host-side
# suites use -- so hand it back the way we found it. The zones survive for reuse.
php "$H/disable_cp_zones.php" >/dev/null 2>&1
configctl captiveportal reconfigure >/dev/null 2>&1

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
