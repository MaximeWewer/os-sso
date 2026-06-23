#!/bin/sh
# Captive Portal SSO end-to-end test (VM-local). Validates the providers API and the
# CaptivePortalAuthorizer security gates, then attempts a real configd allow.
set -e
H=/home/vagrant/os-sso/test/vagrant
GUI=https://127.0.0.1
pass=0; fail=0

echo ">>> case A: /api/sso/portal/providers returns the cp providers (JSON + CORS)"
code=$(curl -ks -o /tmp/cp-prov.json -w '%{http_code}' "$GUI/api/sso/portal/providers")
cors=$(curl -ksI "$GUI/api/sso/portal/providers" | grep -i 'access-control-allow-origin' | tr -d '\r')
if [ "$code" = "200" ] && grep -q 'login_uri' /tmp/cp-prov.json; then
    echo "  PASS providers endpoint 200 + JSON ($(grep -o 'login_uri' /tmp/cp-prov.json | wc -l | tr -d ' ') entries)"; pass=$((pass+1))
else
    echo "  FAIL providers endpoint (code=$code)"; fail=$((fail+1)); fi
if [ -n "$cors" ]; then echo "  PASS CORS header present ($cors)"; pass=$((pass+1)); else echo "  FAIL no CORS header"; fail=$((fail+1)); fi

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

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
