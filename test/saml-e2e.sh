#!/usr/bin/env bash
# End-to-end test of the SAML SP, driven from the HOST (see oidc-e2e.sh for why).
#
# Prerequisites: the keycloak IdP stack + setup-keycloak.sh (same SP_BASE), a running
# VM, and a 'keycloak-saml' auth server registered in it.
#
# Usage: SSO_GUI_PORT=8444 ./saml-e2e.sh
set -uo pipefail
cd "$(dirname "$0")"

PORT="${SSO_GUI_PORT:-8443}"
GUI="https://localhost:$PORT"
PROVIDER="${SSO_SAML_PROVIDER:-keycloak-saml}"
KC_BASE="${KC_BASE:-https://keycloak.test:9443/realms/opnsense}"
KC_USER="${KC_USER:-kctest}"
KC_PASS="${KC_PASS:-Test12345!}"
ACS="$GUI/api/sso/saml/acs?provider=$PROVIDER"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0; fail=0

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || ko "$1 (expected $2, got $3)"; }
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }
authed(){ [ "$(curl -sk -b "$1" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")" = "200" ]; }
is_live(){ authed "$1" && ok "$2" || ko "$2 (session is not authenticated)"; }
not_live(){ authed "$1" && ko "$2 (session still authenticated)" || ok "$2"; }

# Pull the SAMLResponse out of Keycloak's auto-submitting form into $2.
extract_response() {
    python3 - "$1" "$2" <<'PY'
import html, re, sys
page = open(sys.argv[1], encoding='utf-8', errors='replace').read()
m = (re.search(r'name="SAMLResponse"[^>]*value="([^"]+)"', page)
     or re.search(r'value="([^"]+)"[^>]*name="SAMLResponse"', page))
open(sys.argv[2], 'w').write(html.unescape(m.group(1)) if m else '')
PY
}

# SP-initiated ceremony up to (not including) the ACS post; response left in $1.
authenticate() {
    local out="$1" kcjar="$W/kcjar" authz action
    rm -f "$kcjar"
    authz=$(curl -sk -o /dev/null -w '%{redirect_url}' "$GUI/api/sso/saml/login?provider=$PROVIDER")
    case "$authz" in https://*) ;; *) : > "$out"; return ;; esac
    curl -sk -c "$kcjar" -L "$authz" -o "$W/kc.html"
    action=$(grep -o 'action="[^"]*"' "$W/kc.html" | head -1 | sed 's/action="//;s/"$//;s/&amp;/\&/g')
    if [ -z "$action" ]; then : > "$out"; return; fi
    curl -sk -b "$kcjar" -c "$kcjar" -o "$W/post.html" \
        -d "username=$KC_USER" -d "password=$KC_PASS" -d 'credentialId=' "$action"
    extract_response "$W/post.html" "$out"
}

echo "=== os-sso SAML end-to-end ($GUI, provider=$PROVIDER) ==="

# --- 1. SP metadata -------------------------------------------------------------
echo ">>> case 1: SP metadata is per-provider"
curl -sk -o "$W/md.xml" -w '' "$GUI/api/sso/saml/metadata?provider=$PROVIDER"
grep -q "entityID=\"$GUI/api/sso/saml/metadata?provider=$PROVIDER\"" "$W/md.xml" \
    && ok "EntityID carries ?provider=" || ko "EntityID ($(grep -o 'entityID="[^"]*"' "$W/md.xml" | head -1))"
grep -q "saml/acs?provider=$PROVIDER" "$W/md.xml" && ok "ACS carries ?provider=" || ko "ACS URL not per-provider"
grep -q "saml/slo?provider=$PROVIDER" "$W/md.xml" && ok "SLO carries ?provider=" || ko "SLO URL not per-provider"

# --- 2. the ceremony ------------------------------------------------------------
echo ">>> case 2: SP-initiated login"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
authenticate "$W/resp.b64"
[ -s "$W/resp.b64" ] && ok "IdP returned a SAMLResponse" || ko "no SAMLResponse from the IdP"
rm -f "$W/jar"
check "ACS accepts the assertion" 302 \
    "$(curl -sk -c "$W/jar" --data-urlencode "SAMLResponse@$W/resp.b64" -o /dev/null -w '%{http_code}' "$ACS")"
is_live "$W/jar" "session reaches an authenticated API"

# --- 3. replay ------------------------------------------------------------------
echo ">>> case 3: the same assertion cannot be replayed"
check "replayed assertion refused" 400 \
    "$(curl -sk --data-urlencode "SAMLResponse@$W/resp.b64" -o /dev/null -w '%{http_code}' "$ACS")"

# --- 4. IdP-initiated -----------------------------------------------------------
echo ">>> case 4: unsolicited (IdP-initiated) assertions"
idp_initiated() {
    local kcjar="$W/kcjar2" out="$1" action
    rm -f "$kcjar"
    curl -sk -c "$kcjar" -L "$KC_BASE/protocol/saml/clients/opnsense-sso" -o "$W/idp.html"
    action=$(grep -o 'action="[^"]*"' "$W/idp.html" | head -1 | sed 's/action="//;s/"$//;s/&amp;/\&/g')
    case "$action" in
        *login-actions*)
            curl -sk -b "$kcjar" -c "$kcjar" -o "$W/idp.html" \
                -d "username=$KC_USER" -d "password=$KC_PASS" -d 'credentialId=' "$action" ;;
    esac
    extract_response "$W/idp.html" "$out"
}
idp_initiated "$W/unsol.b64"
if [ -s "$W/unsol.b64" ]; then
    ok "IdP produced an unsolicited assertion"
    check "refused while IdP-initiated login is off" 400 \
        "$(curl -sk --data-urlencode "SAMLResponse@$W/unsol.b64" -o /dev/null -w '%{http_code}' "$ACS")"
    vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_allow_idp_initiated=1" >/dev/null
    idp_initiated "$W/unsol2.b64"
    rm -f "$W/jar2"
    check "accepted once explicitly enabled" 302 \
        "$(curl -sk -c "$W/jar2" --data-urlencode "SAMLResponse@$W/unsol2.b64" -o /dev/null -w '%{http_code}' "$ACS")"
    is_live "$W/jar2" "IdP-initiated session is authenticated"
    vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_allow_idp_initiated=0" >/dev/null
    idp_initiated "$W/unsol3.b64"
    check "refused again once disabled" 400 \
        "$(curl -sk --data-urlencode "SAMLResponse@$W/unsol3.b64" -o /dev/null -w '%{http_code}' "$ACS")"
else
    ko "the IdP produced no unsolicited assertion (is saml_idp_initiated_sso_url_name set?)"
fi

# --- 5. HTTP-POST binding for the AuthnRequest ----------------------------------
echo ">>> case 5: HTTP-POST binding for the AuthnRequest"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_authn_post_binding=1" >/dev/null
curl -sk -o "$W/post-binding.html" "$GUI/api/sso/saml/login?provider=$PROVIDER"
grep -q 'name=.SAMLRequest.' "$W/post-binding.html" && ok "login returns a self-posting SAMLRequest form" \
    || ko "no POST form ($(head -c 120 "$W/post-binding.html"))"
grep -q "action='$KC_BASE/protocol/saml'" "$W/post-binding.html" && ok "form posts to the IdP SSO URL" \
    || ko "form action is not the IdP SSO URL"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_authn_post_binding=0" >/dev/null

# --- 6. IdP metadata import -----------------------------------------------------
echo ">>> case 6: IdP settings read from the metadata document"
# Save every manual field before clearing them: restoring only some of them would
# leave the provider incomplete for the cases that follow.
SAVED_ENTITY=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_entity_id")
SAVED_SSO=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_sso_url")
SAVED_X509=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_x509")
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_idp_metadata_url=$KC_BASE/protocol/saml/descriptor sso_idp_entity_id= sso_idp_sso_url= sso_idp_x509=" >/dev/null
curl -sk -b "$W/jar" -o "$W/check.json" "$GUI/api/sso/diagnostics/check/$PROVIDER"
grep -q '"source":"metadata document"' "$W/check.json" && ok "diagnostics reports the metadata source" \
    || ko "metadata not used ($(head -c 200 "$W/check.json"))"
KC_JSON=$(printf '%s' "$KC_BASE" | sed 's#/#\\\\/#g')   # JSON escapes forward slashes
grep -q "\"entity_id\":\"$KC_JSON\"" "$W/check.json" && ok "EntityID read from the document" \
    || ko "EntityID not read from the document ($(grep -o '\"entity_id\":\"[^\"]*\"' "$W/check.json"))"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
authenticate "$W/resp2.b64"
rm -f "$W/jar3"
check "login works with metadata-only configuration" 302 \
    "$(curl -sk -c "$W/jar3" --data-urlencode "SAMLResponse@$W/resp2.b64" -o /dev/null -w '%{http_code}' "$ACS")"
is_live "$W/jar3" "metadata-driven session is authenticated"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_idp_metadata_url= sso_idp_entity_id=$SAVED_ENTITY sso_idp_sso_url=$SAVED_SSO sso_idp_x509=$SAVED_X509" >/dev/null

# --- 7. Single Logout -----------------------------------------------------------
echo ">>> case 7: SP-initiated Single Logout"
SLO=$(curl -sk -b "$W/jar3" -H 'Sec-Fetch-Site: same-origin' -o /dev/null -w '%{redirect_url}' \
    "$GUI/api/sso/saml/slo?provider=$PROVIDER")
case "$SLO" in
    "$KC_BASE"/protocol/saml*) ok "logout redirects to the IdP with a LogoutRequest" ;;
    *) ko "unexpected SLO redirect ($SLO)" ;;
esac
curl -sk -b "$W/jar3" -H 'Sec-Fetch-Site: cross-site' -o "$W/slo.html" "$GUI/api/sso/saml/slo?provider=$PROVIDER"
grep -q 'logout_token' "$W/slo.html" && ok "cross-site logout asks for confirmation" \
    || ko "cross-site SLO was not intercepted"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
