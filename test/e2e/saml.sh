#!/usr/bin/env bash
# End-to-end test of the SAML SP, driven from the HOST (see oidc.sh for why).
#
# Prerequisites: an IdP stack from test/idp (with a matching SP_BASE), a running VM,
# and a '<idp>-saml' auth server registered in it.
#
# Usage: SSO_GUI_PORT=8444 ./saml.sh            (or through ./run-all.sh)
set -uo pipefail
# Work from this script's own directory whatever the caller's: every path below is
# relative to it (lib/, ../idp/), and the suites are started both from here and from
# run-all.sh. CDPATH= so a CDPATH in the environment cannot land us somewhere else, and
# -- so a path beginning with "-" is not read as an option. A symlink is followed where
# readlink can (GNU and FreeBSD both do), otherwise the guard below says so plainly.
self=$0
[ -L "$self" ] && self=$(readlink -f -- "$self" 2>/dev/null || printf '%s' "$self")
cd "$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)" || exit 1

# Fail loudly if the ceremony driver is missing. Every login below reports only the HTTP
# status it got, so an absent driver used to surface as an empty status with no clue.
[ -r lib/idp_login.py ] || {
    echo "FATAL: lib/idp_login.py not found next to $self" >&2
    exit 1
}

PORT="${SSO_GUI_PORT:-8443}"
# The lab can be reached two ways: the NAT-forwarded port, or the host-only address
# (test/Vagrantfile). SSO_GUI_URL picks; it must match the provider Base URL, or the
# callback lands on a different origin than the login and the session is not found.
GUI="${SSO_GUI_URL:-https://localhost:$PORT}"
IDP="${IDP:-keycloak}"
PROVIDER="${SSO_SAML_PROVIDER:-keycloak-saml}"
IDP_BASE="${IDP_BASE:-https://keycloak.test:9443/realms/opnsense}"
IDP_USER="${IDP_USER:-kctest}"
IDP_PASS="${IDP_PASS:-Test12345!}"
ACS="$GUI/api/sso/saml/acs?provider=$PROVIDER"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0; fail=0

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
skip() { echo "  SKIP $1"; }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || ko "$1 (expected $2, got $3)"; }
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }
authed(){ [ "$(curl -sk -b "$1" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")" = "200" ]; }
is_live(){ authed "$1" && ok "$2" || ko "$2 (session is not authenticated)"; }

# The browser ceremony, IdP dialect included, lives in lib/idp_login.py.
ceremony() { # $1 = cookie jar; echoes the ACS status
    python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol saml \
        --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$1" | tail -1
}

capture() { # $1 = file for the raw SAMLResponse; stops just before the ACS
    python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol saml \
        --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$W/cap.jar" \
        --capture "$1" | tail -1
}

echo "=== os-sso SAML end-to-end ($GUI, idp=$IDP, provider=$PROVIDER) ==="

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
check "ACS accepts the assertion" 302 "$(ceremony "$W/jar")"
is_live "$W/jar" "session reaches an authenticated API"

# --- 3. replay ------------------------------------------------------------------
echo ">>> case 3: the same assertion cannot be replayed"
check "assertion captured before delivery" captured "$(capture "$W/resp.b64")"
check "first delivery accepted" 302 \
    "$(curl -sk -c "$W/jar1" --data-urlencode "SAMLResponse@$W/resp.b64" -o /dev/null -w '%{http_code}' "$ACS")"
check "replayed assertion refused" 400 \
    "$(curl -sk --data-urlencode "SAMLResponse@$W/resp.b64" -o /dev/null -w '%{http_code}' "$ACS")"

# --- 4. IdP-initiated -----------------------------------------------------------
echo ">>> case 4: unsolicited (IdP-initiated) assertions"
if [ "$IDP" = "keycloak" ]; then
    idp_initiated() { # $1 = output file for the SAMLResponse
        local kcjar="$W/kcjar2" action
        rm -f "$kcjar"
        curl -sk -c "$kcjar" -L "$IDP_BASE/protocol/saml/clients/opnsense-sso" -o "$W/idp.html"
        action=$(grep -o 'action="[^"]*"' "$W/idp.html" | head -1 | sed 's/action="//;s/"$//;s/&amp;/\&/g')
        case "$action" in
            *login-actions*)
                curl -sk -b "$kcjar" -c "$kcjar" -o "$W/idp.html" \
                    -d "username=$IDP_USER" -d "password=$IDP_PASS" -d 'credentialId=' "$action" ;;
        esac
        python3 - "$W/idp.html" "$1" <<'PY'
import html, re, sys
page = open(sys.argv[1], encoding='utf-8', errors='replace').read()
m = (re.search(r'name="SAMLResponse"[^>]*value="([^"]+)"', page)
     or re.search(r'value="([^"]+)"[^>]*name="SAMLResponse"', page))
open(sys.argv[2], 'w').write(html.unescape(m.group(1)) if m else '')
PY
    }
    idp_initiated "$W/unsol.b64"
    if [ -s "$W/unsol.b64" ]; then
        ok "IdP produced an unsolicited assertion"
        check "refused while IdP-initiated login is off" 400 \
            "$(curl -sk --data-urlencode "SAMLResponse@$W/unsol.b64" -o /dev/null -w '%{http_code}' "$ACS")"
        vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_allow_idp_initiated=1" >/dev/null
        idp_initiated "$W/unsol2.b64"
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
else
    skip "IdP-initiated: the lab only wires that endpoint up on Keycloak"
fi

# --- 5. HTTP-POST binding for the AuthnRequest ----------------------------------
echo ">>> case 5: HTTP-POST binding for the AuthnRequest"
SSO_URL=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_sso_url")
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_authn_post_binding=1" >/dev/null
curl -sk -o "$W/post-binding.html" "$GUI/api/sso/saml/login?provider=$PROVIDER"
grep -q 'name=.SAMLRequest.' "$W/post-binding.html" && ok "login returns a self-posting SAMLRequest form" \
    || ko "no POST form ($(head -c 120 "$W/post-binding.html"))"
grep -q "action='$SSO_URL'" "$W/post-binding.html" && ok "form posts to the IdP SSO URL" \
    || ko "form action is not the IdP SSO URL"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_authn_post_binding=0" >/dev/null

# --- 6. IdP metadata import -----------------------------------------------------
echo ">>> case 6: IdP settings read from the metadata document"
case "$IDP" in
    keycloak)  MD_URL="$IDP_BASE/protocol/saml/descriptor" ;;
    authentik) MD_URL="$IDP_BASE/application/saml/opnsense-saml/metadata/" ;;
esac
# Save every manual field before clearing them: restoring only some of them would
# leave the provider incomplete for the cases that follow.
SAVED_ENTITY=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_entity_id")
SAVED_SSO=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_sso_url")
SAVED_X509=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_idp_x509")
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_idp_metadata_url=$MD_URL sso_idp_entity_id= sso_idp_sso_url= sso_idp_x509=" >/dev/null
curl -sk -b "$W/jar" -o "$W/check.json" "$GUI/api/sso/diagnostics/check/$PROVIDER"
grep -q '"source":"metadata document"' "$W/check.json" && ok "diagnostics reports the metadata source" \
    || ko "metadata not used ($(head -c 200 "$W/check.json"))"
ENTITY_JSON=$(printf '%s' "$SAVED_ENTITY" | sed 's#/#\\\\/#g')   # JSON escapes forward slashes
grep -q "\"entity_id\":\"$ENTITY_JSON\"" "$W/check.json" && ok "EntityID read from the document" \
    || ko "EntityID not read from the document ($(grep -o '"entity_id":"[^"]*"' "$W/check.json"))"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
check "login works with metadata-only configuration" 302 "$(ceremony "$W/jar3")"
is_live "$W/jar3" "metadata-driven session is authenticated"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_idp_metadata_url= sso_idp_entity_id=$SAVED_ENTITY sso_idp_sso_url=$SAVED_SSO sso_idp_x509=$SAVED_X509" >/dev/null

# --- 7. Single Logout -----------------------------------------------------------
echo ">>> case 7: SP-initiated Single Logout"
SLO=$(curl -sk -b "$W/jar3" -H 'Sec-Fetch-Site: same-origin' -o /dev/null -w '%{redirect_url}' \
    "$GUI/api/sso/saml/slo?provider=$PROVIDER")
case "$SLO" in
    "$IDP_BASE"*) ok "logout redirects to the IdP with a LogoutRequest" ;;
    *) ko "unexpected SLO redirect ($SLO)" ;;
esac
curl -sk -b "$W/jar3" -H 'Sec-Fetch-Site: cross-site' -o "$W/slo.html" "$GUI/api/sso/saml/slo?provider=$PROVIDER"
grep -q 'logout_token' "$W/slo.html" && ok "cross-site logout asks for confirmation" \
    || ko "cross-site SLO was not intercepted"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
