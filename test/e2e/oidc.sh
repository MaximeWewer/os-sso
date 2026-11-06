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
    python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" \
        --protocol oidc --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" \
        --jar "$1" "${@:2}" | tail -1
}
# The Keycloak admin password the container was started with (test/idp/keycloak/.env).
kc_admin_password() { docker exec keycloak printenv KC_BOOTSTRAP_ADMIN_PASSWORD 2>/dev/null; }
# Set provider fields from a JSON object (JSON and PEM values survive the nested quoting).
asjson() { vm "php /home/vagrant/os-sso/test/vagrant/set_authserver_json.php $PROVIDER b64:$(printf '%s' "$1" | base64 | tr -d '\n')" >/dev/null; }

echo "=== os-sso OIDC end-to-end ($GUI, idp=$IDP, provider=$PROVIDER) ==="

# --- 1. the ceremony itself --------------------------------------------------
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
echo ">>> case 1: full browser login"
check "callback -> 302" 302 "$(login "$W/jar")"
is_live "$W/jar" "session reaches an authenticated API"

# --- 1b. the response names its issuer (RFC 9207) ------------------------------
# A mix-up attack swaps one IdP's response for another's. Keycloak sends iss and says so
# in its discovery document, so a response naming another issuer, or none, is refused.
echo ">>> case 1b: the authorization response names its issuer (RFC 9207)"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
check "a response naming another issuer is refused" 400 \
    "$(login "$W/jar-iss1" --callback-param iss=https://evil.example/realms/opnsense)"
check "a response with its iss stripped is refused" 400 \
    "$(login "$W/jar-iss2" --callback-param iss=)"

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
LOGOUT=$(curl -sk -b "$W/jar" -H 'Sec-Fetch-Site: same-origin' -o /dev/null \
    -w '%{http_code} %{redirect_url}' "$GUI/api/sso/logout")
check "same-origin logout proceeds" 302 "${LOGOUT%% *}"
# /api/sso/logout only dispatches to the protocol's own logout; that one ends the
# session and sends the browser on to the IdP's end_session_endpoint.
END_SESSION=$(curl -sk -b "$W/jar" -H 'Sec-Fetch-Site: same-origin' -o /dev/null \
    -w '%{redirect_url}' "${LOGOUT#* }")

# --- 5c. back from the IdP's logout without tripping the HTTP_REFERER check ----
# Straight from the IdP, the login page would carry the IdP as Referer and core would
# refuse it (issue #10). The IdP must come back to our no-referrer page instead.
echo ">>> case 5c: the return from the IdP logout reaches the login page"
LOGGED_OUT="$GUI/api/sso/oidc/loggedout"
ENC=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$LOGGED_OUT")
case "$END_SESSION$LOGOUT" in
    *"post_logout_redirect_uri=$ENC"*) ok "the IdP is asked to come back to the signed-out page" ;;
    *) ko "post_logout_redirect_uri is not the signed-out page ($END_SESSION)" ;;
esac
curl -sk -D "$W/lo.h" -o "$W/lo.html" "$LOGGED_OUT" >/dev/null
grep -qi '^referrer-policy: no-referrer' "$W/lo.h" && ok "the signed-out page is served no-referrer" \
    || ko "no Referrer-Policy on the signed-out page"
grep -q "content='0;url=/'" "$W/lo.html" && ok "and moves straight on to the login page" \
    || ko "the signed-out page does not continue to /"
# Why the hop matters: core refuses a session-less request referred by another host.
curl -sk -H 'Referer: https://login.live.com/' -o "$W/ref.html" "$GUI/"
grep -q 'HTTP_REFERER' "$W/ref.html" && ok "core still refuses a login page referred by the IdP" \
    || ko "the HTTP_REFERER check did not fire (is it disabled on the lab?)"
curl -sk -o "$W/noref.html" "$GUI/"
grep -q 'HTTP_REFERER' "$W/noref.html" && ko "the login page refused a request with no Referer" \
    || ok "the login page is served once the Referer is gone"

# --- 5b. pushed authorization requests -----------------------------------------
# PAR moves the request off the browser entirely, so what changes is the shape of the
# redirect: client_id and an opaque reference, nothing else. The login has to still
# work, which is the half a URL check cannot tell you.
echo ">>> case 5b: pushed authorization requests (PAR)"
# Not every IdP offers it (Authentik does not publish the endpoint), and asking for it
# must not break those: the flow falls back to the ordinary redirect, which is the other
# half of what this case checks.
ISSUER=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_authserver.php $PROVIDER sso_issuer")
HAS_PAR=$(vm "fetch -qo - --no-verify-peer '${ISSUER%/}/.well-known/openid-configuration'" \
    | grep -c pushed_authorization_request_endpoint)
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_use_par=1" >/dev/null
PARURL=$(curl -sk -o /dev/null -w '%{redirect_url}' "$GUI/api/sso/oidc/login?provider=$PROVIDER")
if [ "${HAS_PAR:-0}" -gt 0 ] 2>/dev/null; then
    case "$PARURL" in
        *request_uri=urn*) ok "the redirect carries a request_uri reference" ;;
        *) ko "no request_uri in the redirect ($PARURL)" ;;
    esac
    case "$PARURL" in
        *state=*|*code_challenge=*|*redirect_uri=*) ko "the request parameters still travel in the URL" ;;
        *) ok "no state, PKCE challenge or redirect_uri left in the URL" ;;
    esac
else
    case "$PARURL" in
        *code_challenge=*) ok "an IdP without a PAR endpoint keeps the ordinary redirect" ;;
        *) ko "the redirect lost its parameters against an IdP that has no PAR ($PARURL)" ;;
    esac
fi
rm -f "$W/parjar"
check "a PAR login completes" 302 "$(login "$W/parjar")"
is_live "$W/parjar" "and the session it opened is authenticated"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_use_par=0" >/dev/null
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null

# --- 6. rate limiting ----------------------------------------------------------
echo ">>> case 6: pre-auth rate limit"
# The ceiling is 60 a minute per source: one source is regularly a whole NATed office
# arriving at nine, so it has to sit well above a working burst -- which means the probe
# has to go past it rather than past 20.
limited=0
for _ in $(seq 1 66); do
    c=$(curl -sk -o /dev/null -w '%{http_code}' "$GUI/api/sso/oidc/login?provider=$PROVIDER")
    [ "$c" = "400" ] && limited=$((limited+1))
done
[ "$limited" -gt 0 ] && ok "login throttled after the window filled ($limited refused of 66)" \
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

echo ">>> case 8b: a login that passes undoes the deprovisioning"
# The account is disabled by case 8 above. Lift the gate it failed -- the IdP now says
# this person is allowed again, which is precisely the event a login-driven plugin was
# waiting for and could not hear. Without the revival that event is unreachable: the
# login that would carry it is refused by the flag its own earlier refusal set, and
# somebody has to go and tick the box back by hand.
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_required_groups= sso_deprovision=1" >/dev/null
check "the login that disproves the refusal succeeds" 302 "$(login "$W/jar3r")"
is_live "$W/jar3r" "and the session it opened authenticates"
DUMP=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php $IDP_USER")
case "$DUMP" in
    *disabled=0*) ok "the account was re-enabled ($DUMP)" ;;
    *) ko "account still disabled ($DUMP)" ;;
esac

echo ">>> case 8c: a privileged account is never deprovisioned (anti-lockout)"
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

# --- 2b. requested claims (the OIDC claims parameter) -----------------------------
# Keycloak's fw_role mapper (setup-keycloak.sh) answers an essential fw_role claim
# requested with a value. Read the groups from it and require that value: the login then
# passes only if the claims request reached the IdP and its answer came back.
if [ "$IDP" = "keycloak" ]; then
    echo ">>> case 2b: requested claims (claims parameter)"
    asjson '{"sso_groups_claim":"fw_role","sso_required_groups":"fw-claims-ok","sso_claims_request":"{\"id_token\":{\"fw_role\":{\"essential\":true,\"value\":\"fw-claims-ok\"}}}"}'
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    check "the requested claim satisfies the group gate" 302 "$(login "$W/jar-claims1")"
    asjson '{"sso_claims_request":""}'
    check "without the claims request it is not there" 400 "$(login "$W/jar-claims2")"
    asjson '{"sso_groups_claim":"groups","sso_required_groups":""}'
fi

# --- 2c. signed request object (JAR, RFC 9101) -----------------------------------
# Keycloak is told to require a signed request object and given our certificate; the
# login then passes only with JAR on, and a certificate Keycloak does not hold fails it.
# Registered by certificate, Keycloak names the key itself, hence no Key ID here.
if [ "$IDP" = "keycloak" ] && command -v docker >/dev/null; then
    echo ">>> case 2c: signed request object (JAR)"
    kcadm() { docker exec keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
    kcadm config credentials --server http://localhost:8080 --realm master --user admin --password "$(kc_admin_password)" >/dev/null 2>&1
    KCID=$(kcadm get clients -r opnsense -q clientId=opnsense-oidc --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/jar.key" -out "$W/jar.crt" -days 1 -subj /CN=jar 2>/dev/null
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/other.key" -out "$W/other.crt" -days 1 -subj /CN=other 2>/dev/null
    kccert() { kcadm update "clients/$KCID" -r opnsense -s "attributes.\"jwt.credential.certificate\"=$(openssl x509 -in "$1" -outform DER | base64 -w0)" >/dev/null 2>&1; }
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."use.jwks.url"=false' \
        -s 'attributes."request.object.signature.alg"=RS256' \
        -s 'attributes."request.object.required"=request or request_uri' >/dev/null 2>&1
    kccert "$W/jar.crt"
    asjson "$(python3 -c 'import json,sys;print(json.dumps({"sso_private_key":open(sys.argv[1]).read(),"sso_signed_request":"1"}))' "$W/jar.key")"
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    check "a signed request object is accepted where the IdP requires one" 302 "$(login "$W/jar-jar1")"
    asjson '{"sso_use_par":"1"}'
    check "and pushed by PAR" 302 "$(login "$W/jar-jar2")"
    asjson '{"sso_use_par":""}'
    # By reference: Keycloak takes only a request_uri, which it must have registered,
    # and fetches the object from the firewall over the lab-CA HTTPS.
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."request.object.required"=request_uri only' \
        -s "attributes.\"request.uris\"=$GUI/api/sso/oidc/request*" >/dev/null 2>&1
    check "a request object passed by value fails where the IdP wants a request_uri" 000 "$(login "$W/jar-jar5")"
    asjson '{"sso_request_by_reference":"1"}'
    check "and passes by reference, fetched by the IdP from the firewall" 302 "$(login "$W/jar-jar6")"
    check "an id the firewall did not issue finds nothing" 404 \
        "$(curl -sk -o /dev/null -w '%{http_code}' "$GUI/api/sso/oidc/request?id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")"
    asjson '{"sso_request_by_reference":""}'
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."request.object.required"=request or request_uri' >/dev/null 2>&1
    kccert "$W/other.crt"
    check "a request object signed with a key the IdP does not hold fails" 000 "$(login "$W/jar-jar3")"
    asjson '{"sso_signed_request":""}'
    kccert "$W/jar.crt"
    check "an unsigned request fails where the IdP requires one" 000 "$(login "$W/jar-jar4")"
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."request.object.required"=not required' >/dev/null 2>&1
    asjson '{"sso_private_key":""}'
fi

# --- 2d. signed authorization response (JARM) ------------------------------------
# Keycloak signs the response when asked (query.jwt, form_post.jwt). Once JARM is on, a
# response stripped of its JWT or with a broken signature must be refused.
if [ "$IDP" = "keycloak" ]; then
    echo ">>> case 2d: signed authorization response (JARM)"
    asjson '{"sso_jarm":"1"}'
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    check "a signed response (query.jwt) logs in" 302 "$(login "$W/jar-jarm1")"
    check "a response stripped of its JWT is refused" 400 "$(login "$W/jar-jarm2" --callback-param response=)"
    check "a response whose signature was altered is refused" 400 "$(login "$W/jar-jarm3" --callback-param response=@corrupt)"
    asjson '{"sso_form_post":"1"}'
    check "and over form_post.jwt" 302 "$(login "$W/jar-jarm4")"
    asjson '{"sso_form_post":"","sso_jarm":""}'
fi

# --- 2e. DPoP-bound access token (RFC 9449) ----------------------------------------
# Keycloak is told to require DPoP-bound tokens and codes (a client policy enforcing code
# binding, so the authorization request must carry dpop_jkt), and the lab proxy's DPoP
# gate (test/idp/proxy/dpop_nonce.py) asks for a nonce at the token and userinfo
# endpoints. One login then exercises all of it: the code bound to the login key, the
# token request and the userinfo call each retried with the server nonce.
if [ "$IDP" = "keycloak" ] && command -v docker >/dev/null; then
    echo ">>> case 2e: DPoP-bound access token"
    kcadm() { docker exec -i keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
    kcadm config credentials --server http://localhost:8080 --realm master --user admin --password "$(kc_admin_password)" >/dev/null 2>&1
    KCID=$(kcadm get clients -r opnsense -q clientId=opnsense-oidc --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."dpop.bound.access.tokens"=true' >/dev/null 2>&1
    printf '%s' '{"profiles":[{"name":"dpop-code-binding","executors":[{"executor":"dpop-bind-enforcer","configuration":{"auto-configure":"true","allow-only-refresh-token-binding":"false","enforce-authorization-code-binding-to-dpop":"true"}}]}]}' \
        | kcadm update client-policies/profiles -r opnsense -f - >/dev/null 2>&1
    printf '%s' '{"policies":[{"name":"dpop-code-binding","enabled":true,"conditions":[{"condition":"client-access-type","configuration":{"type":["confidential"]}}],"profiles":["dpop-code-binding"]}]}' \
        | kcadm update client-policies/policies -r opnsense -f - >/dev/null 2>&1
    asjson '{"sso_dpop":"1"}'
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    UI_BEFORE=$(vm "grep -ah \"userinfo request failed\" /var/log/system/system_*.log /var/log/audit/audit_*.log | grep -vc COMMAND")
    GATE_FROM=$(docker logs idp-dpop-nonce 2>&1 | wc -l)
    check "a DPoP login passes where the IdP binds codes and tokens" 302 "$(login "$W/jar-dpop1")"
    GATE=$(docker logs idp-dpop-nonce 2>&1 | tail -n +$((GATE_FROM + 1)))
    UI_AFTER=$(vm "grep -ah \"userinfo request failed\" /var/log/system/system_*.log /var/log/audit/audit_*.log | grep -vc COMMAND")
    printf '%s' "$GATE" | grep -q 'passed POST .*/token with the nonce -> 200' \
        && ok "the token request was retried with the server nonce" || ko "no nonce retry at the token endpoint ($GATE)"
    printf '%s' "$GATE" | grep -q 'passed GET .*/userinfo with the nonce -> 200' \
        && ok "and so was the userinfo call" || ko "no nonce retry at userinfo ($GATE)"
    check "and userinfo was not lost on the way" "$UI_BEFORE" "$UI_AFTER"
    asjson '{"sso_dpop":""}'
    check "without DPoP the login is refused" 000 "$(login "$W/jar-dpop2")"
    printf '%s' '{"policies":[]}' | kcadm update client-policies/policies -r opnsense -f - >/dev/null 2>&1
    kcadm update "clients/$KCID" -r opnsense -s 'attributes."dpop.bound.access.tokens"=false' >/dev/null 2>&1
fi

# --- 10b. front-channel logout --------------------------------------------------
# What Entra ID offers instead of back-channel: a sign-out at the IdP loads our page in
# an iframe with the IdP session id. Keycloak is set up for it (setup-keycloak.sh); the
# helper signs out there from another client of the same session, as a user leaving
# some other application would, and loads the iframes Keycloak renders.
echo ">>> case 10b: front-channel logout"
check "a request without sid is refused" 400 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "$GUI/api/sso/oidc/frontchannel?provider=$PROVIDER")"
if [ "$IDP" = "keycloak" ]; then
    # Keycloak does front- or back-channel per client: make sure this one is front.
    command -v docker >/dev/null && docker exec keycloak /opt/keycloak/bin/kcadm.sh update \
        "clients/$(docker exec keycloak /opt/keycloak/bin/kcadm.sh get clients -r opnsense -q clientId=opnsense-oidc --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')" \
        -r opnsense -s frontchannelLogout=true >/dev/null 2>&1
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    check "login for the front-channel case" 302 "$(login "$W/jar-fc")"
    python3 lib/kc_frontchannel.py "$W/jar-fc" "https://keycloak.test:9443/realms/opnsense" > "$W/fc.out" 2>&1
    grep -q "frontchannel?provider=$PROVIDER" "$W/fc.out" \
        && ok "a sign-out at the IdP frames our front-channel page" \
        || ko "no front-channel iframe ($(head -c 200 "$W/fc.out"))"
    grep -q "frame-ancestors https://keycloak.test:9443" "$W/fc.out" \
        && ok "and only the IdP may frame it" || ko "unexpected framing policy ($(grep CSP "$W/fc.out"))"
    not_live "$W/jar-fc" "the firewall session ends with the IdP session"
fi

# --- 10c. a real back-channel logout from Keycloak -----------------------------------
# Keycloak calls the firewall itself, over HTTPS it can verify: the lab gives the WebGUI a
# certificate from the lab CA (deploy.sh), which the Keycloak container trusts. Keycloak
# does front- or back-channel per client, not both, so the client is switched for the
# case and back afterwards. Its logout token is explicitly typed logout+jwt.
if [ "$IDP" = "keycloak" ] && command -v docker >/dev/null; then
    echo ">>> case 10c: a real back-channel logout from Keycloak"
    # No -i: with stdin attached, "kcadm create" reads it as the request body.
    kcadm() { docker exec keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
    kcadm config credentials --server http://localhost:8080 --realm master --user admin --password "$(kc_admin_password)" >/dev/null 2>&1
    KCID=$(kcadm get clients -r opnsense -q clientId=opnsense-oidc --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
    KCUSER=$(kcadm get users -r opnsense -q username="$IDP_USER" --fields id --format csv --noquotes 2>/dev/null | tr -d '\r')
    # Keycloak sends one logout token per open session: clear those of the earlier cases
    # (with no logout URL set yet, so nothing is sent) to leave only this case's one.
    kcadm update "clients/$KCID" -r opnsense -s frontchannelLogout=false \
        -s 'attributes."backchannel.logout.url"=' >/dev/null 2>&1
    kcadm create "users/$KCUSER/logout" -r opnsense >/dev/null 2>&1
    kcadm update "clients/$KCID" -r opnsense \
        -s "attributes.\"backchannel.logout.url\"=$GUI/api/sso/oidc/backchannel?provider=$PROVIDER" \
        -s 'attributes."backchannel.logout.session.required"=true' >/dev/null 2>&1
    vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
    check "login for the back-channel case" 302 "$(login "$W/jar-bc")"
    is_live "$W/jar-bc" "the session is open"
    kcadm create "users/$KCUSER/logout" -r opnsense >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do authed "$W/jar-bc" || break; sleep 2; done
    not_live "$W/jar-bc" "Keycloak's logout token ended it, over verified HTTPS"
    kcadm update "clients/$KCID" -r opnsense -s frontchannelLogout=true \
        -s 'attributes."backchannel.logout.url"=' >/dev/null 2>&1
fi

# --- 11. service scoping --------------------------------------------------------
# A provider narrowed to the portal must stop being a WebGUI door -- button and
# endpoint both, since the button is only the part an attacker does not need.
echo ">>> case 11: a provider scoped away from the WebGUI"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_services=portal" >/dev/null
check "the login endpoint refuses a WebGUI login" 400 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "$GUI/api/sso/oidc/login?provider=$PROVIDER")"
curl -sk -o "$W/loginpage.html" "$GUI/"
grep -q "api/sso/oidc/login?provider=$PROVIDER" "$W/loginpage.html" \
    && ko "the login page still offers the provider" \
    || ok "no button for it on the login page"
vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER sso_services=" >/dev/null
check "and it works again once the scope is cleared" 302 "$(login "$W/jar5")"

# --- 12. ending a session from the diagnostics page -----------------------------
# One administrator ends somebody else's session: which is the point of the button, and
# what tells the two sessions apart is the handle the page lists (a digest of the
# session id, never the id).
echo ">>> case 12: an administrator ends another session"
handles() { curl -sk -b "$1" "$GUI/api/sso/diagnostics/sessions" \
    | grep -o '"id":"[a-f0-9]\{64\}"' | sed 's/.*:"//;s/"//' | sort; }
# The WebGUI's own CSRF token, read the way the page's JS gets it. Without it core
# refuses the POST, which is a property worth asserting in its own right.
curl -sk -b "$W/jar5" "$GUI/ui/sso/diagnostics" -o "$W/diag.html"
TOK=$(sed -n 's/.*"X-CSRFToken", "\([^"]*\)".*/\1/p' "$W/diag.html" | head -1)
[ -n "$TOK" ] && ok "the diagnostics page carries a CSRF token" || ko "no CSRF token on the page"
BEFORE=$(handles "$W/jar5")
check "a second login" 302 "$(login "$W/jar6")"
SID=$(comm -13 <(printf '%s\n' "$BEFORE") <(handles "$W/jar5") | head -1)
[ -n "$SID" ] && ok "the new session shows up with its own handle" || ko "the new session is not listed"
check "ending it needs a POST" 405 \
    "$(curl -sk -b "$W/jar5" -H "X-CSRFToken: $TOK" -o /dev/null -w '%{http_code}' \
        "$GUI/api/sso/diagnostics/endSession/$SID")"
check "and a CSRF token" 403 \
    "$(curl -sk -b "$W/jar5" -X POST -o /dev/null -w '%{http_code}' \
        "$GUI/api/sso/diagnostics/endSession/$SID")"
curl -sk -b "$W/jar5" -H "X-CSRFToken: $TOK" -X POST -o "$W/end.json" \
    "$GUI/api/sso/diagnostics/endSession/$SID" >/dev/null
grep -q '"ended":1' "$W/end.json" && ok "one access was ended ($(cat "$W/end.json"))" \
    || ko "endSession answered $(cat "$W/end.json")"
not_live "$W/jar6" "the ended session no longer authenticates"
is_live "$W/jar5" "the administrator's own session is untouched"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
