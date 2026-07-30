#!/usr/bin/env bash
# SCIM 2.0 provisioning end-to-end, driven from the host.
#
# The headline case is the last one: a user logs in over SSO, the directory then says
# "active: false", and the open session dies. That is the gap SCIM exists to close --
# without it a revoked account keeps its session until it idles out, because a
# login-driven plugin only hears about revocations when someone tries to log in.
#
# Prerequisites: a running VM and an SSO provider with SCIM enabled. The suite sets
# the token and the source allowlist itself.
#
# Usage: SSO_GUI_URL=https://192.168.60.10 ./scim.sh
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
GUI="${SSO_GUI_URL:-https://localhost:$PORT}"
IDP="${IDP:-keycloak}"
PROVIDER="${SSO_PROVIDER:-keycloak}"
IDP_USER="${IDP_USER:-kctest}"
IDP_PASS="${IDP_PASS:-Test12345!}"
BASE="$GUI/api/sso/scim"
TOKEN="${SCIM_TOKEN:-os-sso-e2e-token-$(head -c 24 /dev/urandom | base64 | tr -d '=+/')}"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
pass=0; fail=0

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
check(){ [ "$2" = "$3" ] && ok "$1 ($3)" || ko "$1 (expected $2, got $3)"; }
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }
set_provider() { vm "php /home/vagrant/os-sso/test/vagrant/set_authserver.php $PROVIDER $*" >/dev/null; }

AUTH="Authorization: Bearer $TOKEN"
CT='Content-Type: application/scim+json'
code() { curl -sk -o "$W/out" -w '%{http_code}' -m 15 "$@"; }
body() { cat "$W/out"; }
json() { python3 -c "import json,sys;d=json.load(open('$W/out'));print(eval('d'+sys.argv[1]))" "$1" 2>/dev/null; }

echo "=== os-sso SCIM end-to-end ($BASE, provider=$PROVIDER) ==="

echo ">>> enabling SCIM on '$PROVIDER'"
# The source allowlist is mandatory, so the baseline has to name one. 0.0.0.0/0
# stands in for "wherever this suite runs from"; case 2 exercises the real thing.
ANY_SOURCE='0.0.0.0/0,::/0'
set_provider "sso_scim_enabled=1 sso_scim_token=$TOKEN sso_scim_trusted=$ANY_SOURCE"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null

# --- 1. discovery + authentication ----------------------------------------------
echo ">>> case 1: discovery and authentication"
check "no token is refused" 401 "$(code "$BASE/ServiceProviderConfig")"
check "a wrong token is refused" 401 "$(code -H 'Authorization: Bearer wrong' "$BASE/ServiceProviderConfig")"
check "ServiceProviderConfig" 200 "$(code -H "$AUTH" "$BASE/ServiceProviderConfig")"
grep -q '"patch":{"supported":true}' "$W/out" && ok "advertises PATCH support" || ko "ServiceProviderConfig content"
check "ResourceTypes" 200 "$(code -H "$AUTH" "$BASE/ResourceTypes")"
check "Schemas" 200 "$(code -H "$AUTH" "$BASE/Schemas")"

echo ">>> case 2: the source allowlist bounds who may use the token"
set_provider "sso_scim_trusted=203.0.113.0/24"
check "valid token from an untrusted source is refused" 401 "$(code -H "$AUTH" "$BASE/ServiceProviderConfig")"
# Empty means "nobody", not "anybody": the allowlist is part of the credential.
set_provider "sso_scim_trusted="
check "valid token with no allowlist configured is refused" 401 "$(code -H "$AUTH" "$BASE/ServiceProviderConfig")"
set_provider "sso_scim_trusted=$ANY_SOURCE"
check "accepted again once the source is allowed" 200 "$(code -H "$AUTH" "$BASE/ServiceProviderConfig")"

# --- 3. user lifecycle -----------------------------------------------------------
echo ">>> case 3: user lifecycle"
# scim.alice too: this suite creates it, so a leftover from a previous run would
# make the "already exists" cases pass or fail for the wrong reason.
vm "env RESET_USERS=jwtuser,grpprobe,kctest,cptester,akadmin,scim.alice php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null
NEW='{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"scim.alice",
      "externalId":"ext-alice-1","active":true,"name":{"givenName":"Alice","familyName":"Martin"},
      "emails":[{"value":"alice@example.com","primary":true}]}'
check "POST /Users creates" 201 "$(code -H "$AUTH" -H "$CT" -X POST "$BASE/Users" -d "$NEW")"
UID_=$(json "['id']")
[ -n "$UID_" ] && ok "the response carries an id ($UID_)" || ko "no id in the created resource"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -q 'disabled=0' \
    && ok "the account exists and is enabled in config.xml" || ko "account not created"
check "GET /Users/{id}" 200 "$(code -H "$AUTH" "$BASE/Users/$UID_")"
check "a second POST is a conflict" 409 "$(code -H "$AUTH" -H "$CT" -X POST "$BASE/Users" -d "$NEW")"

echo ">>> case 4: search"
code -H "$AUTH" -G "$BASE/Users" --data-urlencode 'filter=userName eq "scim.alice"' >/dev/null
[ "$(json "['totalResults']")" = "1" ] && ok "filter on userName" || ko "filter on userName ($(head -c 120 "$W/out"))"
code -H "$AUTH" -G "$BASE/Users" --data-urlencode 'filter=externalId eq "ext-alice-1"' >/dev/null
[ "$(json "['totalResults']")" = "1" ] && ok "filter on externalId" || ko "filter on externalId"
check "an unsupported filter is refused" 400 \
    "$(code -H "$AUTH" -G "$BASE/Users" --data-urlencode 'filter=userType co "x"')"
grep -q 'invalidFilter' "$W/out" && ok "refusal carries scimType invalidFilter" || ko "no scimType on the error"
# count=0 is how a client sizes a sync before walking it: the total, and no rows.
code -H "$AUTH" -G "$BASE/Users" --data-urlencode 'count=0' >/dev/null
[ "$(json "['itemsPerPage']")" = "0" ] && ok "count=0 returns no resources" \
    || ko "count=0 returned $(json "['itemsPerPage']") resource(s)"
[ "$(json "['totalResults']")" -ge 1 ] && ok "count=0 still reports the total" \
    || ko "count=0 lost totalResults"

echo ">>> case 5: PATCH and DELETE"
check "PATCH active=false" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Users/$UID_" \
    -d '{"Operations":[{"op":"replace","path":"active","value":false}]}')"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -q 'disabled=1' \
    && ok "the account is disabled in config.xml" || ko "account still enabled"
check "PATCH active=true" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Users/$UID_" \
    -d '{"Operations":[{"op":"replace","path":"active","value":true}]}')"
check "PATCH displayName" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Users/$UID_" \
    -d '{"Operations":[{"op":"replace","path":"displayName","value":"Alice M."}]}')"
[ "$(json "['displayName']")" = "Alice M." ] && ok "displayName updated" || ko "displayName not updated"
check "DELETE deactivates" 204 "$(code -H "$AUTH" -X DELETE "$BASE/Users/$UID_")"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -q 'disabled=1' \
    && ok "DELETE disabled the account instead of removing it" || ko "DELETE did not disable"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -q 'uid=' \
    && ok "the account still exists (rules and keys survive)" || ko "the account was removed"

# --- 6. the guards ---------------------------------------------------------------
echo ">>> case 6: privileged accounts are out of reach"
# 404, not 403: an account os-sso does not own is not addressable over SCIM at all, so
# the response says nothing about whether it exists. uids run sequentially from nextuid,
# and a 403 here would have turned /Users/<n> into an enumeration of every local account
# on the firewall -- root included.
check "PATCH on uid 0 is not addressable" 404 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Users/0" \
    -d '{"Operations":[{"op":"replace","path":"active","value":false}]}')"
check "DELETE on uid 0 is not addressable" 404 "$(code -H "$AUTH" -X DELETE "$BASE/Users/0")"
grep -q 'not found' "$W/out" && ok "the refusal does not confirm the account exists" \
    || ko "the refusal leaked something ($(head -c 120 "$W/out"))"
check "POST colliding with a local account is refused" 403 \
    "$(code -H "$AUTH" -H "$CT" -X POST "$BASE/Users" -d '{"userName":"root","externalId":"ext-evil"}')"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php root" | grep -q 'disabled=0' \
    && ok "root is untouched" || ko "root was modified"

echo ">>> case 7: groups take membership, nothing else"
GID=$(vm "php /home/vagrant/os-sso/test/vagrant/add_group.php vpnusers")
code -H "$AUTH" -G "$BASE/Groups" --data-urlencode 'filter=displayName eq "vpnusers"' >/dev/null
[ "$(json "['totalResults']")" = "1" ] && ok "the group is listed (gid $GID)" || ko "group not listed"
check "POST /Groups is refused" 403 "$(code -H "$AUTH" -H "$CT" -X POST "$BASE/Groups" -d '{"displayName":"x"}')"
check "DELETE /Groups is refused" 403 "$(code -H "$AUTH" -X DELETE "$BASE/Groups/$GID")"
check "add a member" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Groups/$GID" \
    -d "{\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$UID_\"}]}]}")"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -q 'vpnusers' \
    && ok "membership written to config.xml" || ko "membership not written"
check "remove the member" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Groups/$GID" \
    -d "{\"Operations\":[{\"op\":\"remove\",\"path\":\"members[value eq \\\"$UID_\\\"]\"}]}")"
vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scim.alice" | grep -qv 'vpnusers' \
    && ok "membership removed" || ko "membership still there"
ADMINS=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_group.php admins")
check "a privileged group refuses membership from SCIM" 403 \
    "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Groups/$ADMINS" \
    -d "{\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$UID_\"}]}]}")"

# --- 8. what SCIM is for ---------------------------------------------------------
echo ">>> case 8: deactivating over SCIM ends the open sessions"
# A non-privileged account, or the guards above would (rightly) refuse to touch it.
set_provider "sso_default_groups= sso_required_groups= sso_deprovision=0"
vm "php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
LOGIN=$(python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol oidc \
    --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$W/jar" | tail -1)
check "the user logs in over SSO" 302 "$LOGIN"
LIVE=$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")
[ "$LIVE" = "200" ] && ok "the session is live" || ko "the session is not live ($LIVE)"

SSO_UID=$(vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php $IDP_USER" | sed -n 's/^uid=\([0-9]*\).*/\1/p')
check "SCIM deactivates that account" 200 "$(code -H "$AUTH" -H "$CT" -X PATCH "$BASE/Users/$SSO_UID" \
    -d '{"Operations":[{"op":"replace","path":"active","value":false}]}')"
LIVE=$(curl -sk -b "$W/jar" -o /dev/null -w '%{http_code}' "$GUI/api/core/menu/search")
[ "$LIVE" != "200" ] && ok "the open session was killed by the deactivation" \
    || ko "the session survived the deactivation"
vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null
AGAIN=$(python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol oidc \
    --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$W/jar2" | tail -1)
check "and the user can no longer log back in" 400 "$AGAIN"

# --- 9. the real client ----------------------------------------------------------
# Everything above drives our endpoint directly. This drives Authentik's own SCIM
# client against it, which is the only way to know the two actually agree.
if [ "$IDP" = "authentik" ]; then
    echo ">>> case 9: Authentik's own SCIM client provisions and revokes"
    AK_API=http://127.0.0.1:9000/api/v3
    AK_TOK=$(python3 -c "
for line in open('../idp/authentik/.env'):
    if line.startswith('AUTHENTIK_BOOTSTRAP_TOKEN='):
        print(line.split('=', 1)[1].strip()); break
")
    AK_SCIM_TOKEN=$(python3 -c "
for line in open('/tmp/authentik-out.env'):
    if line.startswith('SCIM_TOKEN='):
        print(line.split('=', 1)[1].strip()); break
" 2>/dev/null)
    AK_PK=$(python3 -c "
for line in open('/tmp/authentik-out.env'):
    if line.startswith('SCIM_PROVIDER_PK='):
        print(line.split('=', 1)[1].strip()); break
" 2>/dev/null)
    if [ -z "$AK_TOK" ] || [ -z "$AK_PK" ]; then
        echo "  SKIP Authentik SCIM provider not set up (run idp/authentik/setup.sh)"
    else
        # The firewall has to accept the token Authentik was given, not ours.
        set_provider "sso_scim_token=$AK_SCIM_TOKEN sso_scim_trusted=$ANY_SOURCE"
        ak() { curl -s -H "Authorization: Bearer $AK_TOK" -H 'Content-Type: application/json' "$@"; }
        # A user of its own, so the suite never disables the admin whose token it uses.
        AK_UID=$(ak "$AK_API/core/users/?username=scimprobe" | python3 -c "
import json,sys
r = json.load(sys.stdin)['results']
print(r[0]['pk'] if r else '')")
        if [ -z "$AK_UID" ]; then
            AK_UID=$(ak -X POST "$AK_API/core/users/" \
                -d '{"username":"scimprobe","name":"SCIM Probe","is_active":true,"path":"users"}' \
                | python3 -c "import json,sys;print(json.load(sys.stdin).get('pk',''))")
        fi
        [ -n "$AK_UID" ] && ok "test user exists in Authentik (pk $AK_UID)" || ko "could not create the Authentik user"

        ak -X POST "$AK_API/providers/scim/$AK_PK/sync/object/" \
            -d "{\"sync_object_model\":\"authentik.core.models.User\",\"sync_object_id\":\"$AK_UID\",\"override_dry_run\":true}" >/dev/null
        sleep 2
        vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scimprobe" | grep -q 'disabled=0' \
            && ok "Authentik provisioned the account on the firewall" \
            || ko "the account was not provisioned ($(vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scimprobe"))"

        ak -X PATCH "$AK_API/core/users/$AK_UID/" -d '{"is_active":false}' >/dev/null
        ak -X POST "$AK_API/providers/scim/$AK_PK/sync/object/" \
            -d "{\"sync_object_model\":\"authentik.core.models.User\",\"sync_object_id\":\"$AK_UID\",\"override_dry_run\":true}" >/dev/null
        sleep 2
        vm "php /home/vagrant/os-sso/test/vagrant/dump_user.php scimprobe" | grep -q 'disabled=1' \
            && ok "deactivating in Authentik disabled the firewall account" \
            || ko "the deactivation did not reach the firewall"
        ak -X DELETE "$AK_API/core/users/$AK_UID/" >/dev/null
    fi
fi

echo ">>> restoring the provider"
set_provider "sso_default_groups=admins sso_scim_enabled=0 sso_scim_token= sso_scim_trusted="
vm "php /home/vagrant/os-sso/test/vagrant/reset_sso_users.php" >/dev/null

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
