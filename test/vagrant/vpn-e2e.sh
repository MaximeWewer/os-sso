#!/bin/sh
# OpenVPN deferred web-auth test (VM-local, run as root). Drives the two halves that
# OpenVPN and the SSO callback would drive: the auth-user-pass-verify hook that defers
# the connection, and the verdict writer that releases (or denies) it.
set -u
HOOK=/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh
VERDICT=/usr/local/opnsense/scripts/OPNsense/SSO/vpn_verdict.sh
STATE=/var/db/os-sso-vpn
W=/tmp/vpn-e2e
pass=0; fail=0
ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }

rm -rf "$W"; mkdir -p "$W"
: > "$W/pending"; : > "$W/control"

echo ">>> case 1: a web-auth capable client is deferred"
env IV_SSO=webauth,crtext auth_pending_file="$W/pending" auth_control_file="$W/control" \
    untrusted_ip=203.0.113.7 sh "$HOOK" >"$W/out" 2>&1
rc=$?
[ "$rc" = "2" ] && ok "hook exits 2 (deferred)" || ko "hook exit $rc ($(cat "$W/out"))"
grep -q '^WEB_AUTH::https://' "$W/pending" && ok "pending file carries a WEB_AUTH url" \
    || ko "pending file ($(cat "$W/pending" | tr '\n' ' '))"
grep -q 'api/sso/oidc/login?provider=' "$W/pending" && ok "url points at the SSO login" \
    || ko "unexpected WEB_AUTH url"
SID=$(sed -n 's/.*&vpn=//p' "$W/pending")
[ -n "$SID" ] && ok "session id minted ($SID)" || ko "no session id in the url"
[ -f "$STATE/$SID" ] && ok "session file created under $STATE" || ko "no session file in $STATE"

echo ">>> case 2: the state directory is private"
MODE=$(stat -f '%Lp' "$STATE" 2>/dev/null)
[ "$MODE" = "700" ] && ok "state dir is 0700" || ko "state dir mode is $MODE"

echo ">>> case 3: a client without web-auth support is refused, not hung"
: > "$W/pending2"
env IV_SSO=crtext auth_pending_file="$W/pending2" auth_control_file="$W/control" \
    untrusted_ip=203.0.113.7 sh "$HOOK" >"$W/out2" 2>&1
rc=$?
[ "$rc" = "1" ] && ok "hook exits 1 (deny)" || ko "hook exit $rc"

echo ">>> case 4: a verdict from a different IP than the VPN client is denied"
"$VERDICT" "$SID" 1 198.51.100.9 >"$W/v1" 2>&1
grep -q 'ip mismatch' "$W/v1" && ok "mismatched browser IP refused ($(cat "$W/v1"))" \
    || ko "mismatch not caught ($(cat "$W/v1"))"
[ "$(cat "$W/control")" = "0" ] && ok "a deny was written to the control file" \
    || ko "control file holds '$(cat "$W/control")'"

echo ">>> case 5: the session id is single use"
"$VERDICT" "$SID" 1 203.0.113.7 >"$W/v2" 2>&1
grep -q 'unknown vpn session' "$W/v2" && ok "consumed session id cannot be reused" \
    || ko "reuse not caught ($(cat "$W/v2"))"

echo ">>> case 6: a matching browser IP releases the tunnel"
: > "$W/pending3"; : > "$W/control3"
env IV_SSO=webauth auth_pending_file="$W/pending3" auth_control_file="$W/control3" \
    untrusted_ip=203.0.113.7 sh "$HOOK" >/dev/null 2>&1
SID2=$(sed -n 's/.*&vpn=//p' "$W/pending3")
"$VERDICT" "$SID2" 1 203.0.113.7 >"$W/v3" 2>&1
[ "$(cat "$W/v3")" = "ok" ] && ok "verdict accepted" || ko "verdict said '$(cat "$W/v3")'"
[ "$(cat "$W/control3")" = "1" ] && ok "the tunnel was authorized (control file = 1)" \
    || ko "control file holds '$(cat "$W/control3")'"

echo ">>> case 7: an unknown session id is refused"
"$VERDICT" deadbeefdeadbeef 1 203.0.113.7 >"$W/v4" 2>&1
grep -q 'unknown vpn session' "$W/v4" && ok "unknown session id refused" \
    || ko "unknown id accepted ($(cat "$W/v4"))"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
