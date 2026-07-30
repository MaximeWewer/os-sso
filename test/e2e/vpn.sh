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
case "$(cat "$W/v3")" in ok*) ok "verdict accepted" ;; *) ko "verdict said '$(cat "$W/v3")'" ;; esac
[ "$(cat "$W/control3")" = "1" ] && ok "the tunnel was authorized (control file = 1)" \
    || ko "control file holds '$(cat "$W/control3")'"

echo ">>> case 7: an unknown session id is refused"
"$VERDICT" deadbeefdeadbeef 1 203.0.113.7 >"$W/v4" 2>&1
grep -q 'unknown vpn session' "$W/v4" && ok "unknown session id refused" \
    || ko "unknown id accepted ($(cat "$W/v4"))"

# OpenVPN keeps using the username the CLIENT sent -- it never asks again on a deferred
# path -- so that name, not the authenticated one, drives username-as-common-name, a
# client-config-dir and per-user rules. The state file records both so a mismatch is
# visible, and refuses it when the operator asked.
defer() { # $1 = claimed username, $2 = pending file -> echoes the session id
    : > "$2"
    env IV_SSO=webauth username="$1" auth_pending_file="$2" auth_control_file="$3" \
        untrusted_ip=203.0.113.7 sh "$HOOK" >/dev/null 2>&1
    sed -n 's/.*&vpn=//p' "$2"
}

echo ">>> case 8: the claimed username is recorded alongside the control path"
SID3=$(defer 'claimed.bob' "$W/pending4" "$W/control4")
[ "$(sed -n 3p "$STATE/$SID3")" = "claimed.bob" ] \
    && ok "the client-supplied username is stored" \
    || ko "line 3 of the session file is '$(sed -n 3p "$STATE/$SID3")'"

# The verdict script sources vpn.conf AFTER the environment, so the file is what
# decides -- which is right in production, and means the setting has to be flipped there
# to test it. The generated file is restored from the model at the end of the suite.
CONF=/usr/local/etc/sso/vpn.conf
set_enforce() {
    # Per profile now: the verdict script resolves the flag of the profile that
    # deferred the attempt, which is the one the hook recorded in the session file.
    P=$(sed -n "s/^DEFAULT_PROFILE='\(.*\)'$/\1/p" "$CONF")
    sed -i '' "/^PROFILE_${P}_ENFORCE_USERNAME=/d" "$CONF" 2>/dev/null
    printf "PROFILE_%s_ENFORCE_USERNAME='%s'\n" "$P" "$1" >> "$CONF"
}

echo ">>> case 9: a mismatch is allowed but logged while enforcement is off"
set_enforce 0
: > "$W/control4"
"$VERDICT" "$SID3" 1 203.0.113.7 'real.alice' >"$W/v5" 2>&1
case "$(cat "$W/v5")" in ok*) ok "a differing username is accepted when not enforced" ;; \
    *) ko "verdict said '$(cat "$W/v5")'" ;; esac
[ "$(cat "$W/control4")" = "1" ] && ok "and the tunnel was authorized" \
    || ko "control file holds '$(cat "$W/control4")'"

echo ">>> case 10: with enforcement on, a mismatch is refused"
SID4=$(defer 'claimed.bob' "$W/pending5" "$W/control5")
: > "$W/control5"
set_enforce 1
"$VERDICT" "$SID4" 1 203.0.113.7 'real.alice' >"$W/v6" 2>&1
grep -q 'username mismatch' "$W/v6" && ok "the mismatch is refused ($(cat "$W/v6"))" \
    || ko "mismatch not caught ($(cat "$W/v6"))"
[ "$(cat "$W/control5")" = "0" ] && ok "a deny was written to the control file" \
    || ko "control file holds '$(cat "$W/control5")'"

echo ">>> case 11: with enforcement on, a matching username passes"
SID5=$(defer 'real.alice' "$W/pending6" "$W/control6")
: > "$W/control6"
"$VERDICT" "$SID5" 1 203.0.113.7 'real.alice' >"$W/v7" 2>&1
case "$(cat "$W/v7")" in ok*) ok "a matching username is accepted" ;; \
    *) ko "verdict said '$(cat "$W/v7")'" ;; esac
[ "$(cat "$W/control6")" = "1" ] && ok "and the tunnel was authorized" \
    || ko "control file holds '$(cat "$W/control6")'"

echo ">>> case 12: a client that sent no username has nothing to spoof"
SID6=$(defer '' "$W/pending7" "$W/control7")
: > "$W/control7"
"$VERDICT" "$SID6" 1 203.0.113.7 'real.alice' >"$W/v8" 2>&1
case "$(cat "$W/v8")" in ok*) ok "an empty claimed username is not refused" ;; \
    *) ko "verdict said '$(cat "$W/v8")'" ;; esac

echo ">>> case 12b: the verdict names the tunnel's common name"
SID7=$(defer 'claimed.carol' "$W/pending9" "$W/control9")
: > "$W/control9"
"$VERDICT" "$SID7" 1 203.0.113.7 'real.alice' >"$W/v9" 2>&1
# It is what SessionRegistry records so a later revocation can kill the tunnel: OpenVPN
# knows the client by the name it sent, not by the account that signed in.
[ "$(cat "$W/v9")" = "ok claimed.carol" ] && ok "the common name comes back with the verdict" \
    || ko "verdict said '$(cat "$W/v9")'"

echo ">>> case 13: abandoned session files are swept"
STALE="$STATE/staleaaaabbbbccccddddeeeeffff0000"
printf '/tmp/x\n203.0.113.7\nold\n' > "$STALE"
touch -t 202001010000 "$STALE"
defer 'sweep.probe' "$W/pending8" "$W/control8" >/dev/null
[ ! -f "$STALE" ] && ok "a session file older than the web-auth timeout is removed" \
    || ko "the stale session file survived"

# Put the generated file back the way the model says.
configctl template reload OPNsense/SSO >/dev/null 2>&1

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
