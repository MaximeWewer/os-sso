#!/bin/sh
# os-sso: write an OpenVPN deferred-auth verdict (root, via configd).
#   vpn_verdict.sh <sid> <0|1> <browser_ip> [<authenticated_username>]
# The auth-user-pass-verify script stored {sid -> control_file, client_ip,
# claimed_username}. We resolve and consume that mapping (single use), require the
# browser that completed the SSO login to share the VPN client's source IP, then
# write the verdict OpenVPN waits for.
set -eu

SID=$(printf '%s' "${1:-}" | tr -cd 'a-f0-9')
VERDICT=$(printf '%s' "${2:-0}" | tr -cd '01')
BROWSER_IP=$(printf '%s' "${3:-}" | tr -cd '0-9a-fA-F.:')
# The account that actually signed in at the IdP.
AUTH_USER=$(printf '%s' "${4:-}" | tr -d '\r\n' | tr -cd '\40-\176')
[ -n "$VERDICT" ] || VERDICT=0

# Same file the hook reads, for ENFORCE_USERNAME. Which profile's, though, is only
# known once the session mapping below has been read -- so the lookup happens there.
CONF=/usr/local/etc/sso/vpn.conf
[ -r "$CONF" ] && . "$CONF"

# Root-owned tree (/var/db is 0755 root:wheel), not the world-writable /var/tmp:
# the session map decides which control file we write a positive verdict into.
DIR=/var/db/os-sso-vpn
MAP="$DIR/$SID"

if [ -z "$SID" ]; then
    echo "unknown vpn session"
    exit 1
fi

# Atomically claim the mapping: the rename is the single-use gate, so two
# concurrent verdicts for one sid cannot both read it (the loser's mv fails).
# mv on a missing source also fails, covering the unknown-session case.
WORK="$MAP.$$"
if ! mv "$MAP" "$WORK" 2>/dev/null; then
    echo "unknown vpn session"
    exit 1
fi

CONTROL=$(sed -n 1p "$WORK")
CLIENT_IP=$(sed -n 2p "$WORK")
CLAIMED_USER=$(sed -n 3p "$WORK")   # empty for a session started before the upgrade
PROFILE=$(sed -n 4p "$WORK")        # likewise
rm -f "$WORK"   # single use

# The username rule belongs to the profile that deferred this attempt. A session file
# written before profiles existed names none, and then there is nothing to look up.
case "$PROFILE" in
    ''|*[!A-Za-z0-9_]*) ENFORCE_USERNAME=0 ;;
    *) eval "ENFORCE_USERNAME=\"\${PROFILE_${PROFILE}_ENFORCE_USERNAME:-0}\"" ;;
esac

case "$CONTROL" in
    /*) ;;
    *) echo "invalid control path"; exit 1 ;;
esac

# IP binding: if the client IP was captured, the browser completing the login must
# match it. Mismatch -> deny the tunnel (write 0) and fail.
if [ -n "$CLIENT_IP" ] && [ "$CLIENT_IP" != "$BROWSER_IP" ]; then
    printf '0' > "$CONTROL"
    echo "client/browser ip mismatch"
    exit 1
fi

# OpenVPN keeps using the username the client sent -- it never asks again on a
# deferred path -- so the name that drives username-as-common-name, client-config-dir
# and per-user rules is whatever the client asked for, while the browser login only
# decided WHETHER the tunnel comes up. The two names land in two different logs and
# nothing joins them, so log both here, and refuse the mismatch when the operator
# turned that on. A client that sent no username has nothing to spoof.
if [ -n "$CLAIMED_USER" ] && [ "$CLAIMED_USER" != "$AUTH_USER" ]; then
    if [ "$ENFORCE_USERNAME" = "1" ]; then
        printf '0' > "$CONTROL"
        logger -t os-sso -p auth.warning \
            "vpn: refused, client asked for '$CLAIMED_USER' but '$AUTH_USER' signed in"
        echo "username mismatch"
        exit 1
    fi
    logger -t os-sso -p auth.notice \
        "vpn: client asked for '$CLAIMED_USER', '$AUTH_USER' signed in (not enforced)"
fi

printf '%s' "$VERDICT" > "$CONTROL"
echo "ok"
