#!/bin/sh
# os-sso: write an OpenVPN deferred-auth verdict (root, via configd).
#   vpn_verdict.sh <sid> <0|1> <browser_ip>
# The auth-user-pass-verify script stored {sid -> control_file, client_ip}. We
# resolve and consume that mapping (single use), require the browser that
# completed the SSO login to share the VPN client's source IP, then write the
# verdict OpenVPN waits for.
set -eu

SID=$(printf '%s' "${1:-}" | tr -cd 'a-f0-9')
VERDICT=$(printf '%s' "${2:-0}" | tr -cd '01')
BROWSER_IP=$(printf '%s' "${3:-}" | tr -cd '0-9a-fA-F.:')
[ -n "$VERDICT" ] || VERDICT=0

DIR=/var/tmp/os-sso-vpn
MAP="$DIR/$SID"

if [ -z "$SID" ] || [ ! -f "$MAP" ]; then
    echo "unknown vpn session"
    exit 1
fi

CONTROL=$(sed -n 1p "$MAP")
CLIENT_IP=$(sed -n 2p "$MAP")
rm -f "$MAP"   # single use

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

printf '%s' "$VERDICT" > "$CONTROL"
echo "ok"
