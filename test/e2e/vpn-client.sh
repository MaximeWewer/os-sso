#!/usr/bin/env bash
# OpenVPN deferred web-auth with a REAL client, driven from the host.
#
# test/e2e/vpn.sh exercises the two scripts in isolation; this one puts an actual
# OpenVPN client in front of them: connect, get deferred, complete the SSO login in
# the "browser", and check the tunnel comes up.
#
# The client runs with `dev null` because bringing up a tun device needs root and the
# tunnel payload is not what is under test -- the authentication handshake is.
#
# Prerequisites: `openvpn` on the host, the lab VPN server started in the VM
#   (vagrant ssh -c 'sudo sh /home/vagrant/os-sso/test/vagrant/setup-vpn-server.sh'),
# and vpn.conf pointing at a working provider (System > Access > SSO VPN web-auth).
#
# Usage: SSO_GUI_PORT=8444 ./vpn-client.sh
set -uo pipefail
cd "$(dirname "$0")"

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
pass=0; fail=0

cleanup() {
    [ -f "$W/vpn.pid" ] && kill "$(cat "$W/vpn.pid")" 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT

ok()   { echo "  PASS $1"; pass=$((pass+1)); }
ko()   { echo "  FAIL $1"; fail=$((fail+1)); }
vm()   { vagrant ssh -c "sudo sh -c '$1'" 2>/dev/null | tr -d '\r'; }

echo "=== os-sso OpenVPN web-auth with a real client (idp=$IDP) ==="

command -v openvpn >/dev/null || { echo "  SKIP openvpn is not installed on the host"; exit 0; }

echo ">>> fetching the lab client profile"
vm "cat /usr/local/etc/sso/client.ovpn" > "$W/client.ovpn"
if ! grep -q '^remote ' "$W/client.ovpn"; then
    echo "  FAIL no client profile in the VM (run vagrant/setup-vpn-server.sh first)"
    exit 1
fi
# The tunnel and the browser must reach the firewall over the SAME path: os-sso only
# releases the tunnel when the browser completing the login comes from the VPN
# client's own address. Connecting over NAT while browsing over host-only (or the
# reverse) is two different source IPs, and the verdict is correctly refused.
VPN_REMOTE=${VPN_REMOTE:-$(printf '%s' "$GUI" | sed -e 's#^https\?://##' -e 's#[:/].*##')}
{
    sed "s/^remote .*/remote $VPN_REMOTE 1194/" "$W/client.ovpn"
    # OpenVPN Connect advertises this natively; the CLI has to be told, otherwise the
    # hook denies the connection (by design -- there would be no browser to drive).
    printf '\nsetenv IV_SSO webauth\nauth-user-pass %s/creds\nauth-retry none\n' "$W"
} > "$W/client-webauth.ovpn"
echo "    connecting to $VPN_REMOTE (same path as the browser)"
printf 'sso\nsso\n' > "$W/creds"

vm "rm -f /var/db/os-sso/ratelimit/*.json" >/dev/null

echo ">>> connecting (expect the server to defer)"
openvpn --config "$W/client-webauth.ovpn" --dev null --verb 4 --log "$W/vpn.log" \
        --connect-retry-max 1 --tls-exit &
echo $! > "$W/vpn.pid"

for _ in $(seq 1 30); do
    grep -q 'WEB_AUTH::' "$W/vpn.log" 2>/dev/null && break
    sleep 1
done

if grep -q 'AUTH_PENDING received' "$W/vpn.log" 2>/dev/null; then
    ok "server deferred the connection (AUTH_PENDING)"
else
    ko "no AUTH_PENDING from the server"
fi

URL=$(grep -o "WEB_AUTH::[^']*" "$W/vpn.log" | head -1 | sed 's/WEB_AUTH:://')
case "$URL" in
    "$GUI"/api/sso/*login*vpn=*) ok "client received a WEB_AUTH url with a session id" ;;
    *) ko "unexpected WEB_AUTH url ($URL)"; echo ">>> RESULT: $pass passed, $((fail)) failed"; exit 1 ;;
esac

echo ">>> completing the login in the browser"
BODY=$(python3 lib/idp_login.py --gui "$GUI" --provider "$PROVIDER" --protocol oidc \
    --idp "$IDP" --user "$IDP_USER" --password "$IDP_PASS" --jar "$W/jar" \
    --start-url "$URL" --body "$W/done.html" 2>/dev/null | tail -1)
[ "$BODY" = "200" ] && ok "the SSO login returned the VPN confirmation page" \
    || ko "login returned $BODY"
grep -q 'VPN authorized' "$W/done.html" 2>/dev/null && ok "page confirms the tunnel is authorized" \
    || ko "unexpected confirmation page"

echo ">>> waiting for the tunnel"
for _ in $(seq 1 30); do
    grep -q 'Initialization Sequence Completed' "$W/vpn.log" 2>/dev/null && break
    sleep 1
done
grep -q 'Initialization Sequence Completed' "$W/vpn.log" \
    && ok "tunnel established after the browser login" \
    || ko "the tunnel never came up ($(grep -c AUTH_FAILED "$W/vpn.log") AUTH_FAILED lines)"

echo ""
echo ">>> RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
