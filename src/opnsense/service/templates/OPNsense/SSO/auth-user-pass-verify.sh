#!/bin/sh
# os-sso OpenVPN deferred web authentication (WEB_AUTH / pending-auth).
#
# Wire into an OpenVPN server with:
#   auth-user-pass-verify /usr/local/etc/sso/auth-user-pass-verify.sh via-file
#
# OpenVPN 2.5+ exports for a deferred auth attempt:
#   $username, $auth_pending_file, $auth_control_file, and peer-info $IV_SSO.
# We hand the client a WEB_AUTH url to our OIDC login and defer (exit 2). The
# os-sso OIDC callback writes the final verdict (1/0) into $auth_control_file.
set -eu
# Create the state dir/files private from the start (the session file holds the
# auth-control path + client IP); the explicit chmods below are belt-and-suspenders.
umask 077

CONF=/usr/local/etc/sso/vpn.conf
[ -r "$CONF" ] && . "$CONF"
PROTOCOL="${PROTOCOL:-oidc}"   # oidc | saml
PROVIDER="${PROVIDER:-}"
HOST="${HOST:-}"
TIMEOUT="${TIMEOUT:-180}"
STATE_DIR=/var/tmp/os-sso-vpn

case "$PROTOCOL" in
    oidc|saml) ;;
    *) echo "os-sso vpn: invalid PROTOCOL '$PROTOCOL' (oidc|saml)" >&2; exit 1 ;;
esac

if [ -z "$PROVIDER" ] || [ -z "$HOST" ]; then
    echo "os-sso vpn: PROVIDER/HOST not set in $CONF" >&2
    exit 1
fi

# The client must advertise web-auth SSO capability, else there is no browser to
# drive -- deny rather than hang.
case "${IV_SSO:-}" in
    *webauth*) ;;
    *) echo "os-sso vpn: client has no webauth capability (IV_SSO=${IV_SSO:-none})" >&2; exit 1 ;;
esac

# Deferred auth requires the pending/control files (OpenVPN 2.5+).
if [ -z "${auth_pending_file:-}" ] || [ -z "${auth_control_file:-}" ]; then
    echo "os-sso vpn: no deferred-auth support from OpenVPN" >&2
    exit 1
fi

mkdir -p "$STATE_DIR"
# Fail closed: a state dir we cannot lock down (e.g. pre-existing world-readable)
# must not hold the per-session control-file path + client IP.
chmod 700 "$STATE_DIR" || { echo "os-sso vpn: cannot secure $STATE_DIR" >&2; exit 1; }

# One-time, unguessable session id mapped to this attempt's control file + the
# client's source IP. The web callback resolves + consumes it (single use); the
# verdict is only written if the browser completing the SSO login comes from the
# same IP as the VPN client (binds the deferred approval to the connecting peer).
SID=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
CLIENT_IP="${untrusted_ip:-${trusted_ip:-}}"
{
    printf '%s\n' "$auth_control_file"
    printf '%s\n' "$CLIENT_IP"
} > "$STATE_DIR/$SID"
chmod 600 "$STATE_DIR/$SID" || { rm -f "$STATE_DIR/$SID"; echo "os-sso vpn: cannot secure session file" >&2; exit 1; }

# Defer and point the client at the browser SSO login.
{
    printf '%s\n' "$TIMEOUT"
    printf 'webauth\n'
    printf 'WEB_AUTH::https://%s/api/sso/%s/login?provider=%s&vpn=%s\n' "$HOST" "$PROTOCOL" "$PROVIDER" "$SID"
} > "$auth_pending_file"

exit 2   # 2 = authentication deferred
