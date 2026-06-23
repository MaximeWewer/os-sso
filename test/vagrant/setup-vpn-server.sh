#!/bin/sh
# Lab OpenVPN server wired to the os-sso deferred web-auth hook.
# Run inside the VM as root. Idempotent; (re)starts the server.
set -eu

PKI=/usr/local/etc/sso/pki
CONF=/usr/local/etc/sso/vpn-server.conf
HOOK=/usr/local/etc/sso/auth-user-pass-verify.sh

mkdir -p "$PKI"
cd "$PKI"

# --- minimal EC PKI (CA + server cert). Clients authenticate via web-auth, not
#     a client cert (verify-client-cert none), so no client cert is issued. ---
if [ ! -f ca.crt ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
        -subj "/CN=os-sso-vpn-CA"
fi
if [ ! -f server.crt ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out server.key
    openssl req -new -key server.key -out server.csr -subj "/CN=os-sso-vpn-server"
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 3650 -sha256 -out server.crt \
        -extfile /dev/stdin <<'EXT'
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EXT
    rm -f server.csr
fi

# --- server config ---
cat > "$CONF" <<EOF
dev tun
proto udp
port 1194
ca   $PKI/ca.crt
cert $PKI/server.crt
key  $PKI/server.key
dh none
topology subnet
server 10.8.0.0 255.255.255.0
keepalive 10 60
persist-key
persist-tun
verify-client-cert none
auth-user-pass-verify $HOOK via-file
auth-user-pass-optional
script-security 2
tmp-dir /var/tmp
verb 4
log /var/log/openvpn-sso.log
status /var/log/openvpn-sso-status.log 5
EOF

# --- (re)start the server ---
pkill -f "openvpn --config $CONF" 2>/dev/null || true
sleep 1
openvpn --config "$CONF" --daemon
sleep 1

echo ">>> openvpn server status:"
sockstat -4 -l 2>/dev/null | grep ':1194' || netstat -an 2>/dev/null | grep '1194' | head -1
pgrep -lf "openvpn --config" || echo "!! openvpn not running -- check /var/log/openvpn-sso.log"

# --- emit a client profile (CA inlined; web-auth, no client cert) ---
cat > /usr/local/etc/sso/client.ovpn <<EOF
client
dev tun
proto udp
remote 127.0.0.1 1194
nobind
remote-cert-tls server
verb 4
<ca>
$(cat "$PKI/ca.crt")
</ca>
EOF
echo ">>> client profile written: /usr/local/etc/sso/client.ovpn"
