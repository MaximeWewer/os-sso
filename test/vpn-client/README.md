# os-sso VPN — validate the deferred web-auth flow

A lab OpenVPN server runs in the VM (udp `127.0.0.1:1194`), wired to the os-sso
`auth-user-pass-verify` hook. Authentication happens in the browser via the same
OIDC/SAML flow as the WebGUI.

## You need a web-auth-capable client

The plain `openvpn` CLI does **not** support the browser web-auth flow (it does not
advertise `IV_SSO=webauth`, so the server denies it — by design). Use one of:

- **OpenVPN Connect** (Windows/macOS/Linux GUI) — https://openvpn.net/client/
- **OpenVPN 3 Linux** (`openvpn3`) — https://github.com/OpenVPN/openvpn3-linux

## Connect

The client profile is generated inside the VM at `/usr/local/etc/sso/client.ovpn`.
Pull it onto the host first (run from `test/`):
```sh
vagrant ssh -c 'sudo cat /usr/local/etc/sso/client.ovpn' > client.ovpn
```

OpenVPN 3 Linux:
```sh
openvpn3 session-start --config client.ovpn
# when prompted for a username, type anything (e.g. "sso"); leave password blank
# openvpn3 prints / opens a WEB_AUTH url -> authenticate in the browser
```

OpenVPN Connect: import `client.ovpn`, connect, enter any username. The app
opens the IdP login in a browser.

## What happens

1. Client connects → server runs the hook → defers (pending auth), hands the client
   a `WEB_AUTH::https://localhost:8443/api/sso/<proto>/login?...&vpn=<sid>` url.
2. The browser opens it → you log in at the IdP (Keycloak/Authentik) → "VPN
   authorized" page.
3. os-sso writes the verdict to OpenVPN's control file (via configd) → the tunnel
   comes up; the client gets an address in `10.8.0.0/24`.

## Switch protocol / provider

Edit `/usr/local/etc/sso/vpn.conf` in the VM, then reconnect:
```
PROTOCOL=oidc        # or: saml
PROVIDER=keycloak    # oidc: keycloak | authentik ; saml: keycloak-saml | authentik-saml
HOST=localhost:8443
TIMEOUT=180
```

## Browser cert warnings

The lab uses self-signed/lab-CA certs, so the browser will warn for
`localhost:8443` and the IdP host — click through (Advanced → Proceed).

## Restart the server

```sh
sudo sh /vagrant/test/vagrant/setup-vpn-server.sh   # in the VM
```
Server log: `/var/log/openvpn-sso.log`.
