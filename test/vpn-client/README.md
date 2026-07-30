# os-sso VPN - validate the deferred web-auth flow by hand

`test/e2e/vpn-client.sh` automates all of this with the plain CLI. What follows is for
driving it yourself with a real GUI client, which is what an actual user has.

A lab OpenVPN server runs in the VM on udp 1194 (forwarded to the host, and reachable on
the host-only address), wired to the os-sso `auth-user-pass-verify` hook. Authentication
happens in the browser through the same OIDC/SAML flow as the WebGUI.

Start the server first, from `test/`:
```sh
vagrant ssh -c 'sudo sh /home/vagrant/os-sso/test/vagrant/setup-vpn-server.sh'
```
Server log in the VM: `/var/log/openvpn-sso.log`.

## You need a web-auth-capable client

The plain `openvpn` CLI does **not** advertise `IV_SSO=webauth`, so the hook denies it - by
design, there would be no browser to drive. (The e2e suite forces it with
`setenv IV_SSO webauth`, which is a test fixture, not a real client.) Use one of:

- **OpenVPN Connect** (Windows/macOS/Linux GUI) - https://openvpn.net/client/
- **OpenVPN 3 Linux** (`openvpn3`) - https://github.com/OpenVPN/openvpn3-linux

## Connect from the same address you browse from

The verdict is only written if the browser completing the login comes from the **same IP**
as the VPN client - that is what binds the approval to the peer that asked. Connecting over
the NAT forward (`127.0.0.1:1194`) while browsing the host-only address, or the reverse, is
two different source IPs and the tunnel is correctly refused. Pick one path and stay on it.

Pull the generated profile onto the host (run from `test/`):
```sh
vagrant ssh -c 'sudo cat /usr/local/etc/sso/client.ovpn' > client.ovpn
```

OpenVPN 3 Linux:
```sh
openvpn3 session-start --config client.ovpn
# when prompted for a username, type anything (e.g. "sso"); leave the password blank
# openvpn3 prints / opens a WEB_AUTH url -> authenticate in the browser
```

OpenVPN Connect: import `client.ovpn`, connect, enter any username. The app opens the IdP
login in a browser.

## What happens

1. Client connects → the server runs the hook → it defers (pending auth) and hands the
   client a `WEB_AUTH::https://<host>/api/sso/<proto>/login?provider=…&vpn=<sid>` url.
2. The browser opens it → you log in at the IdP (Keycloak/Authentik) → "VPN authorized".
3. os-sso writes the verdict into OpenVPN's control file (via configd) → the tunnel comes
   up and the client gets an address in `10.8.0.0/24`.

## Switch protocol / provider

`/usr/local/etc/sso/vpn.conf` is **generated** - editing it is overwritten on the next
template reload. Change the settings instead, either in the GUI under
*System > Access > SSO VPN web-auth*, or from `test/`:

```sh
vagrant ssh -c 'sudo php /home/vagrant/os-sso/test/vagrant/set_vpn_settings.php \
    protocol=saml provider=keycloak-saml'
```

Fields: `protocol` (`oidc`|`saml`), `provider` (an OIDC/SAML auth server name), `host`
(what the client's browser opens), `timeout`, `enforce_username`. The helper re-renders
`vpn.conf` for you.

**About the username.** OpenVPN keeps using the name the client typed - it never asks again
on a deferred path - so it, not the authenticated account, is what drives
`username-as-common-name`, a `client-config-dir` and per-user rules. Both names are logged
on the firewall. Set `enforce_username=1` to refuse the tunnel when they differ; leave it
off for the throwaway-username flow above.

## Browser cert warnings

The lab uses self-signed / lab-CA certificates, so the browser warns for both the firewall
and the IdP host - click through (Advanced → Proceed).
