# os-sso test lab

Two independent layers:

- **`unit/`** - the security-deciding logic, called directly. No dependency but PHP.
- **`e2e/`** - the real thing: a Vagrant OPNsense VM plus Authentik and Keycloak in
  Docker, driven through actual browser ceremonies.

## Unit tests

```sh
php unit/run.php                 # everything
php unit/run.php scim            # only matching suites
```

Covers what an end-to-end run never reaches, because every case is a *refusal*: which
local account an asserted identity may bind to, which group a directory may fill, what
counts as a same-site return URL, how the client authenticates to a token endpoint.

Several groups need `/var/db/os-sso` (where the config lock and the session registry
live) and report `skip` rather than fail without it, so the suite still runs
unprivileged. One case inside them additionally wants root and a `nobody` account, to
make that directory unusable the way `StateDir` itself judges it -- which is what proves
a captive-portal grant nothing can record is given back rather than kept. For the full
set, either:

```sh
docker run --rm -v "$PWD/..:/w" -w /w php:8.3-cli php test/unit/run.php
vagrant ssh -c 'cd /home/vagrant/os-sso && sudo php test/unit/run.php'
```

## Bringing the lab up

`vagrant up` is self-contained: it pushes the source over SCP and deploys the plugin into
the live tree, no manual steps.

```sh
vagrant up                            # boot the OPNsense VM + deploy the plugin
cd idp && ./up.sh                     # start Authentik + Keycloak (+ TLS proxy)
bash keycloak/setup-keycloak.sh       # create realm, clients, test user
bash authentik/setup.sh               # create OIDC/SAML providers + mappings
```

Host `/etc/hosts` needs `127.0.0.1 authentik.test keycloak.test`. The VM gets a host-only
address (`192.168.60.10`) *and* a NAT forward for the WebGUI; override either when
something already owns it:

```sh
SSO_LAN_IP=192.168.60.10 SSO_GUI_PORT=8444 vagrant up      # host-only + WebGUI forward
KC_HTTP_PORT=8091 ./up.sh keycloak                         # Keycloak admin port
SP_BASE=https://192.168.60.10 bash keycloak/setup-keycloak.sh
```

### One origin, end to end

`SP_BASE`, the auth server's **Base URL** and `SSO_GUI_URL` must all be the same string.
The OIDC/SAML anti-replay material (state, nonce, PKCE) lives in a session cookie, so a
login started on one origin with a callback landing on another will not find it.

Prefer the host-only address: the captive portal listens on `8000+zoneid` of the zone
interface and redirects there, which a NAT forward cannot reach. (192.168.60/24 rather
than the usual .56 because VMware takes `vmnet2`/`vmnet3` there, and VirtualBox only
allows host-only addresses inside 192.168.56.0/21 without `/etc/vbox/networks.conf`.)

## Running the suites

```sh
export SSO_GUI_URL=https://192.168.60.10       # must match the provider Base URL
e2e/run-all.sh                                 # everything, Keycloak
IDP=authentik e2e/run-all.sh                   # same, Authentik
e2e/run-all.sh oidc saml                       # a subset
e2e/oidc.sh                                    # or one suite on its own
```

| Suite | Where | Checks | Covers |
|---|---|---|---|
| `oidc.sh` | host | 42-43 | the browser ceremony, Host-header hardening, diagnostics + UI pages, logout CSRF, pushed authorization requests, rate limiting, required groups, deprovisioning, session expiry, back-channel logout, service scoping, ending a session from the diagnostics page |
| `saml.sh` | host | 16-21 | per-provider EntityID/ACS/SLO, assertion replay, IdP-initiated (off/on/off - Keycloak only), POST binding, metadata import, SLO |
| `portal.sh` | host | 11 | a captive client signing in, being authorized in its zone, and being disconnected again when its grant is revoked |
| `vpn-client.sh` | host | 5 | a real OpenVPN client: deferred auth, WEB_AUTH url, tunnel up after the browser login |
| `scim.sh` | host | 46 | discovery, bearer + source gate, user lifecycle, filters, the four refusals, session revocation on deactivate, and Authentik's real SCIM client |
| `jwt.sh` | VM | 17 | source gate, signature/aud, `iat`, max-age, single-use, group mapping |
| `cp.sh` | VM | 8 | the authorizer gates, CORS scoping, and a real configd allow |
| `vpn.sh` | VM | 23 | the hook and the verdict writer, profile resolution, IP binding, single-use session ids, username enforcement, the common name a revocation kills, stale-session sweep |

Host-side suites drive the whole ceremony through `e2e/lib/idp_login.py`, which speaks
both dialects: Keycloak renders a login form, Authentik drives a flow-executor API. They
run from any directory - each resolves its own location first, symlinks included - and say
so rather than failing blank if started from an incomplete copy.

`vpn-client.sh` needs `openvpn` on the host and the lab VPN server started with
`vagrant ssh -c 'sudo sh /home/vagrant/os-sso/test/vagrant/setup-vpn-server.sh'`; it skips
itself when openvpn is missing. See [vpn-client/README.md](vpn-client/README.md) for
driving the flow by hand with a real GUI client.

## When it breaks for the wrong reason

Three failure modes that look like plugin bugs and are not:

- **Clock drift.** A suspended VirtualBox guest drifts, and its NTP has no route out here
  (the WAN interface is disabled). Past the 60s signing leeway every login fails on the
  *token* - `Cannot handle token with iat prior to ...` - which reads like anything but a
  clock problem. `run-all.sh` resynchronises from the host before it starts; tune with
  `SSO_CLOCK_TOLERANCE` (default 5s), disable with `SSO_SKIP_CLOCK_SYNC=1`.
- **An enabled captive portal zone** installs pf `rdr` rules that intercept http/https on
  the LAN interface - the very origin the host-side suites use - so a leftover zone breaks
  the *next* run with a TLS handshake error. `cp.sh` and `portal.sh` disable their zones on
  the way out; `vagrant/disable_cp_zones.php` does it by hand.
- **Leftover account state.** `scim.sh` and the deprovisioning cases deliberately disable
  accounts. `vagrant/reset_sso_users.php` puts them back; `run-all.sh` does not, so a suite
  run on its own after another may find a disabled user.
