# os-sso - Single Sign-On for OPNsense

Add **OpenID Connect**, **SAML 2.0** and **JWT forward-auth** as authentication
types in OPNsense. The firewall acts as a pure consumer (Relying Party / Service
Provider): your users sign in at your existing Identity Provider, and MFA and
passkeys stay there - nothing to re-implement on the firewall.

Works for the **WebGUI**, the **Captive Portal** and **OpenVPN**, with group
mapping driving OPNsense privileges. The local password (+ native TOTP) always
stays available as a break-glass path.

## Features

- **OpenID Connect** - automatic `.well-known` discovery, PKCE, JWKS key
  rotation. Works with Keycloak, Authentik, Entra ID, Zitadel, …
- **SAML 2.0** - signed assertions, metadata generation, Single Logout.
- **JWT forward-auth** - trust a signed JWT from a reverse proxy in front of
  OPNsense (oauth2-proxy, Authelia, Authentik forward-auth, Cloudflare Access).
- **WebGUI login** - one button per provider on the login page.
- **Captive Portal login** via OIDC/SAML.
- **OpenVPN** login through the browser (deferred web-auth / `WEB_AUTH`).
- **Group mapping** - IdP groups become OPNsense group membership; privileges
  are resolved by the normal ACL.
- **Single Logout** - the WebGUI *Logout* button ends the IdP session too.

## Screenshots

| Authentication servers | Server configuration | WebGUI login |
|---|---|---|
| ![Authentication servers](assets/servers.png) | ![Server configuration](assets/server_config.png) | ![WebGUI login form](assets/login_form.png) |

| Captive Portal login | OpenVPN web-auth settings | SSO diagnostics |
|---|---|---|
| ![Captive portal login page](assets/cp_portal.png) | ![OpenVPN web-auth settings](assets/vpn_settings.png) | ![SSO diagnostics](assets/sso_diagnostics.png) |

## Requirements

- **OPNsense 25.7 or newer** - the login-page SSO button hook
  (`ISSOContainer` / `listSSOproviders`) landed in core in 25.7.
- For OpenVPN login: **OpenVPN 2.6+** on the firewall and a
  web-auth-capable client (OpenVPN Connect, OpenVPN 3 Linux, Windows 2.6+).
- An Identity Provider you control or use (Keycloak, Authentik, Entra ID, Zitadel, …).

## Install

Each release ships one package per FreeBSD ABI. Download the one matching your
firewall's base from the [Releases](../../releases) page - check it with
`pkg config ABI` (e.g. `FreeBSD:14:amd64` → the `…-FreeBSD-14.pkg`), then install:

```sh
pkg add os-sso-devel-*-FreeBSD-14.pkg   # pick the file matching your ABI
```

Then reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**.

> Building from source instead: see [Build](#build).

## Configure an authentication server

Go to **System ▸ Access ▸ Servers** and click **＋ Add**, then pick the **Type**.
All types share a few options:

- **Username claim/attribute** - which IdP field becomes the local username.
  Use an immutable, IdP-administered value (e.g. `preferred_username`). For SAML the
  username, email and display-name attributes are each configurable; left empty they
  try the conventional friendly names and then the NameID - set them when your IdP
  emits OID-style names such as `urn:oid:0.9.2342.19200300.100.1.1`.
- **Automatic user creation** - off by default. When on, matched users are created
  in `config.xml` with no local password (IdP-only login).
- **Required groups** - access gate: comma separated IdP group names, at least one
  of which the user must hold to get in through this provider (WebGUI, Captive
  Portal and VPN alike). Checked on the IdP-asserted groups before any local
  account is matched, created or updated. Empty means every account the IdP
  authenticates may log in - set it unless that is what you want.
- **Deprovision on refused login** - when the required groups above refuse a login,
  also disable the local account behind it and end its open sessions. A login attempt
  is the only moment a firewall plugin hears about a revocation at the IdP, so this is
  what makes "removed from the group there" reach the account here. Only
  os-sso-managed accounts are touched, never a privileged one, and they are disabled,
  not deleted.
- **Default groups** - OPNsense groups always granted to mapped users.
- **Group mapping** - optional `idpGroup:opnsenseGroup` pairs (comma separated).
  Mapped groups are trusted and may target privileged groups (e.g. `admins`). IdP
  groups with no mapping fall back to a 1:1 name match that refuses privileged
  groups (see Security).
- **Strict group sync** - off by default (membership is additive: groups are only
  ever added). When on, each login also *revokes* groups os-sso previously granted
  but the IdP no longer asserts. Only groups os-sso itself granted are touched
  (hand-assigned groups are kept), and the last member of a privileged group is
  never removed.
- **Base URL** (required, OIDC/SAML) - the firewall's public `https://host[:port]`.
  Every URL handed to the IdP is built from it: the OIDC redirect/callback, the SAML
  SP EntityID/ACS/SLO. Mind a reverse proxy or port-forward. It is required because
  the fallback would derive those URLs from the request `Host` header, which the
  client controls - an IdP doing prefix/wildcard redirect matching could then be
  talked into sending the authorization code elsewhere. The form shows the exact
  **redirect/ACS URL** live underneath this field - copy it into your IdP.
- **Maximum session lifetime** - end the WebGUI session this long after login
  regardless of activity. The WebGUI's own timeout is *idle*-only, so a kept-open tab
  otherwise never goes back through the IdP. Enforced on every SSO login and by the
  configd action **os-sso: expire SSO sessions** - schedule it under
  *System ▸ Settings ▸ Cron*, every 5 minutes is plenty. `0` disables it.
- **Default landing URL** - where users land after login when no specific page was
  requested (e.g. `/ui/dashboard`).

### OpenID Connect

1. Create a **confidential** client at your IdP with redirect URL
   `https://<opnsense>/api/sso/oidc/callback` (shown live in the form).
2. In OPNsense fill **Issuer URL** + **Client ID/Secret**. Discovery and keys are
   fetched automatically from `<issuer>/.well-known/openid-configuration`.
3. Keep **PKCE** on; scopes `openid email profile` (+ a groups scope if you map
   groups). The client authentication method (`client_secret_basic` or
   `client_secret_post`) is taken from the IdP's discovery document.
4. Optional hardening: **Maximum authentication age** sends `max_age` and enforces
   the returned `auth_time`, so an old IdP session must re-authenticate;
   **form_post response mode** keeps the authorization code out of the URL;
   **Extra authorization parameters** passes things like `prompt=login` or
   `acr_values=mfa` through to the IdP.

| Provider | Issuer URL | Groups |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | add a *Group Membership* mapper → `groups` |
| **Authentik** | `https://<authentik>/application/o/<slug>/` | add the *Groups* scope |
| **Entra ID** | `https://login.microsoftonline.com/<tenant>/v2.0` | `groups` claim (object IDs - use an explicit name map) |

### SAML 2.0

1. In OPNsense either set the **IdP metadata URL** (https) and leave the rest empty -
   the EntityID, SSO/SLO endpoints and signing certificate are read from it and
   cached for 24 h, so an IdP **signing-key rotation is picked up on its own** - or
   fill **IdP EntityID**, **IdP SSO URL** (HTTP-Redirect) and the **IdP x509
   certificate** (full PEM of the signing cert - not a fingerprint) by hand. Anything
   filled in by hand wins over the document.
2. Give your IdP the SP URLs (shown live in the form). Each SAML server is its own
   SP identity, so every endpoint carries `?provider=<server name>` - two IdPs never
   share an EntityID or ACS:
   - ACS: `https://<opnsense>/api/sso/saml/acs?provider=<name>`
   - Metadata / EntityID: `https://<opnsense>/api/sso/saml/metadata?provider=<name>`
   - SLO: `https://<opnsense>/api/sso/saml/slo?provider=<name>`
3. The IdP must **sign the assertion**. Map the NameID to the username. Optional:
   **HTTP-POST binding** for the AuthnRequest (when the IdP does not take a redirect),
   **encrypted assertions** (needs the SP certificate + key), and **IdP-initiated
   login** - the last one off by default, since an unsolicited assertion proves
   nothing about who asked to log in.
4. The IdP must send **at least one attribute** (configure attribute / property
   mappings - e.g. groups, email). An empty `<AttributeStatement/>` is invalid per
   the SAML schema and is rejected by the strict validation - and you need the
   groups attribute for group mapping anyway.

| Provider | IdP EntityID | SSO URL (redirect) |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | `https://<kc>/realms/<realm>/protocol/saml` |
| **Authentik** | `https://<authentik>/application/saml/<slug>/metadata/` (the response Issuer - note the `/metadata/` suffix) | `…/application/saml/<slug>/sso/binding/redirect/` |

### JWT forward-auth

For OPNsense behind a trusted identity-aware proxy that authenticates users and
forwards a **signed JWT in a header**.

1. Fill **Issuer** and **Audience** (both checked), and the **JWKS URL**
   (preferred - supports key rotation) or a static PEM public key.
2. Set **Trusted proxy IPs/CIDRs** - *required*. The JWT header is only accepted
   when the request comes from these source IPs (the proxy), which is what prevents
   anyone else from forging it. The match is on the **direct TCP peer**
   (`REMOTE_ADDR`), never a forwardable header - list the IP that actually connects
   to the firewall. If another reverse proxy fronts the WebGUI, that proxy's IP goes
   here and it must strip the JWT header from untrusted clients.
3. Point the proxy at `https://<opnsense>/api/sso/jwt/login?provider=<name>` and
   have it inject the token in the configured header (default `X-Auth-Request-Jwt`,
   or `Authorization: Bearer`).
4. Bound the replay window. A signed JWT is a bearer credential - whoever holds the
   bytes is the user until it expires. Both controls are off by default because they
   depend on how your proxy issues tokens:
   - **Maximum token age** - refuse tokens whose `iat` is older than N seconds, no
     matter what `exp` says.
   - **Single-use tokens** - accept each token once (keyed on `jti` when present).
     Only if the proxy mints a fresh token per login; if it reuses one token for the
     whole session (the usual oauth2-proxy setup), the second login would be refused.

Only asymmetric algorithms (`RS256`/`ES256`/…) are accepted; `exp`/`nbf` are
enforced.

## Where SSO applies

### WebGUI

Each configured OIDC/SAML/JWT server adds a **“Login with …”** button to the
firewall login page. Users click it, authenticate at the IdP, and land in the
WebGUI with privileges from their mapped groups.

### Captive Portal

1. Add the OIDC/SAML server (as above).
2. **Services ▸ Captive Portal ▸ Administration**: in the zone, add that server
   under *Authentication* (optionally set an enforce-group).
3. Build the bundled portal template and upload it:

   ```sh
   configctl sso build_cp_template     # prints /tmp/os-sso-cp-template.zip
   ```

   Upload that zip under *Templates* and select it on the zone. The page shows one
   button per SSO provider and keeps the standard username/password form. Mind the
   core naming rule: a template *name* may not contain a hyphen (letters, digits,
   `.`, `,`, `_` and spaces only).

   In the lab, `test/vagrant/setup-cp.sh` does the whole thing — zone, template,
   render, unpack, start — and documents the ordering the UI normally handles.
4. Make sure the zone lets unauthenticated clients reach the firewall WebGUI and
   the IdP (zone *allowed addresses* / pre-auth) so the login can complete.

A user who signs in through SSO gets their device authorized in that portal zone.

### OpenVPN (deferred web-auth)

OpenVPN 2.6+ “pending auth” lets the client authenticate in a browser:

1. The client connects and is shown a `WEB_AUTH` URL.
2. It opens the URL, logs in at the IdP (passkey/MFA there).
3. The tunnel comes up once the login succeeds.

Configure it under **System ▸ Access ▸ SSO VPN web-auth**: protocol, the
authentication server (picked from the configured OIDC/SAML servers), the host the
client's browser opens, and the web-auth timeout. Saving writes
`/usr/local/etc/sso/vpn.conf` (no more editing it over SSH). Then point the OpenVPN
server at the script:

```
auth-user-pass-verify /usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh via-file
```

Use a web-auth-capable client (OpenVPN Connect, OpenVPN 3 Linux) - see
`test/vpn-client/README.md`. With web-auth disabled the script denies the connection
rather than deferring it. What the client sees:

```
AUTH_PENDING received, extending handshake timeout from 60s to 240s
Info command was pushed by server ('WEB_AUTH::https://vpn.example.com/api/sso/oidc/login?provider=keycloak&vpn=48e5ef74…')
   ... the user authenticates in the browser ...
Initialization Sequence Completed
```

and on the firewall: `os-sso vpn: authorized tunnel for 'kctest' from 10.0.2.2`.

### Logout

The WebGUI **Logout** button performs Single Logout: it ends the IdP session for
OIDC (`end_session_endpoint`) and SAML, and falls back to the normal local logout
for password sessions. Register at your IdP:

- OIDC post-logout redirect: `https://<opnsense>/`
- SAML logout service: `https://<opnsense>/api/sso/saml/slo?provider=<name>`

**Back-channel logout (OIDC).** Register
`https://<opnsense>/api/sso/oidc/backchannel?provider=<name>` as the client's
back-channel logout URI and the IdP can end the firewall session by itself - when the
user logs out elsewhere, or when you disable the account. Without it (and without a
maximum session lifetime) an open session survives until it idles out. The endpoint
takes only a signed `logout_token`: issuer, audience, `iat` freshness, the
backchannel-logout event, absence of a `nonce` and single-use `jti` are all checked
before any session is ended.

### API access (not SSO)

The OPNsense **API** keeps using its own key/secret credentials - os-sso does not
turn an IdP token into API access, and cannot: API authentication is handled by core
before any plugin sees the request, so bearer-token support would have to land in
core, not here. What does work is the useful half: an account provisioned by SSO is a
normal local account, so you can issue it an API key under *System ▸ Access ▸ Users*
and the ACL applies the groups os-sso mapped. Its local *password* stays unusable -
API keys are separate credentials, not the password.

## Diagnostics

**System ▸ Access ▸ SSO Diagnostics** shows, for every configured provider, the exact
URLs to register at the IdP, the effective policy (required groups, auto-creation,
group sync, session lifetime), and a **Test** button that talks to the IdP live -
discovery + JWKS for OIDC, the metadata document for SAML, the JWKS for forward-auth.
It also lists the currently open SSO sessions and lets you **flush the caches**
(discovery, JWKS, SAML metadata, icons) after changing something at the IdP instead of
waiting out a TTL. Access is gated by its own ACL privilege,
*System: Access: SSO Diagnostics*.

## Security

- Privileges are **never** stored in the session - the OPNsense ACL resolves them
  from group membership on every request.
- New sessions regenerate their ID (anti session-fixation).
- SSO will not bind the username claim to an existing local account that has its
  own password (only to SSO-managed or passwordless accounts), and never to a
  privileged account (`root`/system or `admins`) it didn't create; email matching
  requires a verified email and an already-SSO-managed account.
- The 1:1 group fallback won't grant a privileged group (`admins`, or any group
  with full-GUI / shell / user-manager rights) without an explicit mapping.
- Group membership is additive by default; **Strict group sync** additionally
  revokes IdP-unasserted groups it earlier granted, but only those (never a
  hand-assigned group) and never the last member of a privileged group.
- A **disabled or expired** local account is refused, matching the local-password
  path (SSO is not a way around an account's expiry). The check runs before group
  sync writes anything and covers the VPN path too, not only the WebGUI session.
- OIDC validates `iss`/`aud`/`azp`/`nonce`/`exp` and requires an asymmetric
  signature; SAML verifies the assertion signature and is replay-protected
  (single-use request id + consumed-assertion cache).
- The local password (+ native TOTP) is always left active as a **break-glass**
  path - keep at least one local admin.

> `client_secret` and SP keys are stored in `config.xml` like other OPNsense
> credentials (e.g. LDAP bind passwords) and are never written to logs.

## Test / lab

A reproducible lab lives under `test/` - a Vagrant OPNsense VM plus Authentik and
Keycloak in Docker behind a TLS proxy. `vagrant up` is self-contained: it pushes
the source over SCP and deploys the plugin into the live tree (no manual steps).

```sh
cd test && vagrant up                 # boot the OPNsense VM + deploy the plugin
cd test/idp && ./up.sh                # start Authentik + Keycloak (+ TLS proxy)
bash keycloak/setup-keycloak.sh       # create realm, clients, test user
bash authentik/setup.sh               # create OIDC/SAML providers + mappings
```

Host `/etc/hosts` needs `127.0.0.1 authentik.test keycloak.test`. The VM gets a
host-only address (`192.168.60.10` by default) *and* a NAT forward for the WebGUI;
both are overridable when something else already owns them:

```sh
SSO_LAN_IP=192.168.60.10 SSO_GUI_PORT=8444 vagrant up      # host-only + WebGUI forward
KC_HTTP_PORT=8091 ./up.sh keycloak                         # Keycloak admin port
SP_BASE=https://192.168.60.10 bash keycloak/setup-keycloak.sh
```

**Use one origin end to end.** The URL given to `SP_BASE`, the **Base URL** on the
auth server, and `SSO_GUI_URL` for the suites must be the same - the OIDC/SAML
anti-replay material (state, nonce, PKCE) lives in a session cookie, so a login
started on one origin and a callback landing on another simply will not find it.

The host-only address is what the **captive portal** needs: its listener sits on
`8000+zoneid` on the zone interface and redirects there, so a NAT forward cannot
reach it. On a machine with VMware installed, 192.168.56/57 are already taken by
`vmnet2`/`vmnet3`, hence the 192.168.60.0/24 default - VirtualBox only allows
host-only addresses inside 192.168.56.0/21 unless `/etc/vbox/networks.conf` says
otherwise.

Seven end-to-end suites under `test/e2e/`, run against either IdP:

```sh
cd test/e2e
SSO_GUI_URL=https://192.168.60.10 ./run-all.sh                # everything, Keycloak
SSO_GUI_URL=https://192.168.60.10 IDP=authentik ./run-all.sh  # same, Authentik
SSO_GUI_URL=https://192.168.60.10 ./run-all.sh oidc saml      # a subset
```

| Suite | Where | Checks | Covers |
|---|---|---|---|
| `oidc.sh` | host | 28 | the browser ceremony, Host-header hardening, diagnostics + UI pages, logout CSRF, rate limiting, required groups, deprovisioning, session expiry, back-channel logout |
| `saml.sh` | host | 21 | per-provider EntityID/ACS/SLO, assertion replay, IdP-initiated (off/on/off), POST binding, metadata import, SLO |
| `portal.sh` | host | 7 | a captive client signing in and being authorized in its zone |
| `vpn-client.sh` | host | 5 | a real OpenVPN client: deferred auth, WEB_AUTH url, tunnel up after the browser login |
| `jwt.sh` | VM | 17 | source gate, signature/aud, `iat`, max-age, single-use, group mapping |
| `cp.sh` | VM | 6 | the authorizer gates and a real configd allow |
| `vpn.sh` | VM | 13 | the hook and the verdict writer, IP binding, single-use session ids |

The host-side suites drive the whole browser ceremony through
`lib/idp_login.py`, which speaks both IdP dialects: Keycloak renders a login form,
Authentik drives a flow-executor API.

`vpn-client.sh` needs `openvpn` on the host and the lab VPN server started with
`vagrant ssh -c 'sudo sh /home/vagrant/os-sso/test/vagrant/setup-vpn-server.sh'`;
it skips itself when openvpn is missing.

## Build

CI builds the `.pkg` in a FreeBSD VM and publishes a GitHub release on a
`v*.*.*` tag (or a manual run) - see `.github/workflows/build-pkg.yml`. Versions
follow `YEAR.MONTH.INDEX` (e.g. `2026.6.3`).

Locally on an OPNsense dev VM (plugin name `sso`, category `security`):

```sh
cd /usr/plugins/security/sso
make package
pkg add ./work/pkg/*.pkg
```

## License

BSD-2-Clause. © 2026 Maxime Wewer.
