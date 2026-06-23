# os-sso — Single Sign-On for OPNsense

Add **OpenID Connect**, **SAML 2.0** and **JWT forward-auth** as authentication
types in OPNsense. The firewall acts as a pure consumer (Relying Party / Service
Provider): your users sign in at your existing Identity Provider, and MFA and
passkeys stay there — nothing to re-implement on the firewall.

Works for the **WebGUI**, the **Captive Portal** and **OpenVPN**, with group
mapping driving OPNsense privileges. The local password (+ native TOTP) always
stays available as a break-glass path.

## Features

- **OpenID Connect** — automatic `.well-known` discovery, PKCE, JWKS key
  rotation. Works with Keycloak, Authentik, Entra ID, Zitadel, …
- **SAML 2.0** — signed assertions, metadata generation, Single Logout.
- **JWT forward-auth** — trust a signed JWT from a reverse proxy in front of
  OPNsense (oauth2-proxy, Authelia, Authentik forward-auth, Cloudflare Access).
- **WebGUI login** — one button per provider on the login page.
- **Captive Portal login** via OIDC/SAML.
- **OpenVPN** login through the browser (deferred web-auth / `WEB_AUTH`).
- **Group mapping** — IdP groups become OPNsense group membership; privileges
  are resolved by the normal ACL.
- **Single Logout** — the WebGUI *Logout* button ends the IdP session too.

## Requirements

- **OPNsense 25.7 or newer** — the login-page SSO button hook
  (`ISSOContainer` / `listSSOproviders`) landed in core in 25.7.
- For OpenVPN login: **OpenVPN 2.5+** on the firewall (shipped) and a
  web-auth-capable client (OpenVPN Connect, OpenVPN 3 Linux, Windows 2.6+).
- An Identity Provider you control or use (Keycloak, Authentik, Entra ID, Zitadel, …).

## Install

Download the latest `os-sso-*.pkg` from the [Releases](../../releases) page and
install it on the firewall:

```sh
pkg add os-sso-*.pkg
```

Then reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**.

> Building from source instead: see [Build](#build).

## Configure an authentication server

Go to **System ▸ Access ▸ Servers** and click **＋ Add**, then pick the **Type**.
All types share a few options:

- **Username claim/attribute** — which IdP field becomes the local username.
  Use an immutable, IdP-administered value (e.g. `preferred_username`).
- **Automatic user creation** — off by default. When on, matched users are created
  in `config.xml` with no local password (IdP-only login).
- **Default groups** — OPNsense groups always granted to mapped users.
- **Base URL (override)** — set the firewall's public `https://host[:port]` when
  behind a reverse proxy or port-forward, so the URLs handed to the IdP match.
  Leave empty to auto-detect. The form shows the exact **redirect/ACS URL** live
  underneath this field — copy it into your IdP.
- **Default landing URL** — where users land after login when no specific page was
  requested (e.g. `/ui/dashboard`).

### OpenID Connect

1. Create a **confidential** client at your IdP with redirect URL
   `https://<opnsense>/api/sso/oidc/callback` (shown live in the form).
2. In OPNsense fill **Issuer URL** + **Client ID/Secret**. Discovery and keys are
   fetched automatically from `<issuer>/.well-known/openid-configuration`.
3. Keep **PKCE** on; scopes `openid email profile` (+ a groups scope if you map
   groups).

| Provider | Issuer URL | Groups |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | add a *Group Membership* mapper → `groups` |
| **Authentik** | `https://<authentik>/application/o/<slug>/` | add the *Groups* scope |
| **Entra ID** | `https://login.microsoftonline.com/<tenant>/v2.0` | `groups` claim (object IDs — use an explicit name map) |

### SAML 2.0

1. In OPNsense fill **IdP EntityID**, **IdP SSO URL** (HTTP-Redirect) and the
   **IdP x509 certificate** (full PEM of the signing cert — not a fingerprint).
2. Give your IdP the SP URLs (shown live in the form):
   - ACS: `https://<opnsense>/api/sso/saml/acs`
   - Metadata / EntityID: `https://<opnsense>/api/sso/saml/metadata`
3. The IdP must **sign the assertion**. Map the NameID to the username.
4. The IdP must send **at least one attribute** (configure attribute / property
   mappings — e.g. groups, email). An empty `<AttributeStatement/>` is invalid per
   the SAML schema and is rejected by the strict validation — and you need the
   groups attribute for group mapping anyway.

| Provider | IdP EntityID | SSO URL (redirect) |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | `https://<kc>/realms/<realm>/protocol/saml` |
| **Authentik** | `https://<authentik>/application/saml/<slug>/metadata/` (the response Issuer — note the `/metadata/` suffix) | `…/application/saml/<slug>/sso/binding/redirect/` |

### JWT forward-auth

For OPNsense behind a trusted identity-aware proxy that authenticates users and
forwards a **signed JWT in a header**.

1. Fill **Issuer** and **Audience** (both checked), and the **JWKS URL**
   (preferred — supports key rotation) or a static PEM public key.
2. Set **Trusted proxy IPs/CIDRs** — *required*. The JWT header is only accepted
   when the request comes from these source IPs (the proxy), which is what prevents
   anyone else from forging it.
3. Point the proxy at `https://<opnsense>/api/sso/jwt/login?provider=<name>` and
   have it inject the token in the configured header (default `X-Auth-Request-Jwt`,
   or `Authorization: Bearer`).

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
3. Use the bundled portal template
   (`src/opnsense/scripts/OPNsense/SSO/cp-portal/`) — zip its contents, upload it
   under *Templates*, and select it on the zone. It shows the SSO buttons and keeps
   the standard login form.
4. Make sure the zone lets unauthenticated clients reach the firewall WebGUI and
   the IdP (zone *allowed addresses* / pre-auth) so the login can complete.

A user who signs in through SSO gets their device authorized in that portal zone.

### OpenVPN (deferred web-auth)

OpenVPN 2.5+ “pending auth” lets the client authenticate in a browser:

1. The client connects and is shown a `WEB_AUTH` URL.
2. It opens the URL, logs in at the IdP (passkey/MFA there).
3. The tunnel comes up once the login succeeds.

Configure protocol/provider in `/usr/local/etc/sso/vpn.conf`
(`PROTOCOL=oidc|saml`, `PROVIDER`, `HOST`, `TIMEOUT`). Use a web-auth-capable
client (OpenVPN Connect, OpenVPN 3 Linux) — see `test/vpn-client/README.md`.

### Logout

The WebGUI **Logout** button performs Single Logout: it ends the IdP session for
OIDC (`end_session_endpoint`) and SAML, and falls back to the normal local logout
for password sessions. Register at your IdP:

- OIDC post-logout redirect: `https://<opnsense>/`
- SAML logout service: `https://<opnsense>/api/sso/saml/slo`

## Security

- Privileges are **never** stored in the session — the OPNsense ACL resolves them
  from group membership on every request.
- New sessions regenerate their ID (anti session-fixation).
- SSO will not bind to a privileged local account (`root`/system or `admins`) that
  it didn't create; email matching requires a verified email.
- The 1:1 group fallback won't grant `admins` without an explicit mapping.
- OIDC validates `iss`/`aud`/`azp`/`nonce` and pins signing algorithms; SAML
  verifies the assertion signature and is replay-protected.
- The local password (+ native TOTP) is always left active as a **break-glass**
  path — keep at least one local admin.

> `client_secret` and SP keys are stored in `config.xml` like other OPNsense
> credentials (e.g. LDAP bind passwords) and are never written to logs.

## Test / lab

A reproducible lab lives under `test/` — a Vagrant OPNsense VM plus Authentik and
Keycloak in Docker behind a TLS proxy. `vagrant up` is self-contained: it pushes
the source over SCP and deploys the plugin into the live tree (no manual steps).

```sh
cd test && vagrant up                      # boot the OPNsense VM + deploy the plugin
cd test/idp && ./up.sh                      # start Authentik + Keycloak (+ TLS proxy)
bash keycloak/setup-keycloak.sh             # create realm, clients, test user
bash authentik/setup.sh                     # create OIDC/SAML providers + mappings
```

Helper scripts under `test/vagrant/` register the auth servers and run the JWT /
Captive Portal end-to-end suites. Host `/etc/hosts` needs
`127.0.0.1 authentik.test keycloak.test`.

## Build

CI builds the `.pkg` in a FreeBSD VM and publishes a GitHub release on a
`v*.*.*` tag (or a manual run) — see `.github/workflows/build-pkg.yml`. Versions
follow `YEAR.MONTH.INDEX` (e.g. `2026.6.3`).

Locally on an OPNsense dev VM (plugin name `sso`, category `security`):

```sh
cd /usr/plugins/security/sso
make package
pkg add ./work/pkg/*.pkg
```

## License

BSD-2-Clause. © 2026 Maxime Wewer.
