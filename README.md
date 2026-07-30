# os-sso - Single Sign-On (SSO) and SCIM provisioning for OPNsense

Add **OpenID Connect**, **SAML 2.0** and **JWT forward-auth** as authentication
types in OPNsense. The firewall acts as a pure consumer (Relying Party / Service
Provider): your users sign in at your existing Identity Provider, and MFA and
passkeys stay there - nothing to re-implement on the firewall.

Works for the **WebGUI**, the **Captive Portal** and **OpenVPN**, with group
mapping driving OPNsense privileges, and takes **SCIM 2.0** provisioning from the
same IdP so account lifecycle does not wait for a login. The local password
(+ native TOTP) always stays available as a break-glass path.

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
- **SCIM 2.0 provisioning** - the IdP pushes account lifecycle, so a revoked user is
  disabled (and their sessions killed) when the directory says so, not at their next
  login attempt.

## Screenshots

| Authentication servers | Server configuration | SCIM provisioning |
|---|---|---|
| ![Authentication servers](assets/servers.png) | ![Server configuration](assets/server_config.png) | ![SCIM settings](assets/scim_settings.png) |

| WebGUI login | Captive Portal login | OpenVPN web-auth settings |
|---|---|---|
| ![WebGUI login form](assets/login_form.png) | ![Captive portal login page](assets/cp_portal.png) | ![OpenVPN web-auth settings](assets/vpn_settings.png) |

| SSO diagnostics |
|---|
| ![SSO diagnostics](assets/sso_diagnostics.png) |

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
- **SCIM provisioning** - lets the IdP push account lifecycle instead of os-sso
  waiting for a login. Needs a bearer token *and* the source addresses the IdP connects
  from - both are required, an empty allowlist refuses every request.
  See [SCIM provisioning](#scim-provisioning).
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
   groups). **Client authentication method** defaults to `auto`, which picks
   `client_secret_basic` or `client_secret_post` from the IdP's discovery document.
   Set it explicitly for the methods that get the shared secret off the wire - or
   remove it entirely:

   | Method | What it needs here | Shared secret |
   |---|---|---|
   | `client_secret_basic` / `client_secret_post` | the client secret | sent on every token request |
   | `client_secret_jwt` | the client secret, ≥32 chars for HS256 | never leaves the firewall (signs an assertion) |
   | `private_key_jwt` | a **client private key** (PEM) + algorithm, optional `kid` | none |
   | `tls_client_auth` / `self_signed_tls_client_auth` | a **client certificate** + key (PEM) | none |

   These are not auto-selected even when the IdP advertises them, because they need key
   material registered over there first. For `private_key_jwt`, point the IdP's *JWKS
   URL* at `https://<opnsense>/api/sso/oidc/jwks?provider=<name>` (shown on the
   diagnostics page) and a key rollover on this side needs no copy-paste - the endpoint
   serves the public key derived from the private one, and nothing else. Mutual TLS
   follows RFC 8705: when the IdP publishes `mtls_endpoint_aliases`, the aliased token
   endpoint is used automatically.
4. Optional hardening: **Maximum authentication age** sends `max_age` and enforces
   the returned `auth_time`, so an old IdP session must re-authenticate;
   **Required authentication context** sends `acr_values` and enforces the returned
   `acr`, which is how you actually require the IdP's MFA context (requesting one is
   voluntary per the spec - an IdP may ignore it, so only the returned `acr` proves
   anything); **form_post response mode** keeps the authorization code out of the URL;
   **Extra authorization parameters** passes things like `prompt=login` through to the
   IdP.

| Provider | Issuer URL | Groups |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | add a *Group Membership* mapper → `groups` |
| **Authentik** | `https://<authentik>/application/o/<slug>/` | add the *Groups* scope |
| **Entra ID** | `https://login.microsoftonline.com/<tenant>/v2.0` | `groups` claim (object IDs - use an explicit name map) |

The **Groups claim** accepts dot notation for a nested claim, which is where roles
usually live: `realm_access.roles` for Keycloak realm roles,
`resource_access.<client-id>.roles` for its client roles. A claim whose own name
contains dots (`urn:oid:…`) is matched whole first, so both styles work.

**Entra ID group overage.** Past roughly 200 groups, Entra stops sending `groups` and
substitutes a pointer (`_claim_names` / `_claim_sources`) to Microsoft Graph. Nothing in
the token says "no groups" - the claim is just absent - so the most heavily grouped users
in a tenant, usually the administrators, otherwise arrive with nothing and are refused by
the required-groups gate for a reason no log explains.

Tick **Follow Entra ID group overage** to have os-sso resolve it. The firewall asks Graph
*on its own behalf* (the user's access token is scoped to another resource and cannot be
exchanged), so the app registration needs the **application** permission
`GroupMember.Read.All` - or `Directory.Read.All` - with **admin consent**. Graph answers
with group object ids, the same values the ordinary claim carries, so the group map is
written against ids either side of the threshold. Only Microsoft's own Graph hosts are
ever called, whatever endpoint the claim names. If you would rather not grant the
permission, keep the claim under the limit instead: use application roles, or a group
filter on the token configuration.

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
   **force re-authentication** (sends `ForceAuthn`) together with a **maximum
   authentication age**, which checks the assertion's `AuthnInstant` and so verifies the
   IdP honoured the request rather than reusing an old session - the SAML counterpart of
   the OIDC `max_age`/`auth_time` pair;
   **sign the AuthnRequest** (needs the SP certificate + key; required by ADFS in a
   strict configuration and by Keycloak with *Client signature required*, and it makes
   the SP metadata declare `AuthnRequestsSigned` so the IdP knows to expect one),
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

   In the lab, `test/vagrant/setup-cp.sh` does the whole thing - zone, template,
   render, unpack, start - and documents the ordering the UI normally handles.
4. Make sure the zone lets unauthenticated clients reach the firewall WebGUI and
   the IdP (zone *allowed addresses* / pre-auth) so the login can complete.

A user who signs in through SSO gets their device authorized in that portal zone.

The "connected" page then bounces them to wherever they were originally headed, which
is an arbitrary external site by design - that is what a captive portal does. The URL
is validated for shape only (no other scheme, no protocol-relative host, no userinfo),
never against an allowlist, so treat `/api/sso/{oidc,saml}/{callback,acs}?cpurl=…` as
an intentional redirector. It carries nothing with it: the page is sent `no-referrer`
so the callback URL - which holds the authorization code and state - never reaches the
destination.

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

> **Mind the username.** OpenVPN takes it from the client and never revisits it on a
> deferred-auth path: the browser login decides *whether* the tunnel comes up, not
> *whose* it is. Both names are logged on the firewall, so a mismatch is visible.
> Turn on **Require the username to match** if the name is load-bearing on the server
> side (`username-as-common-name`, a `client-config-dir`, per-user rules); leave it off
> for the usual setup where the client sends a throwaway username.

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

## SCIM provisioning

Without it, os-sso only learns that someone was revoked when they try to log in --
until then a disabled directory account keeps working here. SCIM inverts that: the
IdP pushes creations, updates and deactivations as they happen, and pre-provisions
accounts so they exist before the first login (which matters as soon as you reference
a user in a rule or a certificate).

Enable it on any authentication server - OIDC, SAML or JWT (**Enable SCIM
provisioning**, a **bearer token**, and the **source IPs** the IdP connects from - all
three required; with no source list every request is refused, rather than every source
being allowed to try the token), then register the base URL at the IdP:

```
https://<opnsense>/api/sso/scim
```

One base URL serves every provider: the bearer token is what says which one a request
belongs to, and an account provisioned under one provider is not silently adopted by
another.

Supported: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, `/Users`
(GET/POST/PUT/PATCH/DELETE, `filter=userName eq "..."` and `externalId eq "..."`,
pagination, `count=0` for a total-only probe) and `/Groups` (GET, and PATCH of
membership). Not supported: bulk, sort, ETags, `meta.created`/`meta.lastModified`
(config.xml keeps no per-account timestamps, and advertising ones we do not maintain
would be worse than omitting them), and filters beyond `eq` on the indexed attributes -
an unsupported filter is refused rather than silently answered with the wrong set.

A `POST /Users` answers **201** for an account that did not exist and **200** when it
adopted one that already carried the `userName`; a repeat POST of the same `externalId`
is a **409**.

Four things it deliberately refuses, because this is a write API into a firewall's
account database:

- a **privileged** account (system, uid 0, member of `admins`) is never modified,
  disabled or deleted;
- an account with a **real local password** is never taken over;
- **DELETE deactivates**, it does not remove - a user can own firewall rules,
  certificates and API keys;
- a **group carrying administrative privileges** takes no membership from SCIM.
  Granting administration stays an operator action, by hand or through the provider's
  explicit group map.

Groups are never created or deleted over SCIM either; the client fills the groups
that already exist.

**Authentik**, the client this was tested against: create a *SCIM Provider* with URL
`https://<opnsense>/api/sso/scim` and the token, then attach it to the application as
a **backchannel provider** - a SCIM provider that is not backchannel-attached syncs
"successfully" and pushes nothing. Untick *Verify certificates* if the firewall serves
a self-signed WebGUI certificate; that failure is just as silent.

## Diagnostics

**System ▸ Access ▸ SSO Diagnostics** shows, for every configured provider, the exact
URLs to register at the IdP (the SCIM base URL included, when SCIM is on), the
effective policy (required groups, auto-creation, group sync, deprovisioning, SCIM,
session lifetime), and a **Test** button that talks to the IdP live -
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
  own password (only to os-sso-owned or passwordless accounts), and never to a
  privileged account (`root`/system or `admins`) it didn't create; email matching
  requires a verified email and an account os-sso already owns. A scrambled password is
  *not* ownership - that is the WebGUI's own "no local login" checkbox, and LDAP-backed
  administrators wear it.
- An account is bound to **one subject per provider**, recorded on first login. A second
  subject of the same provider presenting that account's username is refused - that is the
  takeover a mutable username claim would otherwise allow. A second *provider* binds
  alongside the first, so one directory fronted by both OIDC and SAML maps onto a single
  local account, as it should.
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
- The SCIM endpoint is gated by a bearer token **and** a source-address allowlist,
  and refuses on the same principles as the login path: no privileged account is
  ever modified or disabled, no password-owning account is taken over, a delete
  deactivates rather than removes, and a group carrying administrative privileges
  takes no membership from a directory.
- The local password (+ native TOTP) is always left active as a **break-glass**
  path - keep at least one local admin.

> `client_secret` and SP keys are stored in `config.xml` like other OPNsense
> credentials (e.g. LDAP bind passwords) and are never written to logs.

## Test / lab

### Unit tests

`test/unit/` covers the logic that decides security and is pure enough to call directly:
which local account an asserted identity may bind to, which group a directory may fill,
what counts as a same-site return URL, how the client authenticates to a token endpoint.
Every case there is a *refusal* - which is exactly what an end-to-end run never reaches,
since it drives the happy path.

No dependency beyond PHP itself:

```sh
php test/unit/run.php                 # everything
php test/unit/run.php scim            # only matching suites
```

A couple of groups need `/var/db/os-sso` (the state directory the config lock lives in)
and report `skip` rather than fail without it, so the suite still runs unprivileged. For
the full set:

```sh
docker run --rm -v "$PWD:/w" -w /w php:8.3-cli php test/unit/run.php
```

### End-to-end lab

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

Eight end-to-end suites under `test/e2e/`, run against either IdP:

```sh
export SSO_GUI_URL=https://192.168.60.10       # must match the provider Base URL
test/e2e/run-all.sh                            # everything, Keycloak
IDP=authentik test/e2e/run-all.sh              # same, Authentik
test/e2e/run-all.sh oidc saml                  # a subset
test/e2e/oidc.sh                               # or one suite on its own
```

Each suite works from any directory - it resolves its own location first, symlinks
included - and says so plainly rather than failing blank if it is run from an incomplete
copy. The host-side suites still need `vagrant` to find `test/Vagrantfile` from there.

| Suite | Where | Checks | Covers |
|---|---|---|---|
| `oidc.sh` | host | 28 | the browser ceremony, Host-header hardening, diagnostics + UI pages, logout CSRF, rate limiting, required groups, deprovisioning, session expiry, back-channel logout |
| `saml.sh` | host | 16-21 | per-provider EntityID/ACS/SLO, assertion replay, IdP-initiated (off/on/off - Keycloak only, skipped on Authentik), POST binding, metadata import, SLO |
| `portal.sh` | host | 7 | a captive client signing in and being authorized in its zone |
| `vpn-client.sh` | host | 5 | a real OpenVPN client: deferred auth, WEB_AUTH url, tunnel up after the browser login |
| `scim.sh` | host | 42-45 | discovery, bearer + source gate, user lifecycle, filters, the four refusals, session revocation on deactivate, and against Authentik its real SCIM client |
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
