# os-sso - Single Sign-On (SSO) and SCIM provisioning for OPNsense

Add **OpenID Connect**, **SAML 2.0** and **JWT forward-auth** as authentication types in
OPNsense, for the **WebGUI**, the **Captive Portal** and **OpenVPN**. The firewall is a
pure consumer (Relying Party / Service Provider): your users sign in at your existing
Identity Provider, and MFA and passkeys stay there - nothing to re-implement on the
firewall. IdP groups drive OPNsense privileges, **SCIM 2.0** takes account lifecycle from
the same IdP, and the local password (+ native TOTP) always stays available as a
break-glass path.

**[Documentation](docs/)** - [install](docs/install.md) ·
[configuration](docs/configuration.md) · [OIDC](docs/oidc.md) · [SAML](docs/saml.md) ·
[JWT](docs/jwt.md) · [portal & VPN](docs/services.md) · [SCIM](docs/scim.md) ·
[high availability](docs/high-availability.md) · [security](docs/security.md)

## Features

- **OpenID Connect** - discovery, PKCE, pushed authorization requests, JWKS rotation, and
  client authentication beyond the shared secret: `client_secret_jwt`, `private_key_jwt`
  or mutual TLS. Keycloak, Authentik, Entra ID, Zitadel, … → [docs](docs/oidc.md)
- **SAML 2.0** - signed (RSA-SHA256; SHA-1 refused) and optionally encrypted assertions,
  metadata import and generation, signed AuthnRequests, Single Logout over either
  binding. → [docs](docs/saml.md)
- **JWT forward-auth** - trust a signed JWT from a reverse proxy in front of OPNsense
  (oauth2-proxy, Authelia, Authentik forward-auth, Cloudflare Access). → [docs](docs/jwt.md)
- **Three doors** - a login button per provider on the WebGUI page, the same on the
  captive portal, and OpenVPN login through the browser (deferred web-auth /
  `WEB_AUTH`). → [docs](docs/services.md)
- **Scoped per service** - a provider says which of the WebGUI, the portal and the VPN it
  serves, so one added for guest wifi is not also a door into the firewall.
- **MFA actually required** - the authentication context (`acr`) and re-authentication age
  (`max_age` / `ForceAuthn`) are *enforced* on the way back, not merely requested.
- **Group mapping** - IdP groups become OPNsense group membership; privileges are resolved
  by the normal ACL. Reads nested claims (`resource_access.<client>.roles`) and follows
  Entra's group-overage pointer.
- **Single Logout** - a revocation from any side (back-channel logout, SLO, SCIM, an
  administrator) ends the WebGUI session, disconnects the portal client and drops the VPN
  tunnel. → [docs](docs/security.md#revocation-reaches-all-three-doors)
- **SCIM 2.0 provisioning** - the IdP pushes account lifecycle, so a revoked user is
  disabled when the directory says so, not at their next login attempt. → [docs](docs/scim.md)
- **HA configuration sync** - exposes the plugin's profiles to OPNsense XMLRPC sync and
  reconfigures the guard and OpenVPN on the backup. → [docs](docs/high-availability.md)

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

## Install

Needs **OPNsense 25.7 or newer**. Each release ships one package per FreeBSD ABI - check
yours with `pkg config ABI`, download the match from the [Releases](../../releases) page,
and install it:

```sh
pkg add os-sso-devel-*-FreeBSD-14.pkg   # pick the file matching your ABI
```

Reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**. Full requirements and a source build:
[docs/install.md](docs/install.md).

## Quick start

**System ▸ Access ▸ Servers ▸ ＋ Add**, pick the **Type**, and fill the **Base URL** of the
firewall - every URL handed to the IdP is built from it. The form shows the exact
redirect/ACS URL to register at the other end.

- **OpenID Connect** - create a *confidential* client with redirect URL
  `https://<opnsense>/api/sso/oidc/callback`, then fill **Issuer URL** + **Client
  ID/Secret**. Discovery and keys are fetched from
  `<issuer>/.well-known/openid-configuration`. Keep **PKCE** on; scopes
  `openid email profile`, plus a groups scope if you map groups.
- **SAML 2.0** - set the **IdP metadata URL** and leave the rest empty (endpoints and the
  signing certificate are read from it and refreshed on their own), then give your IdP the
  SP URLs shown in the form. The assertion must be signed and carry at least one
  attribute.
- **JWT forward-auth** - fill **Issuer**, **Audience** and the **JWKS URL**, and set the
  **trusted proxy IPs** - required, since that is what stops anyone else forging the
  header.

Then mind three fields whatever the type: **Applies to** (empty = all three doors),
**Required groups** (empty lets in every account the IdP authenticates) and **Username
claim** (must be immutable - `preferred_username`, not `email`). The rest of the options,
with what each one decides: [docs/configuration.md](docs/configuration.md).

Check the result under **System ▸ Access ▸ SSO Diagnostics**: the URLs to register, the
effective policy per provider, a live **Test** against the IdP, and the open SSO sessions.

## Security

os-sso is a login path into a firewall, so the [security model](docs/security.md) is
documented in its own right: what binds to which account, which groups a directory can
never fill, what is checked on the way back from the IdP, and how a revocation reaches all
three doors. The short version:

- Privileges are never stored in the session - the ACL resolves them per request.
- An asserted identity never binds to an account with a real local password, nor to a
  privileged account os-sso did not create.
- `admins` and any group carrying full-GUI / shell / user-manager rights only gain members
  through an explicit operator mapping.
- The local password (+ native TOTP) stays active as break-glass: keep one local admin.

## Development

Unit suite and an eight-suite end-to-end lab (Vagrant OPNsense + Authentik + Keycloak in
Docker), plus the translation template:
[docs/development.md](docs/development.md), [`test/`](test/).

```sh
php test/unit/run.php    # ~590 assertions, no setup
```

## License

BSD-2-Clause. © 2026 Maxime Wewer.
