# Configuring an authentication server

**System ▸ Access ▸ Servers ▸ ＋ Add**, then pick the **Type** (*OpenID Connect*,
*SAML 2.0* or *JWT forward-auth*). Every field carries its own help in the form; below is
only what is easy to get wrong, and shared by all three types.

| Option | What to watch |
|---|---|
| **Applies to** | Which of *webgui*, *portal*, *vpn* this provider serves. Empty = all three, so a provider added for the portal is also a WebGUI door. |
| **Base URL** (required, OIDC/SAML) | Every URL the IdP is given is built from it; the fallback would trust the request `Host`. Mind a reverse proxy or port-forward - see [Security](security.md#the-base-url). |
| **Username claim/attribute** | Must be immutable and IdP-administered: `preferred_username`, not `email`. |
| **Required groups** | Empty lets in *every* account the IdP authenticates - WebGUI, portal and VPN alike. |
| **Automatic user creation** | Off by default; on, it writes users into `config.xml` with no local password. |
| **Strict account binding** | On for a newly added server. Turn it off only when two servers front the *same* directory - see [Account binding](security.md#account-binding). |
| **Group mapping** | An explicit mapping may target `admins`; the 1:1 name fallback refuses privileged groups. |
| **Strict group sync** | Off = additive. On, revokes only what os-sso granted, never the last privileged member. |
| **Deprovision on refused login** | Disables the account behind a refused login, and re-enables it when the IdP allows that account again. Does nothing without *Required groups*. |
| **Maximum session lifetime** | The WebGUI timeout is *idle*-only. Applies to the portal client and the VPN tunnel too (capped at 24 h there) - see [Sessions](security.md#sessions). |
| **SCIM provisioning** | Token **and** source addresses, both required - see [SCIM](scim.md). |

Then, per type:

- [OpenID Connect](oidc.md) - client authentication, hardening, groups claim, Entra ID.
- [SAML 2.0](saml.md) - metadata, SP endpoints, assertion requirements.
- [JWT forward-auth](jwt.md) - trusted proxies, replay window.

And per door: [WebGUI, Captive Portal, OpenVPN](services.md).
