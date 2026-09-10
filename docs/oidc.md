# OpenID Connect

Reference for the **OpenID Connect** server type. The first steps are in the README
[quick start](../README.md#quick-start); this page holds the options and the reasoning.

## Client authentication

`auto` picks `client_secret_basic` or `client_secret_post` from the discovery document.
The others must be chosen explicitly - they need key material registered at the IdP
first, so auto-selecting one the moment an IdP advertises it would break every login:

| Method | Needs here | Shared secret |
|---|---|---|
| `client_secret_basic` / `_post` | the client secret | sent on every token request |
| `client_secret_jwt` | the secret, ≥32 chars for HS256 | never leaves the firewall |
| `private_key_jwt` | a client private key (PEM) + algorithm, optional `kid` | none |
| `tls_client_auth` / `self_signed_…` | a client certificate + key (PEM) | none |

For `private_key_jwt`, point the IdP's *JWKS URL* at
`https://<opnsense>/api/sso/oidc/jwks?provider=<name>` (listed on the diagnostics page):
it serves the public key derived from the private one and nothing else, so a rollover
needs no copy-paste. Mutual TLS follows RFC 8705 - an `mtls_endpoint_aliases` token
endpoint is used automatically.

## Hardening options

- **Maximum authentication age** - `max_age`, checked against the returned `auth_time`.
- **Required authentication context** - `acr_values`, checked against the returned `acr`.
  Honouring the request is voluntary per the spec, so checking the answer is the only way
  to actually require the IdP's MFA context.
- **form_post response mode** - keeps the authorization code out of the URL.
- **Pushed authorization requests** (PAR, RFC 9126) - the request goes over the back
  channel and the browser only carries an opaque reference. Used automatically when the
  IdP declares it requires them.
- **Extra authorization parameters** - for things like `prompt=login`.

A **signed userinfo response** (`userinfo_signed_response_alg`) needs nothing configured:
the JWT is verified against the same keys as the ID token, and refused if it is signed
symmetrically or names another issuer or audience. Worth knowing because userinfo is
where groups usually come from, and a response os-sso cannot read is a login that arrives
with none of them - which now says so in the log instead of looking like an IdP that
sends no groups at all.

**Deliberately absent.** A **request object** (JAR) adds little once PAR keeps the request
off the browser entirely; **refresh tokens** would be an offline credential for calls
os-sso never makes; **DPoP** binds access tokens the firewall does not keep; and an
**encrypted ID token or userinfo response** (JWE) is a decryption key to hold for
something that already travels inside TLS to a back-channel endpoint.

## Providers

| Provider | Issuer URL | Groups |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | add a *Group Membership* mapper → `groups` |
| **Authentik** | `https://<authentik>/application/o/<slug>/` | add the *Groups* scope |
| **Entra ID** | `https://login.microsoftonline.com/<tenant>/v2.0` | `groups` claim (object IDs - use an explicit name map) |

## Groups claim

The **Groups claim** accepts dot notation for a nested claim, which is where roles usually
live: `realm_access.roles` for Keycloak realm roles, `resource_access.<client-id>.roles`
for its client roles. A claim whose own name contains dots (`urn:oid:…`) is matched whole
first, so both styles work.

**Entra ID group overage.** Past ~200 groups Entra drops `groups` and substitutes a
pointer to Microsoft Graph, so a tenant's most heavily grouped users - usually the
administrators - arrive with no groups and are refused by the required-groups gate.
Tick **Follow Entra ID group overage** to resolve it. The firewall asks Graph on its own
behalf (the user's token is scoped elsewhere and cannot be exchanged), so the app
registration needs the **application** permission `GroupMember.Read.All` with **admin
consent**; only Microsoft's own Graph hosts are ever called. Graph returns object ids, the
same values the ordinary claim carries, so the group map is written the same either side
of the threshold. Rather not grant it? Keep the claim under the limit with application
roles or a group filter.
