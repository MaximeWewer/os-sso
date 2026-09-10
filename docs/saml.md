# SAML 2.0

Reference for the **SAML 2.0** server type. The first steps are in the README
[quick start](../README.md#quick-start); this page holds the options and the reasoning.

## Trusting the IdP

Two ways, and anything filled in by hand wins over the document:

- **IdP metadata URL** (https), the rest left empty. The EntityID, SSO/SLO endpoints and
  signing certificate are read from it and cached for 24 h, so an IdP **signing-key
  rotation is picked up on its own**. Set the **metadata signing certificate** as well and
  the document's own XML signature is checked against it before anything is read from it -
  worth it wherever the document comes from a federation rather than from your own IdP,
  since TLS only says which host sent the thing that names every future signing key.
- By hand: **IdP EntityID**, **IdP SSO URL** (HTTP-Redirect) and the **IdP x509
  certificate** (full PEM of the signing cert - not a fingerprint).

## SP endpoints

Each SAML server is its own SP identity, so every endpoint carries
`?provider=<server name>` - two IdPs never share an EntityID or ACS. The form shows
them live.

| | URL |
|---|---|
| ACS | `https://<opnsense>/api/sso/saml/acs?provider=<name>` |
| Metadata / EntityID | `https://<opnsense>/api/sso/saml/metadata?provider=<name>` |
| SLO | `https://<opnsense>/api/sso/saml/slo?provider=<name>` |

SLO takes HTTP-Redirect or HTTP-POST; a posted message must carry an XML signature, since
it has no query string to sign.

## What the assertion must carry

- **A signature** with RSA-SHA256. A SHA-1 signature *or digest* is refused, unless
  **Accept SHA-1 signatures** is ticked for an IdP that cannot be moved yet.
- **At least one attribute.** An empty `<AttributeStatement/>` is invalid per the schema
  and the strict validation rejects it - and you need the groups attribute anyway.

Map the NameID to the username; set the username/email/display-name attributes explicitly
when your IdP emits OID-style names (`urn:oid:0.9.2342.19200300.100.1.1`).

## Optional, all off by default

- **Force re-authentication** + **maximum authentication age** - `ForceAuthn` is only a
  request, so the age check on the assertion's `AuthnInstant` is what proves the IdP
  honoured it. The SAML counterpart of OIDC's `max_age`/`auth_time`.
- **Required authentication context** - sent as a `RequestedAuthnContext` *and* checked
  against the `AuthnContextClassRef` the assertion comes back with, which is the only way
  to actually require the IdP's MFA context. The SAML counterpart of OIDC's
  `acr_values`/`acr`.
- **Sign the AuthnRequest** (needs the SP certificate + key) - required by ADFS in a strict
  configuration and by Keycloak with *Client signature required*; it also makes the SP
  metadata declare `AuthnRequestsSigned`.
- **HTTP-POST binding** for the AuthnRequest, when the IdP will not take a redirect.
- **Encrypted assertions** (needs the SP certificate + key).
- **IdP-initiated login** - an unsolicited assertion proves nothing about who asked to log
  in, hence off.

## Providers

| Provider | IdP EntityID | SSO URL (redirect) |
|---|---|---|
| **Keycloak** | `https://<kc>/realms/<realm>` | `https://<kc>/realms/<realm>/protocol/saml` |
| **Authentik** | `https://<authentik>/application/saml/<slug>/metadata/` (the response Issuer - note the `/metadata/` suffix) | `…/application/saml/<slug>/sso/binding/redirect/` |
