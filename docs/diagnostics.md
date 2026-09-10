# Diagnostics

**System ▸ Access ▸ SSO Diagnostics** shows, for every configured provider:

- the exact URLs to register at the IdP (the SCIM base URL included, when SCIM is on);
- the effective policy - required groups, auto-creation, group sync, deprovisioning, SCIM,
  session lifetime;
- a **Test** button that talks to the IdP live: discovery + JWKS for OIDC, the metadata
  document for SAML, the JWKS for forward-auth.

It also lists the currently open SSO sessions - each one can be **ended** on the spot, or
all of them at once - and lets you **flush the caches** (discovery, JWKS, SAML metadata,
icons) after changing something at the IdP instead of waiting out a TTL.

Access is gated by its own ACL privilege, *System: Access: SSO Diagnostics*.
