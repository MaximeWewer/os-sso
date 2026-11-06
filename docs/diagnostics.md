# Diagnostics

**System ▸ Access ▸ SSO Diagnostics** shows, for every configured provider:

- the exact URLs to register at the IdP (back- and front-channel logout, the client JWKS,
  the request object URI for JAR by reference, the SCIM base URL when SCIM is on), and each
  provider's direct login link - the way in when its button is
  hidden, and the initiate-login URI an IdP app launcher asks for;
- the effective policy - required groups, auto-creation, group sync, deprovisioning, SCIM,
  session lifetime;
- a **Test** button that talks to the IdP live: discovery + JWKS for OIDC, the metadata
  document for SAML, the JWKS for forward-auth.

It also lists the currently open SSO sessions - each one can be **ended** on the spot, or
all of them at once - and lets you **flush the caches** (discovery, JWKS, SAML metadata,
icons) after changing something at the IdP instead of waiting out a TTL.

Access is gated by its own ACL privilege, *System: Access: SSO Diagnostics*.
