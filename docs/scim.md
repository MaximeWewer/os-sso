# SCIM 2.0 provisioning

Without it, os-sso only learns that someone was revoked when they try to log in - until
then a disabled directory account keeps working here. SCIM inverts that: the IdP pushes
creations, updates and deactivations as they happen, and pre-provisions accounts so they
exist before the first login (which matters as soon as you reference a user in a rule or a
certificate).

## Enabling it

Enable SCIM on any authentication server - OIDC, SAML or JWT. Three fields, all required:
**Enable SCIM provisioning**, a **bearer token**, and the **source IPs** the IdP connects
from. With no source list every request is refused, rather than every source being allowed
to try the token.

Then register the base URL at the IdP:

```text
https://<opnsense>/api/sso/scim
```

One base URL serves every provider: the bearer token is what says which one a request
belongs to, and an account provisioned under one provider is not silently adopted by
another.

## Supported

`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`, `/Users` (GET/POST/PUT/PATCH/
DELETE, pagination, `count=0` as a total-only probe) and `/Groups` (GET plus PATCH of
membership).

- `POST /Users` answers **201** when it created the account, **200** when it adopted one
  already carrying the `userName`, **409** on a repeated `externalId`.
- Filters take `eq` on `userName`, `externalId`, `id`, `displayName`, `emails` and
  `active`, combined with `and`, `or` and parentheses.
- Resources carry `meta.created` / `meta.lastModified` (os-sso keeps its own timestamps -
  config.xml has none), the groups the account is in, and a weak **ETag** that `If-Match`
  is honoured against, so a conditional write that lost a race gets **412** instead of
  overwriting a change it never saw.

**Not supported:** bulk, sort, and anything beyond that filter subset - an unsupported
filter is refused rather than silently answered with the wrong set.

## Four absolute refusals

This is a write API into a firewall's account database:

- a **privileged** account (system, uid 0, `admins` member) is never touched;
- an account with a **real local password** is never taken over;
- **DELETE deactivates** rather than removes, because a user can own rules, certificates
  and API keys;
- a **group carrying administrative privileges** takes no membership from a directory.

Groups themselves are never created or deleted either - the client fills the ones that
exist.
