# JWT forward-auth

For OPNsense behind a trusted identity-aware proxy that authenticates users and forwards a
**signed JWT in a header** (oauth2-proxy, Authelia, Authentik forward-auth, Cloudflare
Access).

1. Fill **Issuer** and **Audience** (both checked), and the **JWKS URL** (preferred -
   supports key rotation) or a static PEM public key.
2. Set **Trusted proxy IPs/CIDRs** - *required*. The JWT header is only accepted when the
   request comes from these source IPs (the proxy), which is what prevents anyone else
   from forging it. The match is on the **direct TCP peer** (`REMOTE_ADDR`), never a
   forwardable header - list the IP that actually connects to the firewall. If another
   reverse proxy fronts the WebGUI, that proxy's IP goes here and it must strip the JWT
   header from untrusted clients.
3. Point the proxy at `https://<opnsense>/api/sso/jwt/login?provider=<name>` and have it
   inject the token in the configured header (default `X-Auth-Request-Jwt`, or
   `Authorization: Bearer`).

Only asymmetric algorithms (`RS256`/`ES256`/…) are accepted; `exp`/`nbf` are enforced.

## Bounding the replay window

A signed JWT is a bearer credential - whoever holds the bytes is the user until it
expires. Both controls are off by default because they depend on how your proxy issues
tokens:

- **Maximum token age** - refuse tokens whose `iat` is older than N seconds, no matter
  what `exp` says.
- **Single-use tokens** - accept each token once (keyed on `jti` when present). Only if
  the proxy mints a fresh token per login; if it reuses one token for the whole session
  (the usual oauth2-proxy setup), the second login would be refused.
