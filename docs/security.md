# Security model

What os-sso refuses, and why. The [unit suite](../test/README.md) covers exactly this:
every case is a refusal - the part an end-to-end run never reaches.

## Sessions

Privileges are never stored in the session - the OPNsense ACL resolves them from group
membership on every request. A new session regenerates its ID (anti session-fixation). A
**disabled or expired** account is refused before group sync writes anything - on the
WebGUI, on the VPN, and on the captive portal, which needs no local account but will not
let a revoked one onto the network either.

The WebGUI timeout is *idle*-only; **Maximum session lifetime** is the absolute one, and
applies to the portal client and the VPN tunnel too (capped at 24 h there). It is enforced
by the **os-sso: expire SSO sessions** cron job, which the plugin schedules for itself
every 10 minutes.

## Account binding

An asserted identity binds only to an account os-sso owns or one with no usable local
password - never to one with a real password, and never to a privileged account
(`root`/system, `admins`) it did not create. A scrambled password is *not* ownership: that
is the WebGUI's own "no local login" checkbox, which LDAP-backed administrators wear.
Email matching additionally requires a verified address.

Display name and (verified) address are refreshed from the assertion on every login, on
the accounts os-sso owns. Nothing else is: a shell is how an account gets SSH, `expires`
is the operator's own lever, and API keys are separate credentials - none of them is a
directory's to set.

Each account is bound to **one subject per provider**, recorded on first login. A second
subject of the same provider presenting that account's username is refused - the takeover
a mutable username claim would otherwise allow.

**Strict account binding** decides whether a second *provider* may bind alongside, per
server, because nothing in the configuration distinguishes the two shapes it decides
between: one directory behind two authentication servers (the same person arriving over
OIDC and over SAML, where binding alongside is the whole point), and two unrelated
directories, where a user of one presenting a username from the other would inherit their
account and its groups. On - the default for a newly added server - a provider only binds
to an account no other one has claimed, by a previous login *or* by a SCIM push, so an
account a directory pre-provisioned and nobody has logged into yet is already spoken for.
It governs only a first-time match by username or verified email; the durable subject
stamp resolves either way.

## Groups

A **privileged** group (`admins`, or any carrying full-GUI / shell / user-manager rights)
only ever gains members through an explicit operator mapping; the 1:1 name fallback
refuses them. **Strict group sync** revokes only what os-sso granted, never a
hand-assigned group, never the last privileged member. Off, it is purely additive.

## Protocols

OIDC validates `iss`/`aud`/`azp`/`nonce`/`exp`/`iat`, binds `at_hash` to the access token
and requires an asymmetric signature; SAML verifies the assertion signature and is
replay-protected (single-use request id plus a consumed-assertion cache).

What the IdP is *asked* for is also *checked* on return - `max_age` against `auth_time`
(SAML: `AuthnInstant`), the required `acr` against the returned one - because requesting an
MFA context is voluntary per the spec, so only the answer proves anything.

The client can authenticate to the token endpoint with no shared secret at all
(`private_key_jwt`, mutual TLS), and the pre-auth endpoints are rate limited per source
(per /64 in IPv6). A login endpoint only answers a request the browser reports as a
top-level navigation, so a third-party page cannot start one - or, on the forward-auth
path where the proxy adds the token to whatever goes through it, complete one - from an
`<img>` tag.

## The Base URL

**Base URL** matters more than it looks: every URL the IdP is given is built from it, and
the fallback would trust the request `Host`. An IdP doing wildcard redirect matching plus a
forged `Host` header is how an authorization code ends up somewhere else. Mind a reverse
proxy or port-forward; the form shows the exact redirect/ACS URL to copy into the IdP.

## Revocation reaches all three doors

A back-channel logout, a SAML Single Logout, a SCIM `active: false`, "deprovision on
refused login" and the *End* button on the diagnostics page all act on the same record of
what os-sso granted - so they end the WebGUI session, disconnect the captive-portal client
from the network, and drop the OpenVPN tunnels of that common name, rather than only the
first of the three.

A deprovisioning is also **undone** by the login that disproves it: put the account back
in the required group at the IdP and the next login re-enables it, on all three doors,
rather than leaving somebody to tick the box back by hand. Only a refusal os-sso itself
issued is undone - it stamps the accounts it disables, and drops that stamp the moment it
sees one enabled again, so the operator's own *disabled* checkbox and `expires` date are
never overruled.

## Credentials and break-glass

`client_secret`, client keys and SP keys live in `config.xml` like other OPNsense
credentials (LDAP bind passwords and the like) and are never written to logs.

The local password (+ native TOTP) always stays active as a **break-glass** path: keep at
least one local admin.

For a managed OpenVPN profile, os-sso owns the instance's deferred-auth directive. Saving
the instance in the OpenVPN form drops it from `config.xml` (the form only knows its own
options), so os-sso puts it back right after every configuration save, and again in the
OpenVPN configure hook before core generates runtime configuration. The first one matters:
a start/restart from the Services page skips the configure hook, and would otherwise bring
an instance saved but not applied back up on its client certificate alone. Apply reports
invalid or conflicting selections instead of silently weakening authentication.
New VPN logins fail when the plugin or IdP is unavailable. Existing tunnels can continue
with a still-valid OpenVPN auth token until their recorded os-sso session is revoked or
reaches its configured maximum lifetime.

[SCIM](scim.md) needs a bearer token **and** a source-address allowlist, and refuses on the
same principles as the login path.
