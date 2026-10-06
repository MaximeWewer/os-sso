# WebGUI, Captive Portal, OpenVPN

Where an SSO login lands, and what each door needs. A provider's **Applies to** says which
of the three it serves; empty means all three.

## WebGUI

Each configured OIDC/SAML/JWT server adds a **“Login with …”** button to the firewall
login page. Users click it, authenticate at the IdP, and land in the WebGUI with
privileges from their mapped groups.

A provider whose **Applies to** does not list `webgui` gets no button - and its login
endpoint refuses a WebGUI login, which is the half that matters: the button is only the
part an attacker does not need.

## Captive Portal

1. Add the OIDC/SAML server.
2. **Services ▸ Captive Portal ▸ Administration**: in the zone, add that server under
   *Authentication* (optionally set an enforce-group).
3. Build the bundled portal template and upload it:

   ```sh
   configctl sso build_cp_template     # prints /tmp/os-sso-cp-template.zip
   ```

   Upload that zip under *Templates* and select it on the zone. The page shows one button
   per SSO provider and keeps the standard username/password form. Mind the core naming
   rule: a template *name* may not contain a hyphen (letters, digits, `.`, `,`, `_` and
   spaces only).

   In the lab, `test/vagrant/setup-cp.sh` does the whole thing - zone, template, render,
   unpack, start - and documents the ordering the UI normally handles.
4. Make sure the zone lets unauthenticated clients reach the firewall WebGUI and the IdP
   (zone *allowed addresses* / pre-auth) so the login can complete.

A user who signs in through SSO gets their device authorized in that portal zone. If that
grant cannot be written down, the authorization is taken straight back and the login
refused: the record is the only handle a back-channel logout, a SCIM deactivation, the
session sweeper or the *End* button has on a portal client, so an access nothing has a
record of is one nothing can revoke.

The "connected" page then bounces them to wherever they were originally headed, which is
an arbitrary external site by design - that is what a captive portal does. The URL is
validated for shape only (no other scheme, no protocol-relative host, no userinfo), never
against an allowlist, so treat `/api/sso/{oidc,saml}/{callback,acs}?cpurl=…` as an
intentional redirector. It carries nothing with it: the page is sent `no-referrer` so the
callback URL - which holds the authorization code and state - never reaches the
destination.

## OpenVPN (deferred web-auth)

OpenVPN 2.6+ “pending auth” lets the client authenticate in a browser:

1. The client connects and is shown a `WEB_AUTH` URL.
2. It opens the URL, logs in at the IdP (passkey/MFA there).
3. The tunnel comes up once the login succeeds.

Configure it under **System ▸ Access ▸ SSO VPN web-auth**. A **profile** defines one SSO
policy and can protect one or more OpenVPN servers: select the enabled server instances,
protocol, the authentication server (picked from the configured OIDC/SAML servers), the
host the client's browser opens, and the web-auth timeout. **Apply** writes
`/usr/local/etc/sso/vpn.conf`, installs the deferred-auth directives in every selected
instance and asks core to regenerate them. No manual custom option or SSH edit is
required.

Every selected OpenVPN instance must be an enabled **server** and its **Authentication**
field must be empty: os-sso supplies that authentication hook. OPNsense core consequently
requires client-certificate verification to remain enabled. That gives the connection two
independent factors: a device certificate and the browser login (including the IdP's MFA or
passkey). os-sso also adds `auth-user-pass-optional`, so a web-auth-capable client need not
send a reusable password.

Set **Auth Token Lifetime** on the OpenVPN instance if an established client should pass an
OpenVPN-generated token on later TLS renegotiations instead of opening the browser again.
The token is checked locally by OpenVPN; Keycloak logout, SCIM deactivation and the os-sso
maximum session lifetime can still terminate the recorded tunnel. In an HA pair, use the
same **Auth Token secret** on both nodes if tokens must survive a failover.

### Existing manually wired profiles

Profiles created before managed instances were introduced keep their instance field empty
and continue to use their existing manual directive:

```text
auth-user-pass-verify "/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh staff" via-file
```

Select an instance and apply the profile to move it under plugin management. The plugin
then owns that directive and `auth-user-pass-optional`; disabling, deleting or moving the
profile removes both from the old instance without touching its other options.

### Managed hook reconciliation

OPNsense's OpenVPN form only knows its built-in option list, so saving an instance can
discard plugin-owned directives. os-sso repairs them immediately before every normal
OpenVPN **Apply** through the existing core configure hook. Applying an os-sso profile
also reconciles the selected instances and asks core to regenerate OpenVPN configuration
only when a managed directive changed. Invalid or conflicting selections are reported,
left untouched and logged without preventing independent valid instances from being
reconciled.

> **Mind the username.** OpenVPN takes it from the client and never revisits it on a
> deferred-auth path: the browser login decides *whether* the tunnel comes up, not *whose*
> it is. **Require the username to match** is therefore enabled by default and refuses
> an empty username as well as a mismatch. Turn it off only when the server never uses
> the username for `username-as-common-name`, a `client-config-dir`, per-user rules,
> addressing or revocation, and clients intentionally send a throwaway value. Both names
> are logged on the firewall when that compatibility mode is used.

Use a web-auth-capable client (OpenVPN Connect, OpenVPN 3 Linux) - see
[`test/vpn-client/README.md`](../test/vpn-client/README.md). With web-auth disabled the
script denies the connection rather than deferring it. What the client sees:

```text
AUTH_PENDING received, extending handshake timeout from 60s to 240s
Info command was pushed by server ('WEB_AUTH::https://vpn.example.com/api/sso/oidc/login?provider=keycloak&vpn=48e5ef74…')
   ... the user authenticates in the browser ...
Initialization Sequence Completed
```

and on the firewall: `os-sso vpn: authorized tunnel for 'kctest' from 10.0.2.2`.

## Logout

The WebGUI **Logout** button performs Single Logout: it ends the IdP session for OIDC
(`end_session_endpoint`) and SAML, and falls back to the normal local logout for password
sessions. Register at your IdP:

- OIDC post-logout redirect: `https://<opnsense>/`
- SAML logout service: `https://<opnsense>/api/sso/saml/slo?provider=<name>`

**Back-channel logout (OIDC).** Register
`https://<opnsense>/api/sso/oidc/backchannel?provider=<name>` as the client's back-channel
logout URI and the IdP can end the firewall session by itself - when the user logs out
elsewhere, or when you disable the account. Without it (and without a maximum session
lifetime) an open session survives until it idles out. The endpoint takes only a signed
`logout_token`: issuer, audience, `iat` freshness, the backchannel-logout event, absence
of a `nonce` and single-use `jti` are all checked before any session is ended.

## API access (not SSO)

The OPNsense **API** keeps using its own key/secret credentials - os-sso does not turn an
IdP token into API access, and cannot: API authentication is handled by core before any
plugin sees the request, so bearer-token support would have to land in core, not here.
What does work is the useful half: an account provisioned by SSO is a normal local
account, so you can issue it an API key under *System ▸ Access ▸ Users* and the ACL
applies the groups os-sso mapped. Its local *password* stays unusable - API keys are
separate credentials, not the password.
