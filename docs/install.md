# Install

## Requirements

- **OPNsense 25.7 or newer** - the login-page SSO button hook (`ISSOContainer` /
  `listSSOproviders`) landed in core in 25.7.
- For OpenVPN login: **OpenVPN 2.6+** on the firewall and a web-auth-capable client
  (OpenVPN Connect, OpenVPN 3 Linux, Windows 2.6+). Managed OpenVPN instances use
  client-certificate verification plus browser authentication; leave the instance's
  core **Authentication** field empty.
- An Identity Provider you control or use (Keycloak, Authentik, Entra ID, Zitadel, …).

## From a release

Each release ships one package per FreeBSD ABI. Download the one matching your firewall's
base from the [Releases](../../../releases) page - check it with `pkg config ABI`
(e.g. `FreeBSD:14:amd64` → the `…-FreeBSD-14.pkg`), then install:

```sh
pkg add os-sso-devel-*-FreeBSD-14.pkg   # pick the file matching your ABI
```

Then reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**.

## From source

`make package` on an OPNsense dev VM, or the `.github/workflows/build-pkg.yml` job CI runs
on a `v*.*.*` tag.
