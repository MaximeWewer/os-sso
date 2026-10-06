# High availability

os-sso registers **Single Sign-On** as an OPNsense XMLRPC synchronization area. It
contains the plugin-owned `OPNsense.SSO` model: OpenVPN web-auth profiles, their provider
selection, assigned OpenVPN instance UUIDs, public host and timeout.

Install the same os-sso version on both firewalls before synchronizing. Configure XMLRPC
only on the primary node under **System - High Availability - Settings** and select:

- **Single Sign-On** for the os-sso OpenVPN web-auth profiles;
- **Authentication Servers** for the OIDC and SAML providers and their credentials;
- **OpenVPN** for the server instances and managed authentication directives;
- **Users and Groups** when automatic account creation, group mapping or SCIM is used;
- **Certificates and Authorities** when a provider references certificates from the
  OPNsense trust store.

The profile assignments use OpenVPN instance UUIDs, so **Single Sign-On** and **OpenVPN**
must be synchronized together. After changing either, use **System - High Availability -
Status - Synchronize and reconfigure all**. OPNsense configuration synchronization is
on demand; schedule its **HA update and reconfigure backup** cron action if delayed
replication is acceptable.

Use a shared DNS name on the CARP virtual address as every provider's Base URL and every
VPN profile's firewall host. Register callback, logout and metadata URLs with that shared
name, never a node-specific address.

## What is deliberately not synchronized

XMLRPC copies durable configuration, not live authentication state. Browser sessions,
OIDC state/nonce/PKCE records, SAML request and replay records, rate limits, captive-portal
grants and active OpenVPN tunnels remain local. A failover during a browser ceremony
therefore requires the user to start the login again. Existing OpenVPN clients reconnect
to the newly active node and authenticate again.

SCIM and login-time account changes are writes to `config.xml`, but XMLRPC still copies
them only on the next HA synchronization. Choose a schedule that matches the acceptable
revocation delay. For immediate revocation on both nodes, configure the IdP to provision
both node-specific SCIM endpoints if it supports multiple targets. The shared CARP endpoint
alone reaches only the node that is active at that moment.

The generated `vpn.conf` is not copied. OPNsense reloads templates and services on the
backup after synchronization, so each node derives it from synchronized configuration.
If a profile or dependent section is missing, os-sso refuses VPN authentication instead
of falling back to certificate-only access.
