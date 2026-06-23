<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Protocol-neutral identity produced by OidcProtocol / SamlProtocol and consumed
 * by the shared core (IdentityMapper, GroupMapper, SessionEstablisher).
 *
 * This is the ONLY contract the core depends on: protocols differ wildly, the
 * core must not. Nothing here is trusted for authorization on its own -- the
 * mappers decide what a local username and groups become.
 */
final class NormalizedIdentity
{
    /** @var string subject identifier as asserted by the IdP (OIDC `sub` / SAML NameID) */
    public string $subject = '';

    /** @var string the claim/attribute chosen as username source (may be empty) */
    public string $username = '';

    /** @var string email if asserted (fallback match key) */
    public string $email = '';

    /** @var bool whether the IdP asserts the email is verified (OIDC email_verified) */
    public bool $emailVerified = false;

    /** @var string human display name if asserted */
    public string $displayName = '';

    /** @var string[] raw group / role values as asserted by the IdP (pre-mapping) */
    public array $groups = [];

    /** @var array<string,mixed> all raw claims/attributes, for debugging and custom mapping */
    public array $raw = [];

    /** @var string code of the auth server (authserver name) that produced this identity */
    public string $authServer = '';

    public function __construct(string $authServer)
    {
        $this->authServer = $authServer;
    }
}
