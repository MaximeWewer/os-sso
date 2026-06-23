<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use OPNsense\SSO\NormalizedIdentity;

/**
 * A protocol turns a browser redirect ceremony into a NormalizedIdentity.
 * Both legs run in the same browser session; anti-replay state (state/nonce/
 * PKCE verifier for OIDC, InResponseTo for SAML) is stashed between them.
 */
interface ProtocolInterface
{
    /**
     * Leg 1: build the URL the browser should be redirected to (IdP authorize /
     * SSO endpoint) and persist any single-use anti-replay material in session.
     *
     * @param string $returnUrl where to send the user after a successful login
     * @return string absolute redirect URL
     */
    public function startLogin(string $returnUrl): string;

    /**
     * Leg 2: validate the IdP's response (callback / ACS) and produce a verified
     * identity. MUST throw on any validation failure -- never return a partial or
     * unverified identity.
     *
     * @param array $request request parameters (query for OIDC, POST for SAML)
     * @return NormalizedIdentity verified
     * @throws \RuntimeException on any validation failure
     */
    public function handleCallback(array $request): NormalizedIdentity;

    /**
     * @return string the return URL stashed during startLogin (validated), or '/'
     */
    public function consumeReturnUrl(): string;
}
