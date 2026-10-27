<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: exact issuer identity');

// Discovery 1.0 sections 4.1 and 7.2: remove a trailing slash only when
// constructing the well-known URL, never when recording the issuer identity.
foreach (['https://idp.example/tenant', 'https://idp.example/tenant/'] as $issuer) {
    $client = new OidcProtocol(['issuer' => $issuer, 'client_id' => 'firewall']);
    $validateIssuer = new ReflectionMethod($client, 'assertIssuerMatches');

    eq($issuer, $client->getIssuer(), 'the configured issuer is retained exactly: ' . $issuer);
    eq(
        true,
        nothrow(
            fn() => $validateIssuer->invoke($client, ['issuer' => $issuer]),
            'an exactly matching discovered issuer is accepted: ' . $issuer
        ),
        'and reported as exact: ' . $issuer
    );

    // Older versions trimmed both sides, so installs configured without the slash an
    // IdP publishes (Authentik, Auth0) must keep working after the upgrade: accepted,
    // but reported as not exact so discover() can log the value to configure.
    $other = str_ends_with($issuer, '/') ? rtrim($issuer, '/') : $issuer . '/';
    eq(
        false,
        nothrow(
            fn() => $validateIssuer->invoke($client, ['issuer' => $other]),
            'a trailing-slash-only difference still logs in: ' . $issuer
        ),
        'but is reported as not exact: ' . $issuer
    );
}

$client = new OidcProtocol(['issuer' => 'https://idp.example/tenant', 'client_id' => 'firewall']);
$validateIssuer = new ReflectionMethod($client, 'assertIssuerMatches');
foreach (['https://idp.example/tenant//', 'https://idp.example/Tenant', 'https://other.example/tenant', ''] as $other) {
    throws(
        fn() => $validateIssuer->invoke($client, ['issuer' => $other]),
        'does not match',
        'a distinct or missing issuer is refused: ' . $other
    );
}
