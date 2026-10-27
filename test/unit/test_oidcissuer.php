<?php

/* SPDX-License-Identifier: BSD-2-Clause */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: exact issuer identity');

// Discovery 1.0 sections 4.1 and 7.2: remove a trailing slash only when
// constructing the well-known URL, never when comparing issuer identities.
foreach (['https://idp.example/tenant', 'https://idp.example/tenant/'] as $issuer) {
    $client = new OidcProtocol(['issuer' => $issuer, 'client_id' => 'firewall']);
    $validateIssuer = new ReflectionMethod($client, 'assertIssuerMatches');

    eq($issuer, $client->getIssuer(), 'the configured issuer is retained exactly: ' . $issuer);
    nothrow(
        fn() => $validateIssuer->invoke($client, ['issuer' => $issuer]),
        'an exactly matching discovered issuer is accepted: ' . $issuer
    );

    $other = str_ends_with($issuer, '/') ? rtrim($issuer, '/') : $issuer . '/';
    throws(
        fn() => $validateIssuer->invoke($client, ['issuer' => $other]),
        'does not match',
        'adding or removing a trailing slash changes the issuer: ' . $issuer
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
