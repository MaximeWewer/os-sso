<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: the authorization response names its issuer (RFC 9207)');

$oidc = new OidcProtocol(['issuer' => 'https://idp.example/realm', 'client_id' => 'firewall']);
$check = new ReflectionMethod($oidc, 'assertResponseIssuer');
$sends = ['issuer' => 'https://idp.example/realm', 'authorization_response_iss_parameter_supported' => true];
$silent = ['issuer' => 'https://idp.example/realm'];

nothrow(fn() => $check->invoke($oidc, $sends, ['code' => 'c', 'iss' => 'https://idp.example/realm']), 'the right iss is accepted');
throws(
    fn() => $check->invoke($oidc, $sends, ['code' => 'c', 'iss' => 'https://evil.example/realm']),
    'another issuer',
    'a response from another issuer is refused (mix-up)'
);
throws(
    fn() => $check->invoke($oidc, $sends, ['code' => 'c', 'iss' => 'https://idp.example/realm/']),
    'another issuer',
    'compared exactly'
);
throws(
    fn() => $check->invoke($oidc, $sends, ['code' => 'c']),
    'has no iss',
    'a missing iss is refused when the IdP declares it always sends one'
);
nothrow(fn() => $check->invoke($oidc, $silent, ['code' => 'c']), 'an IdP that does not send iss (Entra ID) still works');
throws(
    fn() => $check->invoke($oidc, $silent, ['code' => 'c', 'iss' => 'https://evil.example/realm']),
    'another issuer',
    'but a wrong iss is refused even from such an IdP'
);
throws(
    fn() => $check->invoke($oidc, $sends, ['error' => 'access_denied', 'iss' => 'https://evil.example/realm']),
    'another issuer',
    'an error response is checked too'
);
