<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC front-channel logout: what the iframe request may end');

$oidc = new OidcProtocol(['issuer' => 'https://idp.example/realm', 'client_id' => 'firewall']);
(new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, [
    'issuer' => 'https://idp.example/realm',
    'authorization_endpoint' => 'https://login.idp.example/auth',
]);

eq('abc-123', $oidc->frontChannelSid(['iss' => 'https://idp.example/realm', 'sid' => 'abc-123']), 'iss + sid name the session');
eq('abc-123', $oidc->frontChannelSid(['sid' => 'abc-123']), 'an IdP that sends no iss (the provider is in the URL) still works');
throws(
    fn() => $oidc->frontChannelSid(['iss' => 'https://evil.example/realm', 'sid' => 'abc-123']),
    'issuer mismatch',
    'a different issuer is refused'
);
throws(
    fn() => $oidc->frontChannelSid(['iss' => 'https://idp.example/realm/', 'sid' => 'abc-123']),
    'issuer mismatch',
    'and compared exactly'
);
// No sid, nothing to end: our cookie never reaches a third-party iframe, so guessing
// "the current session" is not an option.
throws(fn() => $oidc->frontChannelSid(['iss' => 'https://idp.example/realm']), 'no usable sid', 'a request without sid is refused');
throws(fn() => $oidc->frontChannelSid(['sid' => ['x']]), 'no usable sid', 'a non-string sid is refused');
throws(fn() => $oidc->frontChannelSid(['sid' => "a\nb"]), 'no usable sid', 'a sid with control characters is refused');

eq(
    ['https://idp.example', 'https://login.idp.example'],
    $oidc->frontChannelOrigins(),
    'only the IdP origins may frame the page'
);
