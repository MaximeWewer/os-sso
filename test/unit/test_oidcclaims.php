<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: required subject claim');

$oidc = new OidcProtocol([
    'issuer' => 'https://idp.example',
    'client_id' => 'firewall',
]);
$assertSubject = new ReflectionMethod($oidc, 'assertSubject');

nothrow(
    fn() => $assertSubject->invoke($oidc, (object)['sub' => '248289761001']),
    'a stable ASCII subject is accepted'
);
throws(
    fn() => $assertSubject->invoke($oidc, (object)[]),
    'no valid sub',
    'a missing subject is refused'
);
throws(
    fn() => $assertSubject->invoke($oidc, (object)['sub' => '']),
    'no valid sub',
    'an empty subject is refused'
);
throws(
    fn() => $assertSubject->invoke($oidc, (object)['sub' => ['not', 'scalar']]),
    'no valid sub',
    'a structured subject is refused'
);
throws(
    fn() => $assertSubject->invoke($oidc, (object)['sub' => str_repeat('a', 256)]),
    'no valid sub',
    'a subject longer than the OIDC limit is refused'
);
throws(
    fn() => $assertSubject->invoke($oidc, (object)['sub' => "line\nbreak"]),
    'no valid sub',
    'a subject containing a control character is refused'
);
