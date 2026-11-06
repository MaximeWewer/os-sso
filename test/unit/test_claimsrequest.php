<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: the claims request parameter');

eq(
    '{"id_token":{"groups":{"essential":true}}}',
    OidcProtocol::claimsRequest(' { "id_token" : { "groups": {"essential": true} } } '),
    'a valid request is kept, compacted'
);
eq(
    '{"userinfo":{"email":null},"id_token":{"acr":{"values":["gold"]}}}',
    OidcProtocol::claimsRequest('{"userinfo":{"email":null},"id_token":{"acr":{"values":["gold"]}}}'),
    'both members, and null claims (default request), are kept as written'
);
eq('{"id_token":{}}', OidcProtocol::claimsRequest('{"id_token":{}}'), 'an empty object stays an object');
foreach (['not json', '[]', '{}', '"x"', '{"access_token":{"a":null}}', '{"id_token":["groups"]}', '{"id_token":"groups"}'] as $bad) {
    eq(null, OidcProtocol::claimsRequest($bad), 'refused: ' . $bad);
}
throws(
    fn() => new OidcProtocol(['issuer' => 'https://idp.example', 'claims_request' => '{"nope":1}']),
    'not a valid claims request',
    'a bad value configured anyway is refused at use, not sent'
);

$oidc = new OidcProtocol([
    'issuer' => 'https://idp.example',
    'client_id' => 'firewall',
    'redirect_uri' => 'https://fw.example/api/sso/oidc/callback',
    'claims_request' => '{"id_token":{"fw_role":{"value":"admins"}}}',
    'extra_params' => 'claims={"id_token":{"evil":null}}, prompt=login',
]);
(new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, [
    'issuer' => 'https://idp.example',
    'authorization_endpoint' => 'https://idp.example/auth',
]);
$_SESSION = [];
parse_str((string)parse_url($oidc->startLogin('/'), PHP_URL_QUERY), $sent);
eq('{"id_token":{"fw_role":{"value":"admins"}}}', $sent['claims'] ?? null, 'the authorization request carries it');
eq('login', $sent['prompt'] ?? null, 'other extras still go through');
$_SESSION = [];
