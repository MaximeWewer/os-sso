<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWT;
use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: signed authorization response (JARM)');

$idpKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($idpKey, $idpPem);
$otherKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($otherKey, $otherPem);

$response = fn(array $claims, string $pem = '') => JWT::encode($claims, $pem ?: $idpPem, 'RS256', 'idp-1');
$good = ['iss' => 'https://idp.example', 'aud' => 'firewall', 'exp' => time() + 60, 'code' => 'c0de', 'state' => 's1'];

eq('s1', OidcProtocol::peekJarmState($response($good)), 'the state is found inside the response, to locate the flow');
eq('', OidcProtocol::peekJarmState('not.a-jwt'), 'nothing is found in garbage');

$oidc = new OidcProtocol([
    'issuer' => 'https://idp.example',
    'client_id' => 'firewall',
    'redirect_uri' => 'https://fw.example/api/sso/oidc/callback',
    'jarm' => true,
    'form_post' => true,
]);
$disco = [
    'issuer' => 'https://idp.example',
    'authorization_endpoint' => 'https://idp.example/auth',
    'jwks_uri' => 'https://idp.example/jarm-jwks',
    'authorization_signing_alg_values_supported' => ['RS256'],
];
(new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, $disco);

$_SESSION = [];
parse_str((string)parse_url($oidc->startLogin('/'), PHP_URL_QUERY), $sent);
eq('form_post.jwt', $sent['response_mode'] ?? null, 'with form_post the IdP is asked for form_post.jwt');
$_SESSION = [];

if (!stateDirUsable()) {
    T::skip('JARM verification', 'state directory unavailable');
    return;
}
$b64u = fn(string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
$details = openssl_pkey_get_details($idpKey)['rsa'];
(new ReflectionMethod($oidc, 'cacheSet'))->invoke($oidc, 'jwks_https://idp.example/jarm-jwks', ['keys' => [[
    'kty' => 'RSA', 'kid' => 'idp-1', 'alg' => 'RS256', 'n' => $b64u($details['n']), 'e' => $b64u($details['e']),
]]]);
$decode = new ReflectionMethod($oidc, 'decodeJarm');

$claims = $decode->invoke($oidc, $disco, ['response' => $response($good)]);
eq(['c0de', 's1', 'https://idp.example'], [$claims['code'], $claims['state'], $claims['iss']], 'a verified response yields its code, state and issuer');
throws(fn() => $decode->invoke($oidc, $disco, ['response' => $response(['iss' => 'https://evil.example'] + $good)]), 'another issuer', 'another issuer is refused');
throws(fn() => $decode->invoke($oidc, $disco, ['response' => $response(['aud' => 'someone-else'] + $good)]), 'not for this client', 'another audience is refused');
$noExp = $good;
unset($noExp['exp']);
throws(fn() => $decode->invoke($oidc, $disco, ['response' => $response($noExp)]), 'no exp', 'a response that never expires is refused');
throws(fn() => $decode->invoke($oidc, $disco, ['response' => $response($good, $otherPem)]), 'Signature verification failed', 'a response signed by another key is refused');
throws(fn() => $decode->invoke($oidc, $disco, ['code' => 'c0de', 'state' => 's1']), 'not a signed JWT', 'a plain response is a downgrade, refused');
throws(fn() => $decode->invoke($oidc, $disco, ['response' => 'a.b.c.d.e']), 'not a signed JWT', 'an encrypted (JWE) response is refused');
