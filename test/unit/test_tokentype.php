<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWT;
use OPNsense\SSO\Protocol\OidcProtocol;
use OPNsense\SSO\TokenType;

T::group('Explicit typing (RFC 8725): reading typ');

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $pem);
$typed = fn(?string $typ, array $claims = ['sub' => 'x']) => JWT::encode($claims, $pem, 'RS256', 'k1', $typ === null ? null : ['typ' => $typ]);

eq('logout+jwt', TokenType::of($typed('logout+jwt')), 'a declared type is read');
eq('logout+jwt', TokenType::of($typed('application/Logout+JWT')), 'case and the application/ prefix do not matter');
eq('', TokenType::of(JWT::encode(['sub' => 'x'], $pem, 'RS256', 'k1', ['typ' => null])), 'no typ reads as none');
throws(fn() => TokenType::refuse($typed('logout+jwt'), [TokenType::LOGOUT], 'test'), 'not accepted', 'a foreign kind is refused');
nothrow(fn() => TokenType::refuse($typed('JWT'), [TokenType::LOGOUT], 'test'), 'a plain JWT is not');
nothrow(fn() => TokenType::allowOnly($typed('logout+jwt'), [TokenType::LOGOUT, TokenType::GENERIC], 'test'), 'an allowed type passes');
throws(fn() => TokenType::allowOnly($typed('at+jwt'), [TokenType::LOGOUT, TokenType::GENERIC], 'test'), 'expected logout+jwt', 'another declared type does not');

T::group('Explicit typing on the OIDC token paths');

if (!stateDirUsable()) {
    T::skip('OIDC token paths', 'state directory unavailable');
    return;
}
$b64u = fn(string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
$details = openssl_pkey_get_details($key)['rsa'];
$oidc = new OidcProtocol(['issuer' => 'https://idp.example', 'client_id' => 'firewall']);
(new ReflectionMethod($oidc, 'cacheSet'))->invoke($oidc, 'jwks_https://idp.example/typ-jwks', ['keys' => [[
    'kty' => 'RSA', 'kid' => 'k1', 'alg' => 'RS256', 'n' => $b64u($details['n']), 'e' => $b64u($details['e']),
]]]);
$disco = [
    'issuer' => 'https://idp.example', 'jwks_uri' => 'https://idp.example/typ-jwks',
    'id_token_signing_alg_values_supported' => ['RS256'],
];
(new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, $disco);

$idClaims = ['iss' => 'https://idp.example', 'aud' => 'firewall', 'sub' => 'alice', 'nonce' => 'n1',
    'iat' => time(), 'exp' => time() + 60];
$validateId = new ReflectionMethod($oidc, 'validateIdToken');
eq('alice', $validateId->invoke($oidc, $disco, $typed('JWT', $idClaims), 'n1')->sub, 'an ID token typed JWT is accepted');
eq('alice', $validateId->invoke($oidc, $disco, $typed(null, $idClaims), 'n1')->sub, 'and so is one with no typ');
throws(
    fn() => $validateId->invoke($oidc, $disco, $typed('logout+jwt', $idClaims), 'n1'),
    'not accepted',
    'a token typed logout+jwt is never an ID token'
);

$logoutClaims = ['iss' => 'https://idp.example', 'aud' => 'firewall', 'sub' => 'alice', 'iat' => time(),
    'jti' => bin2hex(random_bytes(8)), 'events' => ['http://schemas.openid.net/event/backchannel-logout' => new stdClass()]];
eq('alice', $oidc->validateLogoutToken($typed('logout+jwt', $logoutClaims))['sub'], 'a logout token typed logout+jwt is accepted');
$logoutClaims['jti'] = bin2hex(random_bytes(8));
eq('alice', $oidc->validateLogoutToken($typed('JWT', $logoutClaims))['sub'], 'and one with the generic JWT most libraries write');
$logoutClaims['jti'] = bin2hex(random_bytes(8));
throws(
    fn() => $oidc->validateLogoutToken($typed('at+jwt', $logoutClaims)),
    'expected logout+jwt',
    'a logout token declaring another kind is refused'
);
$logoutClaims['jti'] = bin2hex(random_bytes(8));
eq('alice', $oidc->validateLogoutToken($typed(null, $logoutClaims))['sub'], 'an untyped logout token is still accepted (older IdPs)');
