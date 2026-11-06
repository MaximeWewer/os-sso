<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use OPNsense\SSO\Protocol\OidcProtocol;

T::group('OIDC: signed request object (JAR, RFC 9101)');

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $pem);
$public = openssl_pkey_get_details($key)['key'];

$jar = function (array $extra) use ($pem): OidcProtocol {
    $oidc = new OidcProtocol($extra + [
        'issuer' => 'https://idp.example',
        'client_id' => 'firewall',
        'redirect_uri' => 'https://fw.example/api/sso/oidc/callback',
        'signed_request' => true,
        'private_key' => $pem,
        'private_key_id' => 'fw-1',
    ]);
    (new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, [
        'issuer' => 'https://idp.example',
        'authorization_endpoint' => 'https://idp.example/auth',
    ]);
    return $oidc;
};

$_SESSION = [];
parse_str((string)parse_url($jar([])->startLogin('/'), PHP_URL_QUERY), $sent);
eq(['client_id', 'response_type', 'scope', 'request'], array_keys($sent), 'only the request object travels, with what OIDC wants repeated');
$object = JWT::decode($sent['request'], new Key($public, 'RS256'));
eq('firewall', $object->iss ?? null, 'signed by this client');
eq('https://idp.example', $object->aud ?? null, 'for this IdP');
eq('https://fw.example/api/sso/oidc/callback', $object->redirect_uri ?? null, 'carrying the redirect_uri');
truthy(isset($object->state, $object->nonce, $object->code_challenge, $object->jti, $object->exp), 'and state, nonce, PKCE, jti and a short expiry');
$header = json_decode(base64_decode(strtr(explode('.', $sent['request'])[0], '-_', '+/')), true);
eq('oauth-authz-req+jwt', $header['typ'] ?? null, 'explicitly typed as a request object');
eq('fw-1', $header['kid'] ?? null, 'and naming the client key');

$_SESSION = [];
throws(fn() => $jar(['private_key' => ''])->startLogin('/'), 'needs a client private key', 'no key, no request object, and it says so');
$_SESSION = [];
throws(
    fn() => $jar(['assertion_alg' => 'HS256'])->startLogin('/'),
    'not an asymmetric signing algorithm',
    'a symmetric algorithm is refused'
);
$_SESSION = [];
