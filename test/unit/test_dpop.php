<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use OPNsense\SSO\DPoP;

T::group('DPoP proofs (RFC 9449)');

$dpop = new DPoP();
$proof = $dpop->proof('post', 'https://idp.example/token?x=1#frag', 'n-123');
[$h] = explode('.', $proof);
$header = json_decode(base64_decode(strtr($h, '-_', '+/')), true);

eq('dpop+jwt', $header['typ'] ?? null, 'typed dpop+jwt');
eq('ES256', $header['alg'] ?? null, 'signed ES256');
eq(['kty', 'crv', 'x', 'y'], array_keys($header['jwk'] ?? []), 'carrying the public key, and nothing private');

$claims = JWT::decode($proof, JWK::parseKey($header['jwk'], 'ES256'));
truthy(true, 'the proof verifies with the key it carries');
eq('POST', $claims->htm, 'naming the method');
eq('https://idp.example/token', $claims->htu, 'and the URL, without query or fragment');
eq('n-123', $claims->nonce ?? null, 'with the server nonce when there is one');
truthy(!isset($claims->ath), 'no ath on the token request');
truthy(abs(time() - (int)$claims->iat) < 5 && strlen((string)$claims->jti) >= 16, 'fresh, with a unique jti');

$token = 'access.token.value';
$resource = JWT::decode($dpop->proof('GET', 'https://idp.example/userinfo', '', $token), JWK::parseKey($header['jwk'], 'ES256'));
eq(
    rtrim(strtr(base64_encode(hash('sha256', $token, true)), '+/', '-_'), '='),
    $resource->ath ?? null,
    'a resource request is bound to the token (ath)'
);
truthy(!isset($resource->nonce), 'no nonce until a server asks for one');
truthy($resource->jti !== $claims->jti, 'every proof has its own jti');
eq($header['jwk'], (new DPoP())->publicJwk() === $header['jwk'] ? null : $header['jwk'], 'each login gets its own key');
