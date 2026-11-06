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

T::group('DPoP: the code is bound to the login key (dpop_jkt)');

$login = new DPoP();
$reloaded = new DPoP($login->privateKeyPem());
eq($login->publicJwk(), $reloaded->publicJwk(), 'the key carried in the session is the same key at the callback');
eq($login->thumbprint(), $reloaded->thumbprint(), 'with the same thumbprint');
$jwk = $login->publicJwk();
eq(
    rtrim(strtr(base64_encode(hash('sha256', '{"crv":"P-256","kty":"EC","x":"' . $jwk['x'] . '","y":"' . $jwk['y'] . '"}', true)), '+/', '-_'), '='),
    $login->thumbprint(),
    'the thumbprint is RFC 7638: required members, sorted, no whitespace'
);
$rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($rsa, $rsaPem);
throws(fn() => new DPoP($rsaPem), 'not a P-256', 'a key of another kind is refused');

$oidc = new OPNsense\SSO\Protocol\OidcProtocol([
    'issuer' => 'https://idp.example',
    'client_id' => 'firewall',
    'redirect_uri' => 'https://fw.example/api/sso/oidc/callback',
    'dpop' => true,
    'extra_params' => 'dpop_jkt=someone-elses-key',
]);
(new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, [
    'issuer' => 'https://idp.example',
    'authorization_endpoint' => 'https://idp.example/auth',
]);
$_SESSION = [];
parse_str((string)parse_url($oidc->startLogin('/'), PHP_URL_QUERY), $sent);
$kept = array_values(array_filter($_SESSION, fn($v, $k) => str_ends_with((string)$k, 'dpop'), ARRAY_FILTER_USE_BOTH));
truthy(count($kept) === 1 && str_contains((string)$kept[0], 'PRIVATE KEY'), 'the login key waits in the session');
eq((new DPoP((string)($kept[0] ?? '')))->thumbprint(), $sent['dpop_jkt'] ?? null, 'and the authorization request names it (an extra cannot override it)');
$_SESSION = [];
