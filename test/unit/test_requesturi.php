<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\RequestObjectStore;
use OPNsense\SSO\Protocol\OidcProtocol;

T::group('JAR by reference: the request object store');

$id = RequestObjectStore::put('header.payload.signature');
truthy(preg_match('/^[A-Za-z0-9_-]{43}$/', $id) === 1, 'the id is 256 random bits, URL-safe');
eq('header.payload.signature', RequestObjectStore::get($id), 'the object is served under its id');
eq('header.payload.signature', RequestObjectStore::get($id), 'and still on a second fetch');
eq(null, RequestObjectStore::get($id, time() + RequestObjectStore::TTL + 1), 'but not once expired');
eq(null, RequestObjectStore::get('../../etc/passwd'), 'an id that is not one is refused');
eq(null, RequestObjectStore::get(str_repeat('A', 43)), 'an unknown id finds nothing');
$old = RequestObjectStore::put('old', time() - RequestObjectStore::TTL - 5);
RequestObjectStore::put('new');
truthy(!is_file(OPNsense\SSO\StateDir::path('request') . "/$old.json"), 'expired objects are swept on the next put');

T::group('JAR by reference: the authorization request');

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $pem);
$make = function (array $extra) use ($pem) {
    $oidc = new OidcProtocol($extra + [
        'issuer' => 'https://idp.example',
        'client_id' => 'firewall',
        'redirect_uri' => 'https://fw.example/api/sso/oidc/callback',
        'signed_request' => true,
        'token_auth_method' => 'private_key_jwt',
        'assertion_alg' => 'RS256',
        'private_key' => $pem,
    ]);
    (new ReflectionProperty($oidc, 'discovery'))->setValue($oidc, [
        'issuer' => 'https://idp.example',
        'authorization_endpoint' => 'https://idp.example/auth',
    ]);
    $_SESSION = [];
    parse_str((string)parse_url($oidc->startLogin('/'), PHP_URL_QUERY), $sent);
    return $sent;
};

$byValue = $make([]);
truthy(isset($byValue['request']) && !isset($byValue['request_uri']), 'by default the object travels by value');
$byRef = $make(['request_uri_base' => 'https://fw.example/api/sso/oidc/request']);
truthy(!isset($byRef['request']), 'by reference, the URL no longer carries the object');
eq(['client_id', 'response_type', 'scope', 'request_uri'], array_keys($byRef), 'only the outer parameters and the link');
$link = (string)($byRef['request_uri'] ?? '');
truthy(str_starts_with($link, 'https://fw.example/api/sso/oidc/request?id='), 'which points at the firewall');
parse_str((string)parse_url($link, PHP_URL_QUERY), $q);
$jwt = (string)RequestObjectStore::get((string)($q['id'] ?? ''));
$claims = json_decode(base64_decode(strtr(explode('.', $jwt . '..')[1], '-_', '+/')), true);
eq('https://fw.example/api/sso/oidc/callback', $claims['redirect_uri'] ?? null, 'and serves the signed request object');
$unsigned = $make(['signed_request' => false, 'request_uri_base' => 'https://fw.example/api/sso/oidc/request']);
truthy(!isset($unsigned['request_uri']) && isset($unsigned['redirect_uri']), 'without JAR there is nothing to reference');
$_SESSION = [];
