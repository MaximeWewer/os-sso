<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWT;
use OPNsense\SSO\JwkSet;

$b64 = fn(string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

$rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($rsa, $rsaPem);
$rsaDetails = openssl_pkey_get_details($rsa)['rsa'];
// The shape Microsoft Entra ID publishes: kty/use/kid/n/e, and no "alg".
$rsaJwk = ['kty' => 'RSA', 'use' => 'sig', 'kid' => 'r1', 'n' => $b64($rsaDetails['n']), 'e' => $b64($rsaDetails['e'])];

$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
openssl_pkey_export($ec, $ecPem);
$ecDetails = openssl_pkey_get_details($ec)['ec'];
$ecJwk = ['kty' => 'EC', 'use' => 'sig', 'kid' => 'e1', 'crv' => 'P-256', 'x' => $b64($ecDetails['x']), 'y' => $b64($ecDetails['y'])];

$claims = ['sub' => 'u1', 'exp' => time() + 60];

T::group('JwkSet: a JWKS whose keys carry no "alg" (Microsoft Entra ID)');

$keys = nothrow(fn() => JwkSet::parse(['keys' => [$rsaJwk]], ['RS256']), 'an RSA key without alg parses');
eq('RS256', $keys['r1']->getAlgorithm() ?? null, 'it takes the advertised RS256');
$decoded = nothrow(
    fn() => JWT::decode(JWT::encode($claims, $rsaPem, 'RS256', 'r1'), $keys),
    'an RS256 token verifies against it'
);
eq('u1', $decoded->sub ?? null, 'and its claims come through');

$keys = JwkSet::parse(['keys' => [$rsaJwk]], []);
eq('RS256', $keys['r1']->getAlgorithm(), 'RS256 when the issuer advertises nothing');

$keys = JwkSet::parse(['keys' => [$rsaJwk]], ['ES256', 'PS256', 'RS256']);
eq('PS256', $keys['r1']->getAlgorithm(), 'an RSA key takes the first advertised RSA algorithm');

T::group('JwkSet: a mixed set gets an algorithm per key type');

// A single default for the whole set (what php-jwt offers) would label the EC key RS256
// here, and nothing signed by it would ever verify.
$keys = JwkSet::parse(['keys' => [$rsaJwk, $ecJwk]], ['RS256', 'ES256']);
eq('RS256', $keys['r1']->getAlgorithm(), 'the RSA key is RS256');
eq('ES256', $keys['e1']->getAlgorithm(), 'the P-256 key is ES256, whatever comes first in the list');
$decoded = nothrow(
    fn() => JWT::decode(JWT::encode($claims, $ecPem, 'ES256', 'e1'), $keys),
    'an ES256 token verifies against the mixed set'
);
eq('u1', $decoded->sub ?? null, 'and its claims come through');

T::group('JwkSet: what it must not do');

$keys = JwkSet::parse(['keys' => [$rsaJwk + ['alg' => 'RS384']]], ['RS256']);
eq('RS384', $keys['r1']->getAlgorithm(), 'an explicit "alg" on the key is kept');

$keys = JwkSet::parse(['keys' => [$rsaJwk]], ['HS256', 'none']);
eq('RS256', $keys['r1']->getAlgorithm(), 'an advertised HS256/none is never given to a key');

// An "oct" key without alg would become an HMAC secret if it borrowed a default.
$keys = JwkSet::parse(['keys' => [$rsaJwk, ['kty' => 'oct', 'kid' => 'o1', 'k' => $b64('secret')]]], ['HS256']);
eq(['r1'], array_keys($keys), 'an oct key without alg is dropped, the rest of the set survives');

$keys = JwkSet::parse(['keys' => [$rsaJwk, array_merge($ecJwk, ['crv' => 'P-521'])]], []);
eq(['r1'], array_keys($keys), 'a key on an unsupported curve is dropped, not fatal to the set');

throws(fn() => JwkSet::parse(['keys' => []], []), 'did not contain any keys', 'an empty set is still refused');
