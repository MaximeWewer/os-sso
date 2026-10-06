<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Firebase\JWT\JWK;

/**
 * Parses a JWKS into verification keys, filling in the "alg" a key does not carry.
 *
 * RFC 7517 makes "alg" optional on a JWK, and Microsoft Entra ID omits it on every
 * key -- but the vendored php-jwt binds each Key to one algorithm and refuses a JWK
 * without one ('JWK must contain an "alg" parameter'). Its own escape hatch is a single
 * default for the whole set, which is wrong as soon as a set mixes key types: an EC key
 * labelled RS256 never verifies anything. So the algorithm is chosen per key, from what
 * the key physically is:
 *
 *   - EC and OKP keys admit exactly one algorithm, named by their curve.
 *   - An RSA key admits RS* and PS*; the first of those the issuer advertises (OIDC
 *     discovery, or the JWT provider's configured list) wins, RS256 otherwise -- the
 *     one every OIDC provider must support.
 *
 * A key whose algorithm cannot be inferred is dropped rather than failing the whole
 * set: one unusable key must not lock everyone out of the keys that do work. Only
 * asymmetric algorithms are ever inferred, so an "oct" key without an "alg" never
 * becomes an HMAC secret.
 */
final class JwkSet
{
    private const EC_CURVE_ALG = [
        'P-256' => 'ES256',
        'P-384' => 'ES384',
        'secp256k1' => 'ES256K',
    ];

    private const OKP_CURVE_ALG = [
        'Ed25519' => 'EdDSA',
    ];

    /**
     * @param array $raw the JWKS document, decoded to arrays
     * @param string[] $advertised the issuer's signing algorithms, in preference order
     * @return \Firebase\JWT\Key[] keyed by kid
     */
    public static function parse(array $raw, array $advertised): array
    {
        if (isset($raw['keys']) && is_array($raw['keys'])) {
            foreach ($raw['keys'] as $i => $jwk) {
                if (!is_array($jwk) || isset($jwk['alg'])) {
                    continue;
                }
                $alg = self::inferAlg($jwk, $advertised);
                if ($alg === null) {
                    unset($raw['keys'][$i]);
                } else {
                    $raw['keys'][$i]['alg'] = $alg;
                }
            }
        }
        return JWK::parseKeySet($raw);
    }

    /** The algorithm a JWK without "alg" verifies with, null when it cannot be told. */
    private static function inferAlg(array $jwk, array $advertised): ?string
    {
        $crv = (string)($jwk['crv'] ?? '');
        switch ((string)($jwk['kty'] ?? '')) {
            case 'RSA':
                foreach ($advertised as $alg) {
                    if (is_string($alg) && preg_match('/^(RS|PS)(256|384|512)$/', $alg)) {
                        return $alg;
                    }
                }
                return 'RS256';
            case 'EC':
                return self::EC_CURVE_ALG[$crv] ?? null;
            case 'OKP':
                return self::OKP_CURVE_ALG[$crv] ?? null;
            default:
                return null;
        }
    }
}
