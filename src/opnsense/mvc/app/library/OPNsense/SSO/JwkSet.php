<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * Parses a JWKS into verification keys, filling in the "alg" a key does not carry.
 *
 * RFC 7517 makes "alg" optional on a JWK, and Microsoft Entra ID omits it on every
 * key -- but the vendored php-jwt binds each Key to one algorithm and refuses a JWK
 * without one ('JWK must contain an "alg" parameter'). Its own escape hatch is a single
 * default for the whole set, which is wrong as soon as a set mixes key types: an EC key
 * labelled RS256 never verifies anything. So the algorithm is chosen per key:
 *
 *   - An explicit "alg" on the key is kept: the IdP has pinned it.
 *   - EC and OKP keys admit exactly one algorithm, named by their curve.
 *   - An RSA key admits RS* and PS*, and nothing in the key says which. With the token
 *     at hand, the token's own algorithm is used -- once algorithm() has checked it is
 *     allowed, asymmetric and supported -- so an issuer advertising [RS512, RS256] still
 *     verifies its RS256 tokens: the order of that list was never a preference. Without
 *     a token (counting keys for diagnostics) the first advertised RSA algorithm stands
 *     in, RS256 otherwise -- the one every OIDC provider must support.
 *
 * A key whose algorithm cannot be inferred is dropped rather than failing the whole
 * set: one unusable key must not lock everyone out of the keys that do work. Only
 * asymmetric algorithms are ever inferred, so an "oct" key without an "alg" never
 * becomes an HMAC secret. Taking the algorithm from the token header is safe for the
 * same reason: the signature is still verified, against an asymmetric key, with an
 * algorithm the allowlist accepted.
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
     * @param string[] $advertised the allowed signing algorithms (discovery, or the
     *                 JWT provider's configured list); empty allows any asymmetric one
     * @param string $jwt the token about to be verified, '' when there is none
     * @return \Firebase\JWT\Key[] keyed by kid
     */
    public static function parse(array $raw, array $advertised, string $jwt = ''): array
    {
        $algorithm = $jwt === '' ? null : self::algorithm($jwt, $advertised);
        if (isset($raw['keys']) && is_array($raw['keys'])) {
            foreach ($raw['keys'] as $i => $jwk) {
                if (!is_array($jwk) || isset($jwk['alg'])) {
                    continue;
                }
                $alg = self::inferAlg($jwk, $advertised, $algorithm);
                if ($alg === null) {
                    unset($raw['keys'][$i]);
                } else {
                    $raw['keys'][$i]['alg'] = $alg;
                }
            }
        }
        return JWK::parseKeySet($raw);
    }

    /**
     * The algorithm a token says it is signed with, if it may be: asymmetric, supported
     * by php-jwt, and in $allowed (when that list is not empty). Throws otherwise.
     *
     * Read from the unverified header on purpose -- it only picks which algorithm an
     * alg-less RSA key verifies with. JWT::decode() still checks the signature, and an
     * HMAC algorithm is refused here, so a forged header can neither skip verification
     * nor turn a public key into a shared secret.
     */
    public static function algorithm(string $jwt, array $allowed): string
    {
        $parts = explode('.', $jwt);
        $header = count($parts) === 3
            ? json_decode((string)base64_decode(strtr($parts[0], '-_', '+/'), true), true)
            : null;
        $algorithm = is_array($header) ? ($header['alg'] ?? null) : null;
        if (
            !is_string($algorithm)
            || !isset(JWT::$supported_algs[$algorithm])
            || str_starts_with($algorithm, 'HS')
            || ($allowed !== [] && !in_array($algorithm, $allowed, true))
        ) {
            throw new \RuntimeException('JWT: signature algorithm is not allowed');
        }
        return $algorithm;
    }

    /** The algorithm a JWK without "alg" verifies with, null when it cannot be told. */
    private static function inferAlg(array $jwk, array $advertised, ?string $algorithm): ?string
    {
        $crv = (string)($jwk['crv'] ?? '');
        switch ((string)($jwk['kty'] ?? '')) {
            case 'RSA':
                if ($algorithm !== null) {
                    return preg_match('/^(RS|PS)(256|384|512)$/D', $algorithm) ? $algorithm : null;
                }
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
