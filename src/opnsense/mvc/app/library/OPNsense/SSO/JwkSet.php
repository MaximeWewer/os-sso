<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * Parses asymmetric verification keys without treating discovery list order as a
 * per-key algorithm. An explicit JWK alg stays authoritative; otherwise the token's
 * allowed algorithm supplies the RSA choice and the curve supplies the EC/OKP choice.
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
     * @param string[] $advertised the allowed signing algorithms
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
