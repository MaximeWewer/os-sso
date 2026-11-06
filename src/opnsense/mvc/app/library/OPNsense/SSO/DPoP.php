<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Firebase\JWT\JWT;

/**
 * DPoP proofs (RFC 9449): binding an access token to a key the firewall holds.
 *
 * A bearer access token works for whoever has the bytes; a DPoP-bound one only with a
 * proof signed by the key it was issued to. The firewall uses its access token for one
 * thing -- the userinfo call that brings in groups -- and only during the login, so the
 * key is ephemeral: generated when the login starts, its thumbprint sent with the
 * authorization request so the code itself is bound to it (dpop_jkt, RFC 9449 section
 * 10), kept in the login's session until the callback, and dropped there. There is
 * nothing to store, rotate or register at the IdP.
 */
final class DPoP
{
    private string $privateKey;
    /** @var array<string,string> the public key, as the JWK every proof carries */
    private array $jwk;

    /** @param string $privateKeyPem a key carried over from the start of the login; '' for a new one */
    public function __construct(string $privateKeyPem = '')
    {
        $key = $privateKeyPem !== ''
            ? openssl_pkey_get_private($privateKeyPem)
            : openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new \RuntimeException('DPoP: could not load or generate a key');
        }
        $details = openssl_pkey_get_details($key);
        if (($details['ec']['curve_name'] ?? '') !== 'prime256v1') {
            throw new \RuntimeException('DPoP: the key is not a P-256 EC key');
        }
        $ec = $details['ec'];
        $this->privateKey = $pem;
        // P-256 coordinates are 32 bytes; openssl may drop leading zero bytes.
        $this->jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => self::b64u(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => self::b64u(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)),
        ];
    }

    /**
     * A proof for one HTTP request.
     *
     * @param string $method the request's HTTP method
     * @param string $url the request's URL; query and fragment are not part of `htu`
     * @param string $nonce a nonce the server handed out with DPoP-Nonce, '' when none
     * @param string $accessToken the token the request presents, '' for the token request
     */
    public function proof(string $method, string $url, string $nonce = '', string $accessToken = ''): string
    {
        $claims = [
            'jti' => self::b64u(random_bytes(16)),
            'htm' => strtoupper($method),
            'htu' => strtok($url, '?#'),
            'iat' => time(),
        ];
        if ($nonce !== '') {
            $claims['nonce'] = $nonce;
        }
        if ($accessToken !== '') {
            // Binds the proof to the very token it accompanies.
            $claims['ath'] = self::b64u(hash('sha256', $accessToken, true));
        }
        return JWT::encode($claims, $this->privateKey, 'ES256', null, ['typ' => 'dpop+jwt', 'jwk' => $this->jwk]);
    }

    /** @return array<string,string> */
    public function publicJwk(): array
    {
        return $this->jwk;
    }

    /** The private key, to carry it from the start of the login to its callback. */
    public function privateKeyPem(): string
    {
        return $this->privateKey;
    }

    /**
     * The JWK thumbprint (RFC 7638) that dpop_jkt names: the SHA-256 of the required
     * members, in lexicographic order, with no whitespace.
     */
    public function thumbprint(): string
    {
        $canonical = json_encode(
            ['crv' => $this->jwk['crv'], 'kty' => $this->jwk['kty'], 'x' => $this->jwk['x'], 'y' => $this->jwk['y']],
            JSON_UNESCAPED_SLASHES
        );
        return self::b64u(hash('sha256', (string)$canonical, true));
    }

    private static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
