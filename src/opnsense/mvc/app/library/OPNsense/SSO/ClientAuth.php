<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use Firebase\JWT\JWT;

/**
 * How this firewall proves it is the OAuth client when it calls a token endpoint.
 *
 * The shared secret (client_secret_basic / _post) is what most IdPs default to, but it
 * is also what a growing number of them refuse: a long-lived bearer credential sitting
 * in config.xml and travelling on every token request. The alternatives all remove that
 * secret from the wire, in increasing order of key management:
 *
 *   client_secret_jwt    the secret never leaves the box; it signs a short-lived,
 *                        single-use assertion (HMAC, so still a shared secret at rest)
 *   private_key_jwt      no shared secret at all: an asymmetric key here, its public
 *                        half registered at the IdP (see publicJwks())
 *   tls_client_auth      the client certificate on the TLS handshake IS the credential
 *   self_signed_tls_...  same, with a self-signed certificate the IdP pinned
 *
 * The assertion methods follow RFC 7523 / OIDC Core section 9; the mTLS ones RFC 8705,
 * including its mtls_endpoint_aliases redirection.
 */
final class ClientAuth
{
    public const BASIC = 'client_secret_basic';
    public const POST = 'client_secret_post';
    public const SECRET_JWT = 'client_secret_jwt';
    public const PRIVATE_KEY_JWT = 'private_key_jwt';
    public const TLS = 'tls_client_auth';
    public const TLS_SELF_SIGNED = 'self_signed_tls_client_auth';

    public const METHODS = [
        self::BASIC,
        self::POST,
        self::SECRET_JWT,
        self::PRIVATE_KEY_JWT,
        self::TLS,
        self::TLS_SELF_SIGNED,
    ];

    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    /** Assertions are single-use and consumed immediately; a minute is generous. */
    private const ASSERTION_TTL = 60;

    private const HMAC_ALGS = ['HS256', 'HS384', 'HS512'];
    private const ASYMMETRIC_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384'];

    private string $clientId;
    private string $clientSecret;
    /** 'auto', or one of METHODS */
    private string $configured;
    private string $assertionAlg;
    private string $privateKey;
    private string $privateKeyId;
    private string $tlsCert;
    private string $tlsKey;

    /**
     * @param array $cfg client_id, client_secret, token_auth_method, assertion_alg,
     *                   private_key, private_key_id, tls_cert, tls_key
     */
    public function __construct(array $cfg)
    {
        $this->clientId = (string)($cfg['client_id'] ?? '');
        $this->clientSecret = (string)($cfg['client_secret'] ?? '');
        $this->configured = strtolower(trim((string)($cfg['token_auth_method'] ?? 'auto'))) ?: 'auto';
        $this->assertionAlg = strtoupper(trim((string)($cfg['assertion_alg'] ?? ''))) ?: 'RS256';
        $this->privateKey = trim((string)($cfg['private_key'] ?? ''));
        $this->privateKeyId = trim((string)($cfg['private_key_id'] ?? ''));
        $this->tlsCert = trim((string)($cfg['tls_cert'] ?? ''));
        $this->tlsKey = trim((string)($cfg['tls_key'] ?? ''));

        if ($this->configured !== 'auto' && !in_array($this->configured, self::METHODS, true)) {
            throw new \RuntimeException('OIDC: unknown token endpoint authentication method');
        }
    }

    /**
     * The method to use against this IdP.
     *
     * "auto" only ever picks between the two secret methods, and takes the answer from
     * the IdP's own discovery document: a fair number advertise only client_secret_post,
     * against which a Basic header is simply an unauthenticated client. It never
     * auto-selects an assertion or mTLS method, because those need key material the
     * operator has to have registered at the IdP first -- silently switching to one
     * would break every login the moment an IdP added it to its advertised list.
     */
    public function method(array $disco): string
    {
        if ($this->configured !== 'auto') {
            return $this->configured;
        }
        $advertised = (array)($disco['token_endpoint_auth_methods_supported'] ?? []);
        if (empty($advertised) || in_array(self::BASIC, $advertised, true)) {
            return self::BASIC;
        }
        return in_array(self::POST, $advertised, true) ? self::POST : self::BASIC;
    }

    /**
     * The token endpoint to call.
     *
     * RFC 8705: an IdP doing mTLS client authentication frequently serves it on a
     * separate host or port, published under mtls_endpoint_aliases. Sending the request
     * to the ordinary endpoint there means presenting a certificate nobody asked for and
     * being treated as an unauthenticated client.
     */
    public function tokenEndpoint(array $disco, string $method): string
    {
        if ($method === self::TLS || $method === self::TLS_SELF_SIGNED) {
            $alias = $disco['mtls_endpoint_aliases']['token_endpoint'] ?? '';
            if (is_string($alias) && $alias !== '') {
                return $alias;
            }
        }
        return (string)($disco['token_endpoint'] ?? '');
    }

    /**
     * Add this client's credentials to an outgoing token request.
     *
     * @param array $body form fields, by reference
     * @param array $headers request headers, by reference
     * @param array $curlOptions extra curl options (mTLS certificate), by reference
     */
    public function apply(array $disco, string $method, array &$body, array &$headers, array &$curlOptions): void
    {
        switch ($method) {
            case self::POST:
                $body['client_id'] = $this->clientId;
                $body['client_secret'] = $this->requireSecret($method);
                break;

            case self::SECRET_JWT:
            case self::PRIVATE_KEY_JWT:
                // client_id alongside the assertion is redundant but harmless, and some
                // IdPs want it to find the client before verifying the signature.
                $body['client_id'] = $this->clientId;
                $body['client_assertion_type'] = self::ASSERTION_TYPE;
                $body['client_assertion'] = $this->assertion($disco, $method);
                break;

            case self::TLS:
            case self::TLS_SELF_SIGNED:
                // The certificate presented during the handshake is the whole credential
                // (RFC 8705); the body only names which client it belongs to.
                $body['client_id'] = $this->clientId;
                $curlOptions += $this->tlsCurlOptions();
                break;

            default: // client_secret_basic
                $headers[] = 'Authorization: Basic ' . base64_encode(
                    rawurlencode($this->clientId) . ':' . rawurlencode($this->requireSecret($method))
                );
                break;
        }
    }

    /**
     * The client assertion: a JWT saying "I am this client", addressed to this IdP,
     * valid for seconds, and never the same twice.
     *
     * `aud` is the token endpoint URL, which OIDC Core section 9 says SHOULD be used and
     * which every implementation accepts -- addressing it to the issuer instead is a
     * habit some IdPs also allow, but the endpoint is the portable answer.
     */
    private function assertion(array $disco, string $method): string
    {
        $endpoint = (string)($disco['token_endpoint'] ?? '');
        if ($endpoint === '') {
            throw new \RuntimeException('OIDC: discovery has no token_endpoint to address the assertion to');
        }
        $now = time();
        $claims = [
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'aud' => $endpoint,
            // Single-use: an IdP that keeps a jti cache refuses a replayed assertion, and
            // one that does not still only has the TTL above to work with.
            'jti' => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
            'iat' => $now,
            'exp' => $now + self::ASSERTION_TTL,
        ];

        if ($method === self::SECRET_JWT) {
            $alg = in_array($this->assertionAlg, self::HMAC_ALGS, true) ? $this->assertionAlg : 'HS256';
            $secret = $this->requireSecret($method);
            // RFC 7518: an HMAC key must be at least as long as the hash it feeds, and
            // the signer enforces it. Say so here, with the number the operator needs --
            // otherwise a short client secret fails every login with "key is too short"
            // and nothing pointing at which field to change.
            $needed = intdiv((int)substr($alg, -3), 8);
            if (strlen($secret) < $needed) {
                throw new \RuntimeException(sprintf(
                    'OIDC: %s with %s needs a client secret of at least %d characters (this one has %d) -- '
                    . 'lengthen it at the IdP, or use a shorter-digest algorithm',
                    self::SECRET_JWT,
                    $alg,
                    $needed,
                    strlen($secret)
                ));
            }
            return JWT::encode($claims, $secret, $alg);
        }

        if ($this->privateKey === '') {
            throw new \RuntimeException('OIDC: private_key_jwt needs a client private key');
        }
        if (!in_array($this->assertionAlg, self::ASYMMETRIC_ALGS, true)) {
            throw new \RuntimeException(sprintf(
                'OIDC: %s is not an asymmetric signing algorithm (private_key_jwt accepts %s)',
                $this->assertionAlg,
                implode(', ', self::ASYMMETRIC_ALGS)
            ));
        }
        return JWT::encode(
            $claims,
            $this->privateKey,
            $this->assertionAlg,
            $this->privateKeyId !== '' ? $this->privateKeyId : null
        );
    }

    /**
     * curl options carrying the mTLS client certificate.
     *
     * curl wants paths, not PEM strings, so the pair is materialised under the vetted
     * state directory at 0600 and reused while it matches. StateDir refuses a directory
     * it does not own outright, which is the only reason writing a private key there is
     * acceptable -- it is the same key config.xml already holds.
     */
    private function tlsCurlOptions(): array
    {
        if ($this->tlsCert === '' || $this->tlsKey === '') {
            throw new \RuntimeException(
                'OIDC: mutual-TLS client authentication needs a client certificate and its private key'
            );
        }
        return [
            CURLOPT_SSLCERT => self::materialise('cert', $this->tlsCert),
            CURLOPT_SSLCERTTYPE => 'PEM',
            CURLOPT_SSLKEY => self::materialise('key', $this->tlsKey),
            CURLOPT_SSLKEYTYPE => 'PEM',
        ];
    }

    /** How long a staged PEM nobody has used survives. */
    private const STAGED_TTL = 2592000; // 30 days

    /**
     * Write a PEM to a private file named after its own digest, and return the path.
     *
     * The name is the digest, so a rotated certificate or key is written next to the old
     * one rather than over it -- and the old one is a private key that stays on disk for
     * good unless something removes it. Each use refreshes the file's timestamp, so
     * "nobody has presented this in a month" is a safe reading of "no provider uses it
     * any more".
     */
    private static function materialise(string $kind, string $pem): string
    {
        $dir = StateDir::path('oidc-mtls');
        $file = $dir . '/' . $kind . '-' . hash('sha256', $pem) . '.pem';
        if (!is_file($file) || (string)@file_get_contents($file) !== $pem) {
            if (@file_put_contents($file, $pem, LOCK_EX) === false) {
                throw new \RuntimeException('OIDC: cannot stage the mutual-TLS ' . $kind);
            }
            @chmod($file, 0600);
        } else {
            @touch($file); // still in use
        }
        self::sweepStaged($dir);
        return $file;
    }

    /** Drop staged key material no token request has needed in a long while. */
    private static function sweepStaged(string $dir): void
    {
        $now = time();
        foreach (glob($dir . '/*.pem') ?: [] as $staged) {
            if (($now - (int)@filemtime($staged)) > self::STAGED_TTL) {
                @unlink($staged);
            }
        }
    }

    private function requireSecret(string $method): string
    {
        if ($this->clientSecret === '') {
            throw new \RuntimeException(sprintf('OIDC: %s needs a client secret', $method));
        }
        return $this->clientSecret;
    }

    /**
     * The public half of the private_key_jwt key, as a JWKS document.
     *
     * Registering a public key by hand means getting it out of the box somehow; served
     * here, the IdP's "JWKS URL" field can simply point at us and a key rollover needs no
     * copy-paste. Only the public parameters are ever read out of the key -- there is no
     * code path here that can emit `d`.
     *
     * @return array{keys:array<int,array<string,string>>}
     */
    public static function publicJwks(string $privateKeyPem, string $alg, string $kid): array
    {
        $privateKeyPem = trim($privateKeyPem);
        if ($privateKeyPem === '') {
            throw new \RuntimeException('no client private key is configured');
        }
        $key = @openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new \RuntimeException('the client private key is not a readable PEM');
        }
        $details = @openssl_pkey_get_details($key);
        if (!is_array($details)) {
            throw new \RuntimeException('cannot read the client private key parameters');
        }

        $jwk = ['use' => 'sig', 'alg' => strtoupper($alg) ?: 'RS256'];
        if ($kid !== '') {
            $jwk['kid'] = $kid;
        }

        if (($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA) {
            $jwk += [
                'kty' => 'RSA',
                'n' => self::b64u((string)$details['rsa']['n']),
                'e' => self::b64u((string)$details['rsa']['e']),
            ];
            return ['keys' => [$jwk]];
        }
        if (($details['type'] ?? null) === OPENSSL_KEYTYPE_EC) {
            $curve = self::JWK_CURVES[(string)($details['ec']['curve_name'] ?? '')] ?? '';
            if ($curve === '') {
                throw new \RuntimeException('unsupported EC curve for a JWK');
            }
            $jwk += [
                'kty' => 'EC',
                'crv' => $curve,
                'x' => self::b64u((string)$details['ec']['x']),
                'y' => self::b64u((string)$details['ec']['y']),
            ];
            return ['keys' => [$jwk]];
        }
        throw new \RuntimeException('only RSA and EC client keys can be published as a JWK');
    }

    private const JWK_CURVES = [
        'prime256v1' => 'P-256',
        'secp384r1' => 'P-384',
        'secp521r1' => 'P-521',
    ];

    private static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
