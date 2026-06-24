<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use OPNsense\SSO\NormalizedIdentity;

/**
 * Forward-auth provider: validates a signed JWT handed over by a TRUSTED upstream
 * proxy in an HTTP header. There is no redirect ceremony -- the proxy
 * already authenticated the user and vouches for them with a signature.
 *
 * This object only does the cryptographic + claim validation; the controller is
 * responsible for the part that makes this safe at all: refusing the header unless
 * the request actually comes from the configured proxy source IP. A JWT that merely
 * verifies is NOT enough -- without the source gate anyone could forge the header.
 *
 * Hard rules:
 *   - Asymmetric algorithms only (RS256/ES256/PS256...). A symmetric "HS" alg with a
 *     public verification key is the classic alg-confusion takeover -- refused here.
 *   - `iss` and `aud` are pinned; `exp`/`nbf` enforced by firebase/php-jwt.
 */
final class JwtProtocol
{
    private const HTTP_TIMEOUT = 8;
    private const MAX_BODY = 1048576;
    private const MAX_LEEWAY = 300;
    private const CACHE_DIR = '/var/tmp/os-sso-jwt';
    private const JWKS_TTL = 3600;

    private string $issuer;
    private string $audience;
    private string $jwksUrl;
    private string $publicKey;
    /** @var string[] */
    private array $algorithms;
    private string $usernameClaim;
    private string $groupsClaim;

    public function __construct(array $cfg)
    {
        $this->issuer = (string)($cfg['issuer'] ?? '');
        $this->audience = (string)($cfg['audience'] ?? '');
        $this->jwksUrl = rtrim((string)($cfg['jwks_url'] ?? ''), '/');
        $this->publicKey = trim((string)($cfg['public_key'] ?? ''));
        $this->algorithms = !empty($cfg['algorithms']) ? array_values($cfg['algorithms']) : ['RS256', 'ES256'];
        $this->usernameClaim = (string)($cfg['username_claim'] ?? 'preferred_username');
        $this->groupsClaim = (string)($cfg['groups_claim'] ?? 'groups');

        if (!class_exists(\Firebase\JWT\JWT::class)) {
            require_once __DIR__ . '/../vendor/autoload.php';
        }

        if ($this->issuer === '' || $this->audience === '') {
            throw new \RuntimeException('JWT: issuer and audience are required');
        }
        // Asymmetric only -- never let a public key double as an HMAC secret.
        foreach ($this->algorithms as $a) {
            if (stripos((string)$a, 'HS') === 0 || strcasecmp((string)$a, 'none') === 0) {
                throw new \RuntimeException('JWT: symmetric/none algorithms are not allowed');
            }
        }
        if ($this->jwksUrl !== '' && stripos($this->jwksUrl, 'https://') !== 0) {
            throw new \RuntimeException('JWT: JWKS URL must be https');
        }
        if ($this->jwksUrl === '' && $this->publicKey === '') {
            throw new \RuntimeException('JWT: a JWKS URL or a static public key is required');
        }
        // Configurable clock-skew tolerance for exp/nbf (default 60s, capped).
        $leeway = (int)($cfg['leeway'] ?? 60);
        JWT::$leeway = max(0, min($leeway, self::MAX_LEEWAY));
    }

    /**
     * Verify a raw JWT string and return the validated identity.
     * @throws \RuntimeException on any signature/claim failure
     */
    public function verify(string $jwt): NormalizedIdentity
    {
        if ($jwt === '') {
            throw new \RuntimeException('JWT: empty token');
        }
        // decode() enforces signature + exp/nbf and rejects alg:none. Each key carries
        // its own algorithm, so the token cannot downgrade to a different alg.
        try {
            $claims = JWT::decode($jwt, $this->keys(false));
        } catch (\UnexpectedValueException $e) {
            // Unknown kid => the proxy likely rotated keys: refetch JWKS once. Only
            // meaningful for the JWKS case; a static key has no kid to miss.
            if ($this->jwksUrl === '' || stripos($e->getMessage(), 'kid') === false) {
                throw $e;
            }
            $claims = JWT::decode($jwt, $this->keys(true));
        }

        if (!isset($claims->iss) || !hash_equals($this->issuer, (string)$claims->iss)) {
            throw new \RuntimeException('JWT: issuer mismatch');
        }
        $aud = (array)($claims->aud ?? []);
        if (!in_array($this->audience, $aud, true)) {
            throw new \RuntimeException('JWT: audience does not contain this service');
        }
        // decode() only enforces exp WHEN present; a forward-auth token without exp
        // would be replayable forever. Require it so the proxy-minted token expires.
        if (!isset($claims->exp)) {
            throw new \RuntimeException('JWT: token has no exp claim');
        }
        return $this->toIdentity((array)$claims);
    }

    /**
     * @return \Firebase\JWT\Key|\Firebase\JWT\Key[] a keyset (JWKS, looked up by kid)
     *         or a single Key (static PEM, which needs no kid in the token header)
     */
    private function keys(bool $force)
    {
        if ($this->jwksUrl !== '') {
            $cacheKey = 'jwks_' . $this->jwksUrl;
            $raw = $force ? null : $this->cacheGet($cacheKey);
            if ($raw === null) {
                $raw = $this->httpGetJson($this->jwksUrl);
                $this->cacheSet($cacheKey, $raw);
            }
            // Default alg for JWKS entries that omit "alg" (still asymmetric per check).
            return JWK::parseKeySet($raw, $this->algorithms[0]);
        }
        // Static PEM public key: a single Key, so decode() does not require a "kid".
        // The first configured algorithm must match the key type.
        return new Key($this->publicKey, $this->algorithms[0]);
    }

    private function toIdentity(array $claims): NormalizedIdentity
    {
        $id = new NormalizedIdentity('');
        $id->subject = (string)($claims['sub'] ?? '');
        $id->username = (string)($claims[$this->usernameClaim] ?? '');
        $id->email = (string)($claims['email'] ?? '');
        $id->emailVerified = filter_var($claims['email_verified'] ?? false, FILTER_VALIDATE_BOOL);
        $id->displayName = (string)($claims['name'] ?? '');
        $id->groups = $this->extractGroups($claims);
        $id->raw = $claims;
        return $id;
    }

    private function extractGroups(array $claims): array
    {
        $g = $claims[$this->groupsClaim] ?? [];
        if (is_string($g)) {
            $g = preg_split('/[,\s]+/', $g, -1, PREG_SPLIT_NO_EMPTY);
        }
        return array_values(array_filter(array_map('strval', (array)$g)));
    }

    /* ---- JWKS disk cache (TTL, www-owned, 0600) ----------------------- */

    private function cacheGet(string $key): ?array
    {
        $f = self::CACHE_DIR . '/' . hash('sha256', $key) . '.json';
        if (!is_file($f) || (time() - (int)@filemtime($f)) > self::JWKS_TTL) {
            return null;
        }
        $data = json_decode((string)@file_get_contents($f), true);
        return is_array($data) ? $data : null;
    }

    private function cacheSet(string $key, array $data): void
    {
        if (!is_dir(self::CACHE_DIR)) {
            @mkdir(self::CACHE_DIR, 0700, true);
        }
        @chmod(self::CACHE_DIR, 0700);
        $f = self::CACHE_DIR . '/' . hash('sha256', $key) . '.json';
        @file_put_contents($f, json_encode($data), LOCK_EX);
        @chmod($f, 0600);
    }

    private function httpGetJson(string $url): array
    {
        if (stripos($url, 'https://') !== 0) {
            throw new \RuntimeException('JWT: refusing non-https JWKS ' . $url);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_TIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => fn($c, $dt, $dn) => $dn > self::MAX_BODY ? 1 : 0,
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($resp === false) {
            throw new \RuntimeException('JWT: JWKS fetch failed: ' . $err);
        }
        if ($code < 200 || $code >= 300) {
            throw new \RuntimeException('JWT: JWKS HTTP ' . $code);
        }
        $json = json_decode((string)$resp, true);
        if (!is_array($json)) {
            throw new \RuntimeException('JWT: JWKS is not valid JSON');
        }
        return $json;
    }
}
