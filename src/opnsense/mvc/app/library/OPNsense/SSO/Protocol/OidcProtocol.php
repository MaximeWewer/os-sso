<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use OPNsense\SSO\NormalizedIdentity;

/**
 * Hand-rolled OpenID Connect Relying Party on top of firebase/php-jwt.
 *
 * Division of labour:
 *   firebase/php-jwt does the cryptographically delicate parts -- JWT signature
 *   verification, exp/nbf/iat with leeway, JWKS parsing, and rejecting alg:none.
 *   WE do discovery, the auth-code+PKCE dance, the token exchange, and -- the
 *   part that actually decides security -- the ID token CLAIM validation. Every
 *   omitted check below is a known RP vulnerability class.
 *
 * Session keys (single-use, cleared on callback):
 *   sso_oidc_state, sso_oidc_nonce, sso_oidc_verifier, sso_oidc_return
 */
final class OidcProtocol implements ProtocolInterface
{
    private const HTTP_TIMEOUT = 8;       // seconds, short on purpose
    private const MAX_BODY = 1048576;     // 1 MiB cap on IdP responses
    private const LEEWAY = 60;            // max clock skew
    private const CACHE_DIR = '/var/tmp/os-sso-oidc';
    private const DISCO_TTL = 3600;       // discovery document cache TTL
    private const JWKS_TTL = 3600;        // JWKS cache TTL (refetched early on kid miss)

    private string $issuer;
    private string $clientId;
    private string $clientSecret;
    /** @var string[] */
    private array $scopes;
    private string $usernameClaim;
    private string $groupsClaim;
    private string $redirectUri;
    private bool $usePkce;
    /** per-provider session-key prefix so concurrent flows do not clobber each other */
    private string $sessionPrefix;

    /** @var array<string,mixed>|null cached discovery document */
    private ?array $discovery = null;

    /** @var string raw id_token from the last successful callback (for RP logout) */
    private string $lastIdToken = '';

    /**
     * @param array $cfg issuer, client_id, client_secret, scopes[], username_claim,
     *                    groups_claim, redirect_uri, use_pkce
     */
    public function __construct(array $cfg)
    {
        $this->issuer = rtrim((string)($cfg['issuer'] ?? ''), '/');
        $this->clientId = (string)($cfg['client_id'] ?? '');
        $this->clientSecret = (string)($cfg['client_secret'] ?? '');
        $this->scopes = $cfg['scopes'] ?? ['openid', 'email', 'profile'];
        $this->usernameClaim = (string)($cfg['username_claim'] ?? 'preferred_username');
        $this->groupsClaim = (string)($cfg['groups_claim'] ?? 'groups');
        $this->redirectUri = (string)($cfg['redirect_uri'] ?? '');
        $this->usePkce = (bool)($cfg['use_pkce'] ?? true);
        // Namespace the in-flight session keys (state/nonce/verifier/return) by
        // provider so two concurrent logins to different providers in one browser
        // session cannot overwrite each other's single-use anti-replay material.
        $provider = (string)($cfg['provider'] ?? '');
        $this->sessionPrefix = 'sso_oidc_' . ($provider === '' ? '' : substr(hash('sha256', $provider), 0, 16) . '_');

        // Pull in the composer-vendored firebase/php-jwt (Makefile post-extract).
        if (!class_exists(\Firebase\JWT\JWT::class)) {
            require_once __DIR__ . '/../vendor/autoload.php';
        }

        // issuer MUST be https -- no downgrade, ever.
        if (stripos($this->issuer, 'https://') !== 0) {
            throw new \RuntimeException('OIDC issuer must be an https URL');
        }
        JWT::$leeway = self::LEEWAY;
    }

    public function startLogin(string $returnUrl): string
    {
        $disco = $this->discover();

        $state = $this->randomToken();
        $nonce = $this->randomToken();
        $_SESSION[$this->skey('state')] = $state;
        $_SESSION[$this->skey('nonce')] = $nonce;
        $_SESSION[$this->skey('return')] = $this->sanitizeReturnUrl($returnUrl);

        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'nonce' => $nonce,
        ];

        if ($this->usePkce) {
            $verifier = $this->randomToken(64);
            $_SESSION[$this->skey('verifier')] = $verifier;
            $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
            $params['code_challenge'] = $challenge;
            $params['code_challenge_method'] = 'S256';
        }

        return $disco['authorization_endpoint'] . '?' . http_build_query($params);
    }

    public function handleCallback(array $request): NormalizedIdentity
    {
        // Snapshot AND clear all single-use material up front, so a failure midway
        // can never leave reusable state/nonce/verifier behind in the session.
        $sessionState = (string)($_SESSION[$this->skey('state')] ?? '');
        $sessionNonce = (string)($_SESSION[$this->skey('nonce')] ?? '');
        $verifier = (string)($_SESSION[$this->skey('verifier')] ?? '');
        unset($_SESSION[$this->skey('state')], $_SESSION[$this->skey('nonce')], $_SESSION[$this->skey('verifier')]);

        // state: anti-CSRF, single use.
        if ($sessionState === '' || !hash_equals($sessionState, (string)($request['state'] ?? ''))) {
            throw new \RuntimeException('OIDC: state mismatch (possible CSRF)');
        }
        if (!empty($request['error'])) {
            throw new \RuntimeException('OIDC: IdP returned error: ' . (string)$request['error']);
        }
        $code = (string)($request['code'] ?? '');
        if ($code === '') {
            throw new \RuntimeException('OIDC: missing authorization code');
        }

        $disco = $this->discover();
        $tokens = $this->exchangeCode($disco, $code, $verifier);
        $idToken = (string)($tokens['id_token'] ?? '');
        if ($idToken === '') {
            throw new \RuntimeException('OIDC: token response had no id_token');
        }

        $claims = $this->validateIdToken($disco, $idToken, $sessionNonce);
        $this->lastIdToken = $idToken; // keep for RP-initiated logout (id_token_hint)

        // Optionally enrich from userinfo (groups/email often live there).
        $merged = (array)$claims;
        if (!empty($tokens['access_token']) && !empty($disco['userinfo_endpoint'])) {
            $userInfo = $this->fetchUserInfo($disco, (string)$tokens['access_token']);
            if (!empty($userInfo)) {
                // OIDC Core §5.3.2: the UserInfo `sub` MUST exactly match the ID
                // token `sub`; otherwise the response MUST NOT be used. Without this
                // a substituted/mixed-up access token could enrich (and override)
                // our authorization claims with a different subject's data.
                $idSub = (string)($claims->sub ?? '');
                if ($idSub === '' || !hash_equals($idSub, (string)($userInfo['sub'] ?? ''))) {
                    throw new \RuntimeException('OIDC: userinfo sub mismatch (response rejected)');
                }
                $merged = array_merge($merged, $userInfo);
            }
        }

        return $this->toIdentity($merged);
    }

    public function consumeReturnUrl(): string
    {
        $url = $_SESSION[$this->skey('return')] ?? '/';
        unset($_SESSION[$this->skey('return')]);
        return $this->sanitizeReturnUrl((string)$url);
    }

    /** Per-provider session key for the in-flight single-use material. */
    private function skey(string $name): string
    {
        return $this->sessionPrefix . $name;
    }

    public function getLastIdToken(): string
    {
        return $this->lastIdToken;
    }

    /**
     * Build the RP-initiated logout URL (OIDC RP-Initiated Logout 1.0): redirect
     * the browser here to end the session at the IdP. Returns '' if the IdP has no
     * end_session_endpoint (the caller then just does a local logout).
     */
    public function buildLogoutUrl(string $idTokenHint, string $postLogoutRedirect): string
    {
        $disco = $this->discover();
        if (empty($disco['end_session_endpoint'])) {
            return '';
        }
        $params = ['client_id' => $this->clientId];
        if ($idTokenHint !== '') {
            $params['id_token_hint'] = $idTokenHint;
        }
        if ($postLogoutRedirect !== '') {
            $params['post_logout_redirect_uri'] = $postLogoutRedirect;
        }
        return $disco['end_session_endpoint'] . '?' . http_build_query($params);
    }

    /* -------------------------------------------------------------------- */

    /**
     * ID token validation. firebase/php-jwt has already checked signature and
     * exp/nbf/iat by the time we read these. Everything below is OURS and each
     * line is load-bearing.
     *
     * @return object decoded, validated claims
     */
    private function validateIdToken(array $disco, string $idToken, string $sessionNonce): object
    {
        // An OIDC ID token MUST be asymmetrically signed. decode() pins the key's
        // alg to the header alg (blocking alg-confusion), but would still accept a
        // symmetric HS* alg if the issuer's JWKS ever exposed an "oct" key -- so
        // reject HS*/none on the header up front, mirroring the JWT forward-auth path.
        $this->assertAsymmetricAlg($idToken);
        // decode() enforces signature + exp/nbf/iat and rejects alg:none. The key
        // set carries each key's algorithm, so a JWKS public key can never be
        // abused as an HMAC secret (alg-confusion) -- we never pass a string key.
        try {
            $claims = JWT::decode($idToken, $this->jwks($disco, false));
        } catch (\UnexpectedValueException $e) {
            // An unknown "kid" means the IdP likely rotated keys: refetch the JWKS
            // once, bypassing the cache, and retry. Signature failures (a different
            // exception) are NOT retried.
            if (stripos($e->getMessage(), 'kid') === false) {
                throw $e;
            }
            $claims = JWT::decode($idToken, $this->jwks($disco, true));
        }

        if (!isset($claims->iss) || $claims->iss !== $disco['issuer']) {
            throw new \RuntimeException('OIDC: issuer mismatch');
        }
        $aud = (array)($claims->aud ?? []);
        if (!in_array($this->clientId, $aud, true)) {
            throw new \RuntimeException('OIDC: audience does not contain client_id');
        }
        // Per OIDC core: with multiple audiences, azp MUST be present and identify
        // this client. Without this a token minted for a different RP that merely
        // lists us in aud[] would be accepted.
        if (count($aud) > 1 && !isset($claims->azp)) {
            throw new \RuntimeException('OIDC: multi-audience token without azp');
        }
        if (isset($claims->azp) && $claims->azp !== $this->clientId) {
            throw new \RuntimeException('OIDC: azp does not match client_id');
        }
        if ($sessionNonce === '' || !hash_equals($sessionNonce, (string)($claims->nonce ?? ''))) {
            throw new \RuntimeException('OIDC: nonce mismatch (possible replay)');
        }
        // OIDC Core requires exp (and iat) on an ID token. decode() only enforces
        // exp WHEN present, so a token minted/replayed without exp would never
        // expire -- require both explicitly.
        if (!isset($claims->exp)) {
            throw new \RuntimeException('OIDC: ID token has no exp claim');
        }
        if (!isset($claims->iat)) {
            throw new \RuntimeException('OIDC: ID token has no iat claim');
        }

        return $claims;
    }

    /**
     * Reject a non-asymmetric (or "none") id_token signature by inspecting the JWS
     * header alg before verification. Everything the vendored lib supports other
     * than the HS family and "none" is asymmetric (RS, PS, ES, EdDSA), so an
     * HS-prefixed or "none" alg is the only thing to refuse here.
     */
    private function assertAsymmetricAlg(string $jwt): void
    {
        $dot = strpos($jwt, '.');
        $header = $dot === false ? null
            : json_decode((string)base64_decode(strtr(substr($jwt, 0, $dot), '-_', '+/')), true);
        $alg = is_array($header) ? (string)($header['alg'] ?? '') : '';
        if ($alg === '' || stripos($alg, 'HS') === 0 || strcasecmp($alg, 'none') === 0) {
            throw new \RuntimeException('OIDC: id_token must use an asymmetric signature (got ' . ($alg ?: 'none') . ')');
        }
    }

    private function discover(): array
    {
        if ($this->discovery !== null) {
            return $this->discovery;
        }
        $doc = $this->cacheGet('disco_' . $this->issuer, self::DISCO_TTL);
        if ($doc === null) {
            $doc = $this->httpGetJson($this->issuer . '/.well-known/openid-configuration');
            // issuer in the document is authoritative for later iss comparison.
            if (empty($doc['issuer']) || empty($doc['authorization_endpoint']) || empty($doc['token_endpoint'])) {
                throw new \RuntimeException('OIDC: discovery document is incomplete');
            }
            if (stripos($doc['issuer'], 'https://') !== 0) {
                throw new \RuntimeException('OIDC: discovered issuer is not https');
            }
            $this->cacheSet('disco_' . $this->issuer, $doc);
        }
        return $this->discovery = $doc;
    }

    /**
     * Parsed JWKS keyed by kid, cached on disk with a TTL. $force bypasses the
     * cache (used once on an unknown kid to pick up a key rotation).
     * @return \Firebase\JWT\Key[]
     */
    private function jwks(array $disco, bool $force): array
    {
        if (empty($disco['jwks_uri'])) {
            throw new \RuntimeException('OIDC: discovery has no jwks_uri');
        }
        $cacheKey = 'jwks_' . $disco['jwks_uri'];
        $raw = $force ? null : $this->cacheGet($cacheKey, self::JWKS_TTL);
        if ($raw === null) {
            $raw = $this->httpGetJson((string)$disco['jwks_uri']);
            $this->cacheSet($cacheKey, $raw);
        }
        return JWK::parseKeySet($raw);
    }

    /* ---- small on-disk cache for discovery + JWKS (TTL, www-owned) ----- */

    private function cacheGet(string $key, int $ttl): ?array
    {
        $f = self::CACHE_DIR . '/' . hash('sha256', $key) . '.json';
        if (!is_file($f) || (time() - (int)@filemtime($f)) > $ttl) {
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
        @chmod(self::CACHE_DIR, 0700); // reassert mode if the dir pre-existed
        $f = self::CACHE_DIR . '/' . hash('sha256', $key) . '.json';
        @file_put_contents($f, json_encode($data), LOCK_EX);
        @chmod($f, 0600);
    }

    private function exchangeCode(array $disco, string $code, string $verifier): array
    {
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
        ];
        if ($this->usePkce) {
            if ($verifier === '') {
                throw new \RuntimeException('OIDC: PKCE enabled but no code_verifier in session');
            }
            $body['code_verifier'] = $verifier;
        }

        // client_secret_basic
        $headers = [
            'Authorization: Basic ' . base64_encode(rawurlencode($this->clientId) . ':' . rawurlencode($this->clientSecret)),
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ];
        $resp = $this->httpPost((string)$disco['token_endpoint'], http_build_query($body), $headers);
        $json = json_decode($resp, true);
        if (!is_array($json) || isset($json['error'])) {
            throw new \RuntimeException('OIDC: token endpoint error: ' . ($json['error'] ?? 'invalid response'));
        }
        return $json;
    }

    private function fetchUserInfo(array $disco, string $accessToken): array
    {
        try {
            $resp = $this->httpGet((string)$disco['userinfo_endpoint'], [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/json',
            ]);
            $json = json_decode($resp, true);
            return is_array($json) ? $json : [];
        } catch (\Throwable $e) {
            return []; // userinfo is best-effort enrichment, not a gate
        }
    }

    private function toIdentity(array $claims): NormalizedIdentity
    {
        $id = new NormalizedIdentity('');
        $id->subject = self::scalarClaim($claims['sub'] ?? '');
        $id->username = self::scalarClaim($claims[$this->usernameClaim] ?? '');
        $id->email = self::scalarClaim($claims['email'] ?? '');
        $id->emailVerified = filter_var($claims['email_verified'] ?? false, FILTER_VALIDATE_BOOL);
        $id->displayName = self::scalarClaim($claims['name'] ?? '');
        $id->groups = $this->extractGroups($claims);
        $id->raw = $claims;
        return $id;
    }

    /**
     * An identity claim usable as a string: scalars only. A multi-valued (array)
     * or object claim returns '' instead of degrading to the literal "Array",
     * which would otherwise collide every such user onto one local account.
     */
    private static function scalarClaim($value): string
    {
        return is_scalar($value) ? (string)$value : '';
    }

    private function extractGroups(array $claims): array
    {
        $g = $claims[$this->groupsClaim] ?? [];
        if (is_string($g)) {
            $g = preg_split('/[,\s]+/', $g, -1, PREG_SPLIT_NO_EMPTY);
        }
        return array_values(array_filter(array_map('strval', (array)$g)));
    }

    /* ---- HTTP helpers: TLS verification always on, bounded, short ------ */

    private function httpGetJson(string $url): array
    {
        $json = json_decode($this->httpGet($url, ['Accept: application/json']), true);
        if (!is_array($json)) {
            throw new \RuntimeException('OIDC: expected JSON from ' . $url);
        }
        return $json;
    }

    private function httpGet(string $url, array $headers = []): string
    {
        return $this->curl($url, null, $headers);
    }

    private function httpPost(string $url, string $body, array $headers = []): string
    {
        return $this->curl($url, $body, $headers);
    }

    private function curl(string $url, ?string $postBody, array $headers): string
    {
        if (stripos($url, 'https://') !== 0) {
            throw new \RuntimeException('OIDC: refusing non-https endpoint ' . $url);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_TIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_BUFFERSIZE => 16384,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => function ($ch, $dlTotal, $dlNow) {
                return ($dlNow > self::MAX_BODY) ? 1 : 0; // abort oversized responses
            },
        ]);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($resp === false) {
            throw new \RuntimeException('OIDC: HTTP request failed: ' . $err);
        }
        if ($httpCode < 200 || $httpCode >= 300) {
            throw new \RuntimeException('OIDC: HTTP ' . $httpCode . ' from ' . $url);
        }
        return (string)$resp;
    }

    private function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    /**
     * Only allow same-host relative return paths -- defeats open redirect (CWE-601).
     * Rejects "//host" AND "/\host": browsers normalise "\" to "/", so "/\evil.com"
     * would resolve to a protocol-relative URL. Also strips CR/LF/TAB (header split).
     */
    private function sanitizeReturnUrl(string $url): string
    {
        if (
            $url === '' || $url[0] !== '/'
            || str_starts_with($url, '//') || str_starts_with($url, '/\\')
            || strpbrk($url, "\\\r\n\t") !== false
        ) {
            return '/';
        }
        return $url;
    }
}
