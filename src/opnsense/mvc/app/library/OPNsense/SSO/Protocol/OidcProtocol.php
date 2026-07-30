<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Protocol;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use OPNsense\SSO\ClaimPath;
use OPNsense\SSO\ClientAuth;
use OPNsense\SSO\ReturnUrl;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\StateDir;

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
    private const DISCO_TTL = 3600;       // discovery document cache TTL
    private const JWKS_TTL = 3600;        // JWKS cache TTL (refetched early on kid miss)
    private const LOGOUT_TOKEN_TTL = 300; // max age of a back-channel logout token

    private string $issuer;
    private string $clientId;
    private string $clientSecret;
    /** @var string[] */
    private array $scopes;
    private string $usernameClaim;
    private string $groupsClaim;
    private string $redirectUri;
    private bool $usePkce;
    /** force re-authentication when the IdP session is older than this (0 = off) */
    private int $maxAge;
    /** ask the IdP to POST the response back instead of putting it in the URL */
    private bool $formPost;
    /** @var string[] authentication context classes we require (empty = any) */
    private array $requiredAcr;
    /** @var array<string,string> extra authorization-request parameters */
    private array $extraParams;
    /** per-provider session-key prefix so concurrent flows do not clobber each other */
    private string $sessionPrefix;
    /** how this firewall proves it is the client when calling the token endpoint */
    private ClientAuth $clientAuth;
    /** follow an Entra ID group-overage claim to Microsoft Graph */
    private bool $graphOverage;
    /** push the authorization request to the IdP instead of sending it through the browser */
    private bool $usePar;

    /** @var array<string,mixed>|null cached discovery document */
    private ?array $discovery = null;

    /** @var string raw id_token from the last successful callback (for RP logout) */
    private string $lastIdToken = '';

    /** @var string state minted by the last startLogin() (correlation key for the flow) */
    private string $lastState = '';

    /** @var string `sid` of the last validated ID token (IdP session id, for back-channel logout) */
    private string $lastSid = '';

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
        $this->maxAge = max(0, (int)($cfg['max_age'] ?? 0));
        $this->formPost = (bool)($cfg['form_post'] ?? false);
        $this->requiredAcr = array_values(array_filter(array_map(
            'strval',
            (array)($cfg['required_acr'] ?? [])
        )));
        $this->extraParams = self::parseExtraParams((string)($cfg['extra_params'] ?? ''));
        $this->graphOverage = (bool)($cfg['graph_overage'] ?? false);
        $this->usePar = (bool)($cfg['use_par'] ?? false);
        $this->clientAuth = new ClientAuth([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'token_auth_method' => $cfg['token_auth_method'] ?? 'auto',
            'assertion_alg' => $cfg['assertion_alg'] ?? '',
            'private_key' => $cfg['private_key'] ?? '',
            'private_key_id' => $cfg['private_key_id'] ?? '',
            'tls_cert' => $cfg['tls_cert'] ?? '',
            'tls_key' => $cfg['tls_key'] ?? '',
        ]);
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
        $this->lastState = $state;
        $_SESSION[$this->skey('state')] = $state;
        $_SESSION[$this->skey('nonce')] = $nonce;
        $_SESSION[$this->skey('return')] = ReturnUrl::sanitize($returnUrl);

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
        if ($this->maxAge > 0) {
            // Ask the IdP to re-authenticate anyone whose session there is older than
            // this. The answer -- auth_time -- is checked back in validateIdToken.
            $params['max_age'] = (string)$this->maxAge;
        }
        if ($this->formPost) {
            // Keep the code out of the URL (browser history, Referer, proxy logs).
            $params['response_mode'] = 'form_post';
        }
        if (!empty($this->requiredAcr)) {
            // Ask for the context we are going to insist on in validateIdToken. Order is
            // the preference order per OIDC Core; the check accepts any of them.
            $params['acr_values'] = implode(' ', $this->requiredAcr);
        }
        // Operator extras (prompt, login_hint, ui_locales...). parseExtra
        // already dropped anything that would overwrite a parameter we depend on.
        $params += $this->extraParams;

        if ($this->usePar($disco)) {
            return $disco['authorization_endpoint'] . '?' . http_build_query([
                'client_id' => $this->clientId,
                'request_uri' => $this->pushAuthorizationRequest($disco, $params),
            ]);
        }
        return $disco['authorization_endpoint'] . '?' . http_build_query($params);
    }

    /**
     * Should this request be pushed to the IdP instead of sent through the browser?
     *
     * On when the operator asked, and on when the IdP says it will take nothing else.
     * Never on merely because the endpoint exists: PAR is an authenticated back-channel
     * call, so a misconfigured client secret would turn every login into a failure at a
     * point where the ordinary flow works fine.
     */
    private function usePar(array $disco): bool
    {
        if (empty($disco['pushed_authorization_request_endpoint'])) {
            return false;
        }
        return $this->usePar || !empty($disco['require_pushed_authorization_requests']);
    }

    /**
     * Push the authorization request and return the request_uri that stands for it
     * (RFC 9126).
     *
     * The parameters travel over an authenticated back channel instead of through the
     * user's browser, so what reaches the address bar is a client id and an opaque
     * reference. Nothing in between -- history, a Referer, a proxy log, a shoulder --
     * sees the redirect_uri, the scopes, the state or the PKCE challenge, and nothing
     * can alter them on the way: the IdP already has the request it will honour.
     */
    private function pushAuthorizationRequest(array $disco, array $params): string
    {
        $endpoint = (string)$disco['pushed_authorization_request_endpoint'];
        $response = $this->postToEndpoint($disco, $endpoint, $params);
        $requestUri = (string)($response['request_uri'] ?? '');
        // "urn:ietf:params:oauth:request_uri:<reference>" per the RFC; anything else is
        // not something to put in front of the user.
        if (stripos($requestUri, 'urn:') !== 0) {
            throw new \RuntimeException('OIDC: the pushed authorization request returned no usable request_uri');
        }
        return $requestUri;
    }

    /**
     * Parse the operator's "key=value, key=value" extras.
     *
     * Anything that carries the security of the flow -- the ones minted per login,
     * the client identity, the redirect target -- is refused: an extra parameter is a
     * convenience, never a way to rewrite the ceremony.
     *
     * @return array<string,string>
     */
    private static function parseExtraParams(string $spec): array
    {
        static $reserved = [
            'response_type', 'response_mode', 'client_id', 'redirect_uri', 'scope',
            'state', 'nonce', 'code_challenge', 'code_challenge_method', 'max_age',
            // acr_values belongs to the "Required authentication context" setting, which
            // also verifies the acr that comes back. Requesting one here and not
            // checking it is how you end up believing MFA is enforced when it is not.
            'acr_values',
        ];
        $out = [];
        foreach (preg_split('/[,\r\n]+/', $spec) ?: [] as $pair) {
            $parts = explode('=', trim($pair), 2);
            if (count($parts) !== 2) {
                continue;
            }
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            if ($key === '' || $value === '' || in_array(strtolower($key), $reserved, true)) {
                continue;
            }
            $out[$key] = $value;
        }
        return $out;
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

        $claims = $this->validateIdToken($disco, $idToken, $sessionNonce, (string)($tokens['access_token'] ?? ''));
        $this->lastIdToken = $idToken; // keep for RP-initiated logout (id_token_hint)
        // The IdP's own session id, when it publishes one: what a back-channel logout
        // names, and more precise than the subject (one user, several sessions).
        $this->lastSid = isset($claims->sid) && is_scalar($claims->sid) ? (string)$claims->sid : '';

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

        // Entra ID replaces the groups with a pointer past ~200 of them; follow it.
        $merged = $this->resolveGroupOverage($disco, $merged);

        return $this->toIdentity($merged);
    }

    /* ---- Entra ID group overage ---------------------------------------- */

    /** Microsoft's own Graph hosts, per national cloud. Nothing else is called. */
    private const GRAPH_HOSTS = [
        'graph.microsoft.com',
        'graph.microsoft.us',
        'dod-graph.microsoft.us',
        'graph.microsoft.de',
        'microsoftgraph.chinacloudapi.cn',
    ];

    /** Pages of getMemberObjects to follow (999 ids each). */
    private const MAX_OVERAGE_PAGES = 10;

    /**
     * Fill in the groups claim when the IdP sent a pointer instead of the groups.
     *
     * Entra ID stops emitting `groups` once a user is in more than roughly 200 of them
     * and substitutes `_claim_names` / `_claim_sources`, naming a Microsoft Graph
     * endpoint to ask instead. Nothing in the token says "this user has no groups" -- the
     * claim is simply absent -- so without following it the most heavily grouped users in
     * a tenant, typically the administrators, arrive with nothing and are refused by the
     * required-groups gate for a reason no log explains.
     *
     * Best-effort on purpose: a failure here leaves the claim absent, which means fewer
     * privileges and not more, and says so at WARNING level. Off unless the operator
     * enabled it, since it needs an application permission and admin consent at the
     * tenant.
     */
    private function resolveGroupOverage(array $disco, array $claims): array
    {
        if (!$this->graphOverage) {
            return $claims;
        }
        $endpoint = self::overageEndpoint($claims, $this->groupsClaim);
        if ($endpoint === '') {
            return $claims; // the ordinary case: the groups were in the token
        }
        try {
            $groups = $this->fetchOverageGroups($disco, $endpoint);
        } catch (\Throwable $e) {
            syslog(LOG_WARNING, 'os-sso oidc: cannot resolve the group overage claim: ' . $e->getMessage());
            return $claims;
        }
        syslog(LOG_NOTICE, sprintf(
            'os-sso oidc: resolved %d group(s) from the Entra overage claim',
            count($groups)
        ));
        $claims[$this->groupsClaim] = $groups;
        return $claims;
    }

    /**
     * The Graph endpoint an overage claim points at, '' when there is none.
     *
     * Pinned to Microsoft's own Graph hosts. The claim is carried by a token whose
     * signature we verified, so it is the IdP's word -- but this is where an app-only
     * access token with directory-read permission is about to be sent, and a
     * multi-tenant service is not the right thing to let choose that destination.
     */
    private static function overageEndpoint(array $claims, string $groupsClaim): string
    {
        $names = (array)($claims['_claim_names'] ?? []);
        $sources = (array)($claims['_claim_sources'] ?? []);
        if (empty($names) || empty($sources)) {
            return '';
        }
        // The configured claim name first, then Entra's own spelling.
        $key = '';
        foreach ([$groupsClaim, 'groups'] as $candidate) {
            if ($candidate !== '' && isset($names[$candidate]) && is_scalar($names[$candidate])) {
                $key = (string)$names[$candidate];
                break;
            }
        }
        if ($key === '' || !isset($sources[$key])) {
            return '';
        }
        $endpoint = (string)(((array)$sources[$key])['endpoint'] ?? '');
        $host = strtolower((string)(parse_url($endpoint, PHP_URL_HOST) ?? ''));
        if (stripos($endpoint, 'https://') !== 0 || !in_array($host, self::GRAPH_HOSTS, true)) {
            if ($endpoint !== '') {
                syslog(LOG_WARNING, sprintf(
                    'os-sso oidc: refusing an overage endpoint outside Microsoft Graph (%s)',
                    preg_replace('/[^\x20-\x7e]/', '', $endpoint)
                ));
            }
            return '';
        }
        return $endpoint;
    }

    /**
     * Ask Graph for the user's group memberships, as object ids.
     *
     * An app-only token, not the user's: the access token from the code exchange is
     * scoped to whatever resource the login asked for, which is not Graph, and cannot be
     * exchanged for one. So the client authenticates itself again -- with the same
     * method, secret, assertion or certificate as everything else -- and asks on its own
     * behalf. That needs the application permission GroupMember.Read.All (or
     * Directory.Read.All) with admin consent at the tenant.
     *
     * getMemberObjects returns ids, which is also what the non-overage `groups` claim
     * holds on Entra, so the group map stays written the same way either side of the
     * threshold.
     *
     * @return string[]
     */
    private function fetchOverageGroups(array $disco, string $endpoint): array
    {
        $host = strtolower((string)parse_url($endpoint, PHP_URL_HOST));
        $token = $this->tokenRequest($disco, [
            'grant_type' => 'client_credentials',
            'scope' => 'https://' . $host . '/.default',
        ]);
        $accessToken = (string)($token['access_token'] ?? '');
        if ($accessToken === '') {
            throw new \RuntimeException('the client-credentials grant returned no access token');
        }

        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json',
            'Accept: application/json',
        ];
        $groups = [];
        $url = $endpoint;
        for ($page = 0; $page < self::MAX_OVERAGE_PAGES && $url !== ''; $page++) {
            $json = json_decode($this->curl($url, '{"securityEnabledOnly":false}', $headers), true);
            if (!is_array($json)) {
                throw new \RuntimeException('Graph returned a response that is not JSON');
            }
            foreach ((array)($json['value'] ?? []) as $id) {
                if (is_scalar($id) && (string)$id !== '') {
                    $groups[] = (string)$id;
                }
            }
            $next = (string)($json['@odata.nextLink'] ?? '');
            // Paging must not walk off the host we pinned.
            $url = ($next !== '' && strcasecmp((string)(parse_url($next, PHP_URL_HOST) ?? ''), $host) === 0)
                ? $next
                : '';
        }
        if ($url !== '') {
            syslog(LOG_WARNING, sprintf(
                'os-sso oidc: stopped following the group overage after %d pages',
                self::MAX_OVERAGE_PAGES
            ));
        }
        return array_values(array_unique($groups));
    }

    public function consumeReturnUrl(): string
    {
        $url = $_SESSION[$this->skey('return')] ?? '/';
        unset($_SESSION[$this->skey('return')]);
        return ReturnUrl::sanitize((string)$url);
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

    /** The OIDC `state` minted by the last startLogin(); the controller keys its
     *  in-flight flow record by this so the callback can recover it by returned state. */
    public function getLastState(): string
    {
        return $this->lastState;
    }

    /** The configured issuer (the trust anchor a session is recorded against). */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /** The IdP session id (`sid`) of the last validated ID token, '' if it had none. */
    public function getLastSessionId(): string
    {
        return $this->lastSid;
    }

    /**
     * Live view of what the IdP publishes, for the diagnostics page: the discovery
     * document plus what we derive from it. Fetches for real (cache aside), so a
     * failure here is the same failure a login would hit.
     */
    public function describe(): array
    {
        $disco = $this->discover();
        return $disco + [
            'signing_keys' => count($this->jwks($disco, false)),
            'token_auth_method' => $this->tokenAuthMethod($disco),
        ];
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

    /**
     * Validate a back-channel logout token (OIDC Back-Channel Logout 1.0 section 2.6)
     * and return whose session it ends.
     *
     * This endpoint is unauthenticated by construction -- the IdP calls it server to
     * server, with no browser and no session -- so the token is the ONLY thing
     * standing between a stranger and "log everybody out". Every check below is a
     * requirement of that section, including the two negative ones: a logout token
     * must not carry a nonce (that would make an ID token usable here), and it must
     * carry the logout event (so a plain ID token, which has neither, is refused).
     *
     * @return array{sub:string,sid:string}
     */
    public function validateLogoutToken(string $jwt): array
    {
        $disco = $this->discover();
        $this->assertAsymmetricAlg($jwt);
        try {
            $claims = JWT::decode($jwt, $this->jwks($disco, false));
        } catch (\UnexpectedValueException $e) {
            if (stripos($e->getMessage(), 'kid') === false) {
                throw $e;
            }
            $claims = JWT::decode($jwt, $this->jwks($disco, true));
        }

        if (!isset($claims->iss) || $claims->iss !== $disco['issuer']) {
            throw new \RuntimeException('OIDC logout: issuer mismatch');
        }
        if (!in_array($this->clientId, (array)($claims->aud ?? []), true)) {
            throw new \RuntimeException('OIDC logout: audience does not contain client_id');
        }
        if (!isset($claims->iat) || (time() - (int)$claims->iat) > self::LOGOUT_TOKEN_TTL) {
            throw new \RuntimeException('OIDC logout: token is missing iat or too old');
        }
        if (isset($claims->nonce)) {
            throw new \RuntimeException('OIDC logout: a logout token must not carry a nonce');
        }
        $events = (array)($claims->events ?? []);
        if (!array_key_exists('http://schemas.openid.net/event/backchannel-logout', $events)) {
            throw new \RuntimeException('OIDC logout: token does not carry the backchannel-logout event');
        }
        $sub = isset($claims->sub) && is_scalar($claims->sub) ? (string)$claims->sub : '';
        $sid = isset($claims->sid) && is_scalar($claims->sid) ? (string)$claims->sid : '';
        if ($sub === '' && $sid === '') {
            throw new \RuntimeException('OIDC logout: token names neither sub nor sid');
        }
        $this->guardLogoutReplay(isset($claims->jti) && is_scalar($claims->jti) ? (string)$claims->jti : '');

        return ['sub' => $sub, 'sid' => $sid];
    }

    /** Accept each logout token's jti once, so a captured one cannot be re-fired. */
    private function guardLogoutReplay(string $jti): void
    {
        if ($jti === '') {
            return; // optional claim; the short iat window is what bounds it then
        }
        $dir = StateDir::path('oidc-logout');
        foreach (glob($dir . '/*.marker') ?: [] as $old) {
            if ((time() - (int)@filemtime($old)) > self::LOGOUT_TOKEN_TTL) {
                @unlink($old);
            }
        }
        $file = $dir . '/' . hash('sha256', $this->issuer . '|' . $jti) . '.marker';
        $fp = @fopen($file, 'x');
        if ($fp === false) {
            throw new \RuntimeException('OIDC logout: token replay detected');
        }
        fclose($fp);
        @chmod($file, 0600);
    }

    /* -------------------------------------------------------------------- */

    /**
     * ID token validation. firebase/php-jwt has already checked signature and
     * exp/nbf/iat by the time we read these. Everything below is OURS and each
     * line is load-bearing.
     *
     * @return object decoded, validated claims
     */
    private function validateIdToken(
        array $disco,
        string $idToken,
        string $sessionNonce,
        string $accessToken = ''
    ): object {
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
        // We asked for a recent authentication; check we got one. The IdP MUST return
        // auth_time when max_age was requested, so a missing claim is a failure, not
        // an excuse to accept a session of unknown age.
        if ($this->maxAge > 0) {
            if (!isset($claims->auth_time)) {
                throw new \RuntimeException('OIDC: max_age requested but the ID token has no auth_time');
            }
            if ((time() - (int)$claims->auth_time) > $this->maxAge + self::LEEWAY) {
                throw new \RuntimeException('OIDC: the IdP authentication is older than the configured max_age');
            }
        }
        // We asked the IdP for a particular authentication context; check we got it.
        $this->assertAcr($claims);
        // at_hash binds the ID token to the access token delivered with it. Without
        // it, an access token from another (attacker) session could be paired with a
        // genuine ID token and drive the userinfo enrichment below.
        $this->assertAtHash($idToken, $claims, $accessToken);

        return $claims;
    }

    /**
     * Enforce the configured authentication context class.
     *
     * Sending acr_values is a *voluntary* request per OIDC Core: an IdP that cannot, or
     * will not, honour it answers with an ordinary session and no error. So the request
     * on its own enforces nothing -- asking for an MFA context and never reading the
     * answer is exactly how an operator ends up believing MFA is required when it is
     * not. The returned acr is the only evidence there is, and a missing claim is a
     * failure rather than a reason to accept an authentication of unknown strength.
     *
     * acr is a single string per the spec, but IdPs have been seen returning a list;
     * accept either. The comparison is exact -- an acr is an identifier, not a level to
     * be ordered.
     */
    private function assertAcr(object $claims): void
    {
        if (empty($this->requiredAcr)) {
            return;
        }
        $got = [];
        foreach ((array)($claims->acr ?? []) as $value) {
            if (is_scalar($value)) {
                $got[] = (string)$value;
            }
        }
        foreach ($got as $value) {
            if (in_array($value, $this->requiredAcr, true)) {
                return;
            }
        }
        throw new \RuntimeException(sprintf(
            'OIDC: the ID token acr (%s) is none of the required values (%s)',
            $got !== [] ? implode(', ', $got) : 'absent',
            implode(', ', $this->requiredAcr)
        ));
    }

    /**
     * Verify at_hash when the ID token carries one: base64url of the left half of the
     * access token's hash, using the hash size of the token's own signing algorithm.
     */
    private function assertAtHash(string $idToken, object $claims, string $accessToken): void
    {
        if (!isset($claims->at_hash) || !is_string($claims->at_hash) || $accessToken === '') {
            return; // optional in the code flow; nothing to check against
        }
        $alg = self::jwsAlg($idToken);
        $bits = (int)substr($alg, -3);
        $hashAlg = in_array($bits, [384, 512], true) ? 'sha' . $bits : 'sha256';
        $digest = hash($hashAlg, $accessToken, true);
        $expected = rtrim(strtr(base64_encode(substr($digest, 0, intdiv(strlen($digest), 2))), '+/', '-_'), '=');
        if (!hash_equals($expected, $claims->at_hash)) {
            throw new \RuntimeException('OIDC: at_hash does not match the access token');
        }
    }

    /** The "alg" of a JWS header, '' when unreadable. */
    private static function jwsAlg(string $jwt): string
    {
        $dot = strpos($jwt, '.');
        $header = $dot === false ? null
            : json_decode((string)base64_decode(strtr(substr($jwt, 0, $dot), '-_', '+/')), true);
        return is_array($header) ? (string)($header['alg'] ?? '') : '';
    }

    /**
     * Reject a non-asymmetric (or "none") signature by inspecting the JWS header alg
     * before verification. Everything the vendored lib supports other than the HS family
     * and "none" is asymmetric (RS, PS, ES, EdDSA), so an HS-prefixed or "none" alg is
     * the only thing to refuse here.
     *
     * @param string $what which token this is, for the message the operator reads
     */
    private function assertAsymmetricAlg(string $jwt, string $what = 'id_token'): void
    {
        $alg = self::jwsAlg($jwt);
        if ($alg === '' || stripos($alg, 'HS') === 0 || strcasecmp($alg, 'none') === 0) {
            throw new \RuntimeException(
                'OIDC: ' . $what . ' must use an asymmetric signature (got ' . ($alg ?: 'none') . ')'
            );
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
            $this->assertIssuerMatches($doc);
            $this->cacheSet('disco_' . $this->issuer, $doc);
        }
        // Re-check on the cached path too: everything downstream (the iss claim
        // comparison) trusts this value, so it must never come back unverified.
        $this->assertIssuerMatches($doc);
        return $this->discovery = $doc;
    }

    /**
     * OIDC Discovery 1.0 section 4.3: the issuer in the document MUST equal the
     * issuer the well-known URL was built from. Without this the operator pins one
     * issuer and the ID token's `iss` is then compared against whatever the document
     * claimed -- so a multi-tenant IdP where a tenant controls its own metadata could
     * hand us a document naming a different issuer, and tokens minted for that other
     * issuer would validate.
     */
    private function assertIssuerMatches(array $doc): void
    {
        if (rtrim((string)($doc['issuer'] ?? ''), '/') !== $this->issuer) {
            throw new \RuntimeException('OIDC: discovery issuer does not match the configured issuer');
        }
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

    /**
     * Cache file path inside the vetted state directory. A cache we do not fully
     * control is worse than no cache (a writable JWKS cache is a signature bypass),
     * so StateDir throws rather than hand back a suspect directory.
     */
    private function cacheFile(string $key): string
    {
        return StateDir::path('oidc') . '/' . hash('sha256', $key) . '.json';
    }

    private function cacheGet(string $key, int $ttl): ?array
    {
        try {
            $f = $this->cacheFile($key);
        } catch (\RuntimeException $e) {
            return null; // no usable cache: fall through to a live fetch
        }
        if (!is_file($f) || (time() - (int)@filemtime($f)) > $ttl) {
            return null;
        }
        $data = json_decode((string)@file_get_contents($f), true);
        return is_array($data) ? $data : null;
    }

    private function cacheSet(string $key, array $data): void
    {
        try {
            $f = $this->cacheFile($key);
        } catch (\RuntimeException $e) {
            syslog(LOG_WARNING, 'os-sso oidc: cache disabled: ' . $e->getMessage());
            return;
        }
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
        return $this->tokenRequest($disco, $body);
    }

    /**
     * POST a grant to the token endpoint, authenticated as this client.
     *
     * Shared by the authorization-code exchange and by the client-credentials grant the
     * Entra group-overage lookup needs -- the client authentication is identical, and
     * having one place for it means a private_key_jwt or mTLS setup works for both
     * without being wired twice.
     */
    private function tokenRequest(array $disco, array $body): array
    {
        $method = $this->clientAuth->method($disco);
        $endpoint = $this->clientAuth->tokenEndpoint($disco, $method);
        if ($endpoint === '') {
            throw new \RuntimeException('OIDC: discovery has no usable token_endpoint');
        }
        return $this->postToEndpoint($disco, $endpoint, $body);
    }

    /**
     * POST a form to one of the IdP's authenticated endpoints, as this client.
     *
     * Shared by the token endpoint and the pushed-authorization one: both are called
     * from the firewall rather than through the browser, and both authenticate the
     * client exactly the same way, so a private_key_jwt or mTLS setup works for both
     * without being wired twice.
     */
    private function postToEndpoint(array $disco, string $endpoint, array $body): array
    {
        $headers = [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ];
        $curlOptions = [];
        $method = $this->clientAuth->method($disco);
        $this->clientAuth->apply($disco, $method, $body, $headers, $curlOptions);

        $resp = $this->curl($endpoint, http_build_query($body), $headers, $curlOptions);
        $json = json_decode($resp, true);
        if (!is_array($json) || isset($json['error'])) {
            throw new \RuntimeException('OIDC: ' . $endpoint . ' returned: ' . ($json['error'] ?? 'an invalid response'));
        }
        return $json;
    }

    /** The client authentication method in force against this IdP (for diagnostics). */
    private function tokenAuthMethod(array $disco): string
    {
        return $this->clientAuth->method($disco);
    }

    /**
     * Ask the userinfo endpoint for the claims the ID token did not carry.
     *
     * Best-effort enrichment, not a gate -- but a SILENT best effort is how an IdP
     * configured for a signed userinfo response (userinfo_signed_response_alg, a JWT
     * rather than JSON) made groups and email vanish with nothing to read anywhere, and
     * with required groups configured that is a refusal nobody can explain. So a
     * response we cannot use says so, and a signed one is simply verified and used.
     */
    private function fetchUserInfo(array $disco, string $accessToken): array
    {
        try {
            $resp = $this->httpGet((string)$disco['userinfo_endpoint'], [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/json, application/jwt',
            ]);
        } catch (\Throwable $e) {
            syslog(LOG_WARNING, 'os-sso oidc: the userinfo request failed: ' . $e->getMessage());
            return [];
        }
        $json = json_decode($resp, true);
        if (is_array($json)) {
            return $json;
        }
        try {
            return $this->decodeSignedUserInfo($disco, trim($resp));
        } catch (\Throwable $e) {
            syslog(LOG_WARNING, 'os-sso oidc: unusable userinfo response: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * A signed userinfo response (OIDC Core section 5.3.2): a JWT, not a JSON object.
     *
     * Verified exactly like an ID token -- same key set, same refusal of a symmetric or
     * absent algorithm -- because it is about to override authorization claims. `iss` and
     * `aud` are optional on this one per the spec, so they are checked when present rather
     * than required; the `sub` equality the caller enforces is what actually binds the
     * response to the token that asked for it.
     *
     * An encrypted response (JWE, five segments) lands here too and is refused by the
     * segment count, which is the intended answer: os-sso holds no decryption key.
     */
    private function decodeSignedUserInfo(array $disco, string $jwt): array
    {
        if ($jwt === '' || substr_count($jwt, '.') !== 2) {
            throw new \RuntimeException('the response is neither JSON nor a signed JWT');
        }
        $this->assertAsymmetricAlg($jwt, 'userinfo response');
        try {
            $claims = JWT::decode($jwt, $this->jwks($disco, false));
        } catch (\UnexpectedValueException $e) {
            if (stripos($e->getMessage(), 'kid') === false) {
                throw $e;
            }
            $claims = JWT::decode($jwt, $this->jwks($disco, true));
        }
        if (isset($claims->iss) && $claims->iss !== $disco['issuer']) {
            throw new \RuntimeException('signed userinfo: issuer mismatch');
        }
        if (isset($claims->aud) && !in_array($this->clientId, (array)$claims->aud, true)) {
            throw new \RuntimeException('signed userinfo: audience does not contain client_id');
        }
        return (array)$claims;
    }

    private function toIdentity(array $claims): NormalizedIdentity
    {
        $id = new NormalizedIdentity('');
        $id->subject = self::scalarClaim($claims['sub'] ?? '');
        $id->username = self::scalarClaim(ClaimPath::get($claims, $this->usernameClaim));
        $id->email = self::scalarClaim($claims['email'] ?? '');
        $id->emailVerified = filter_var($claims['email_verified'] ?? false, FILTER_VALIDATE_BOOL);
        $id->displayName = self::scalarClaim($claims['name'] ?? '');
        $id->groups = ClaimPath::groups($claims, $this->groupsClaim);
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

    /**
     * @param array $extraOptions curl options from the client authentication (the mTLS
     *                            certificate pair), applied after ours
     */
    private function curl(string $url, ?string $postBody, array $headers, array $extraOptions = []): string
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
        if (!empty($extraOptions)) {
            curl_setopt_array($ch, $extraOptions);
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

}
