<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\SSO\AccessPolicy;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\SessionEstablisher;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\VpnAuthorizer;
use OPNsense\SSO\CaptivePortalAuthorizer;
use OPNsense\SSO\FaviconProxy;
use OPNsense\SSO\LogoutGuard;
use OPNsense\SSO\SiteUrl;
use OPNsense\SSO\Protocol\OidcProtocol;

/**
 * OIDC browser flow endpoints. Pre-auth: doAuth() returns true so the IdP can
 * reach login/callback without an existing session. Security here
 * rests on the in-session anti-replay material (state/nonce/PKCE), not on the
 * usual CSRF token.
 */
class OidcController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    /**
     * Pre-auth AND CSRF-exempt, like the SAML controller. With response_mode=form_post
     * the IdP delivers the callback as a cross-site HTTP-POST that cannot carry the
     * WebGUI CSRF token; the base gate would 403 it. What protects this flow is not a
     * CSRF token but the single-use state/nonce/PKCE material minted at login.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        return true;
    }

    /** GET /api/sso/oidc/login?provider=<name> */
    public function loginAction()
    {
        if ($this->session->get('Username') !== null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        // OPNsense\Mvc\Session snapshots then aborts the native session, so raw
        // $_SESSION writes are dropped. Reopen the native session ourselves so the
        // protocol's anti-replay state (state/nonce/PKCE verifier) actually persists.
        $this->startSession();
        try {
            $provider = $this->request->get('provider');
            $protocol = $this->protocolFor($provider);
            $returnUrl = (string)($this->request->get('url') ?? '/');
            $url = $protocol->startLogin($returnUrl);

            // OpenVPN deferred web-auth: the one-time VPN session id, and Captive
            // Portal deferred login: the zone id + the client's original destination.
            // Both ride through the OIDC ceremony so the callback can authorize the
            // tunnel / captive client instead of opening a WebGUI session.
            $vpn = preg_replace('/[^a-f0-9]/', '', (string)$this->request->get('vpn'));
            $cp = preg_replace('/[^0-9]/', '', (string)$this->request->get('cp'));
            // Validated here, at the door: the portal page filters it too, but a
            // crafted login link never goes through the portal page.
            $cpurl = $cp !== ''
                ? CaptivePortalAuthorizer::sanitizeRedirect((string)($this->request->get('cpurl') ?? ''))
                : '';

            // Record this in-flight login keyed by its OIDC state. Keying by state
            // (not a single shared session key) means two concurrent logins to
            // different providers in one browser no longer clobber each other's
            // provider / vpn / cp -- the callback recovers the right one by the
            // state it gets back. The per-provider state/nonce/verifier the protocol
            // stores are already namespaced; this closes the last shared keys.
            $this->recordFlow($protocol->getLastState(), [
                'provider' => (string)$provider,
                'vpn' => $vpn,
                'cp' => $cp,
                'cpurl' => $cpurl,
            ]);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        session_write_close();
        $this->response->redirect($url, true);
        return 'Redirecting to identity provider...';
    }

    /** GET|POST /api/sso/oidc/callback (POST with response_mode=form_post) */
    public function callbackAction()
    {
        if ($this->session->get('Username') !== null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        $this->startSession();
        // form_post delivers the same parameters in the body instead of the query.
        $response = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && !empty($_POST) ? $_POST : $_GET;
        try {
            // Recover this login's in-flight record by the state the IdP echoes back
            // (single use). Trust the provider recorded at startLogin over any query
            // param, so a crafted callback URL cannot steer which provider validates.
            $state = (string)($response['state'] ?? '');
            $flow = $this->consumeFlow($state);
            $provider = is_array($flow) && $flow['provider'] !== ''
                ? (string)$flow['provider']
                : $this->request->get('provider');
            $auth = $this->authServer($provider);
            $protocol = $this->protocolFor($provider, $auth);

            $identity = $protocol->handleCallback($response);
            $identity->authServer = (string)$provider;

            // Provider-level door policy, before ANY path below (captive portal, VPN
            // or WebGUI) and before any local account is touched or created.
            AccessPolicy::assert((array)$auth->ssoRequiredGroups, $identity, (bool)$auth->ssoDeprovision);

            // Captive Portal path: authorize the captive client's IP in its zone. No
            // local account and no WebGUI session -- evaluated straight from the
            // verified identity (and the zone's group policy) before any mapping.
            $cp = is_array($flow) ? (string)($flow['cp'] ?? '') : '';
            $cpurl = is_array($flow) ? (string)($flow['cpurl'] ?? '') : '';
            if ($cp !== '') {
                $cpRes = CaptivePortalAuthorizer::authorize(
                    $cp,
                    (string)$provider,
                    $identity,
                    (string)($_SERVER['REMOTE_ADDR'] ?? '')
                );
                session_write_close();
                $this->response->setContentType('text/html', 'UTF-8');
                return CaptivePortalAuthorizer::donePage($cpRes['username'], $cpurl);
            }

            $mapper = new IdentityMapper(new GroupMapper(
                GroupMapper::parseMap((string)$auth->ssoGroupMap),
                (bool)$auth->ssoGroupSync
            ));
            $username = $mapper->resolve(
                $identity,
                (bool)$auth->ssoCreateUsers,
                (array)$auth->ssoDefaultGroups
            );

            // OpenVPN deferred web-auth path: authorize the tunnel, do NOT open a
            // WebGUI admin session (different security context).
            $vpn = is_array($flow) ? (string)($flow['vpn'] ?? '') : '';
            if ($vpn !== '') {
                VpnAuthorizer::authorize($vpn, $username, (string)($_SERVER['REMOTE_ADDR'] ?? ''));
                session_write_close();
                $this->response->setContentType('text/html', 'UTF-8');
                return VpnAuthorizer::donePage($username);
            }

            (new SessionEstablisher())->establish($username, (string)$provider, [
                'issuer' => $protocol->getIssuer(),
                'sub' => $identity->subject,
                'sid' => $protocol->getLastSessionId(),
                'lifetime' => (int)$auth->ssoSessionLifetime,
            ]);
            // Keep what RP-initiated logout (SLO) needs, in the fresh session.
            $_SESSION['sso_logout'] = [
                'type' => 'oidc',
                'provider' => (string)$provider,
                'id_token' => $protocol->getLastIdToken(),
            ];
            $returnUrl = $this->landing($protocol->consumeReturnUrl(), $auth);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        session_write_close();
        $this->response->redirect($returnUrl, true);
        return 'Login successful, redirecting...';
    }

    /** GET /api/sso/oidc/icon?provider=<name> -- proxied IdP favicon. */
    public function iconAction()
    {
        try {
            $auth = $this->authServer($this->request->get('provider'));
            $icon = FaviconProxy::fetch((string)$auth->ssoIssuer);
        } catch (\Throwable $e) {
            $this->response->setStatusCode(404, 'Not Found');
            return '';
        }
        $this->response->setHeader('Content-Type', $icon['type']);
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
        return $icon['data'];
    }

    /**
     * POST /api/sso/oidc/backchannel?provider=<name> -- OIDC Back-Channel Logout.
     *
     * The IdP calls this server-to-server when a session ends on its side, so that a
     * user disabled (or logged out) there does not keep an open WebGUI session here
     * until it idles out. No browser, no cookie: the signed logout_token is the whole
     * of the authentication, and it is validated in full before anything is ended.
     */
    public function backchannelAction()
    {
        // Section 2.8: never cache, and answer 200 with no body on success.
        $this->response->setHeader('Cache-Control', 'no-store');
        try {
            $provider = $this->request->get('provider');
            $auth = $this->authServer($provider);
            $protocol = $this->protocolFor($provider, $auth);
            $token = (string)($_POST['logout_token'] ?? '');
            if ($token === '') {
                throw new \RuntimeException('no logout_token in the request');
            }
            $subject = $protocol->validateLogoutToken($token);
            $ended = SessionRegistry::destroyForSubject(
                $protocol->getIssuer(),
                $subject['sub'],
                $subject['sid']
            );
            syslog(LOG_NOTICE, sprintf(
                'os-sso oidc: back-channel logout from %s ended %d session(s)',
                (string)$provider,
                $ended
            ));
        } catch (\Throwable $e) {
            syslog(LOG_ERR, 'os-sso oidc backchannel: ' . $e->getMessage());
            $this->response->setStatusCode(400, 'Bad Request');
            return '';
        }
        $this->response->setStatusCode(200, 'OK');
        return '';
    }

    /** GET /api/sso/oidc/logout -- RP-initiated Single Logout. */
    public function logoutAction()
    {
        $this->startSession();
        // A third-party page must not be able to end the session for the user.
        if (!LogoutGuard::allow()) {
            $page = LogoutGuard::confirm('/api/sso/logout');
            session_write_close();
            $this->response->setContentType('text/html', 'UTF-8');
            return $page;
        }
        $logout = $_SESSION['sso_logout'] ?? null;

        $url = '';
        try {
            if (is_array($logout) && ($logout['type'] ?? '') === 'oidc' && !empty($logout['provider'])) {
                $auth = $this->authServer($logout['provider']);
                $protocol = $this->protocolFor($logout['provider'], $auth);
                $url = $protocol->buildLogoutUrl(
                    (string)($logout['id_token'] ?? ''),
                    $this->baseUrlFor($auth) . '/'
                );
            }
        } catch (\Throwable $e) {
            syslog(LOG_ERR, 'os-sso oidc logout: ' . $e->getMessage());
        }

        $this->clearSession();
        $this->response->redirect($url !== '' ? $url : '/', true);
        return 'Logging out...';
    }

    /* ------------------------------------------------------------------ */

    /** How long an unfinished login stays recoverable, and how many may pile up. */
    private const FLOW_TTL = 600;
    private const FLOW_MAX = 5;

    /**
     * Remember an in-flight login, keyed by its OIDC state.
     *
     * Bounded on purpose: /login is pre-auth, so anyone holding a session cookie can
     * start arbitrarily many ceremonies and each used to leave a record behind for
     * good. Expired entries go on every write and only the newest FLOW_MAX survive,
     * which is well past any real "several tabs at once" case.
     */
    private function recordFlow(string $state, array $flow): void
    {
        $flows = is_array($_SESSION['sso_oidc_flows'] ?? null) ? $_SESSION['sso_oidc_flows'] : [];
        $now = time();
        foreach ($flows as $key => $known) {
            if (!is_array($known) || ($now - (int)($known['ts'] ?? 0)) > self::FLOW_TTL) {
                unset($flows[$key]);
            }
        }
        $flow['ts'] = $now;
        $flows[$state] = $flow;
        if (count($flows) > self::FLOW_MAX) {
            $flows = array_slice($flows, -self::FLOW_MAX, null, true);
        }
        $_SESSION['sso_oidc_flows'] = $flows;
    }

    /** Single-use lookup of an in-flight login; null when unknown or expired. */
    private function consumeFlow(string $state): ?array
    {
        $flow = $_SESSION['sso_oidc_flows'][$state] ?? null;
        if (!is_array($flow)) {
            return null;
        }
        unset($_SESSION['sso_oidc_flows'][$state]);
        return (time() - (int)($flow['ts'] ?? 0)) > self::FLOW_TTL ? null : $flow;
    }

    private function protocolFor($provider, $auth = null): OidcProtocol
    {
        $auth = $auth ?? $this->authServer($provider);
        return new OidcProtocol([
            'provider' => (string)$provider,
            'issuer' => $auth->ssoIssuer,
            'client_id' => $auth->ssoClientId,
            'client_secret' => $auth->ssoClientSecret,
            'scopes' => $auth->ssoScopes,
            'username_claim' => $auth->ssoUsernameClaim,
            'groups_claim' => $auth->ssoGroupsClaim,
            'use_pkce' => $auth->ssoUsePkce,
            'max_age' => $auth->ssoMaxAge,
            'form_post' => $auth->ssoFormPost,
            'extra_params' => $auth->ssoExtraParams,
            'redirect_uri' => $this->baseUrlFor($auth) . '/api/sso/oidc/callback',
        ]);
    }

    /**
     * Post-login landing path: an explicit originally-requested page wins; otherwise
     * use the provider's configured default landing (same-site only), else '/'.
     */
    private function landing(string $returnUrl, $auth): string
    {
        if ($returnUrl !== '' && $returnUrl !== '/') {
            return $returnUrl;
        }
        return $this->sanitizeReturn(trim((string)($auth->ssoLoginRedirect ?? '')));
    }

    /** Same-host relative path only (open redirect / CWE-601). */
    private function sanitizeReturn(string $url): string
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

    /** Configured Base URL override for this provider, else a vetted auto-detect. */
    private function baseUrlFor($auth): string
    {
        return SiteUrl::forProvider($auth);
    }

    private function authServer($provider)
    {
        if (empty($provider)) {
            throw new \RuntimeException('missing provider');
        }
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth === null || $auth->getType() !== 'oidc') {
            throw new \RuntimeException('unknown OIDC provider');
        }
        return $auth;
    }

    /** Reopen the native PHP session (the Mvc wrapper aborts it at dispatch). */
    private function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    /** Local WebGUI logout: wipe + destroy the session (mirrors the core logout). */
    private function clearSession(): void
    {
        SessionRegistry::forget((string)session_id());
        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000, '/', '', true, true);
        }
        @session_destroy();
    }

    private function fail(\Throwable $e): string
    {
        // Detail goes to the log only; the unauthenticated caller gets a generic
        // message (avoid reflecting internal error text).
        syslog(LOG_ERR, 'os-sso oidc: ' . $e->getMessage());
        $this->response->setStatusCode(400, 'Bad Request');
        return 'SSO login failed. See the firewall system log for details.';
    }
}
