<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\SessionEstablisher;
use OPNsense\SSO\VpnAuthorizer;
use OPNsense\SSO\CaptivePortalAuthorizer;
use OPNsense\SSO\FaviconProxy;
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
            $cpurl = $cp !== '' ? (string)($this->request->get('cpurl') ?? '') : '';

            // Record this in-flight login keyed by its OIDC state. Keying by state
            // (not a single shared session key) means two concurrent logins to
            // different providers in one browser no longer clobber each other's
            // provider / vpn / cp -- the callback recovers the right one by the
            // state it gets back. The per-provider state/nonce/verifier the protocol
            // stores are already namespaced; this closes the last shared keys.
            $_SESSION['sso_oidc_flows'][$protocol->getLastState()] = [
                'provider' => (string)$provider,
                'vpn' => $vpn,
                'cp' => $cp,
                'cpurl' => $cpurl,
            ];
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        session_write_close();
        $this->response->redirect($url, true);
        return 'Redirecting to identity provider...';
    }

    /** GET /api/sso/oidc/callback */
    public function callbackAction()
    {
        if ($this->session->get('Username') !== null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        $this->startSession();
        try {
            // Recover this login's in-flight record by the state the IdP echoes back
            // (single use). Trust the provider recorded at startLogin over any query
            // param, so a crafted callback URL cannot steer which provider validates.
            $state = (string)($_GET['state'] ?? '');
            $flow = $_SESSION['sso_oidc_flows'][$state] ?? null;
            if (is_array($flow)) {
                unset($_SESSION['sso_oidc_flows'][$state]);
            }
            $provider = is_array($flow) && $flow['provider'] !== ''
                ? (string)$flow['provider']
                : $this->request->get('provider');
            $auth = $this->authServer($provider);
            $protocol = $this->protocolFor($provider, $auth);

            $identity = $protocol->handleCallback($_GET);
            $identity->authServer = (string)$provider;

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

            $mapper = new IdentityMapper(new GroupMapper(GroupMapper::parseMap((string)$auth->ssoGroupMap)));
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

            (new SessionEstablisher())->establish($username, (string)$provider);
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

    /** GET /api/sso/oidc/logout -- RP-initiated Single Logout. */
    public function logoutAction()
    {
        $this->startSession();
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

    /** Configured Base URL override for this provider, else auto-detect from Host. */
    private function baseUrlFor($auth): string
    {
        $configured = trim((string)($auth->ssoBaseUrl ?? ''));
        if ($configured !== '' && stripos($configured, 'https://') === 0) {
            return rtrim($configured, '/');
        }
        return $this->baseUrl();
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
        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000, '/', '', true, true);
        }
        @session_destroy();
    }

    private function baseUrl(): string
    {
        // OPNsense\Mvc\Request lacks Phalcon's getHttpHost(); read $_SERVER.
        // Host is client-controlled: accept only a well-formed host[:port], else fall
        // back to the server name (defeats Host-header injection into built URLs).
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        if (!preg_match('/^[A-Za-z0-9.\-]+(:\d{1,5})?$/', (string)$host)) {
            $host = $_SERVER['SERVER_NAME'] ?? 'localhost';
        }
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        return ($https ? 'https' : 'http') . '://' . $host;
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
