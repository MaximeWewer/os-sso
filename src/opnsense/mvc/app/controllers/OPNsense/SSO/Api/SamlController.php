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
use OPNsense\SSO\Protocol\SamlProtocol;

/**
 * SAML SP endpoints: login (AuthnRequest), acs (assertion consumer), metadata.
 * Pre-auth via doAuth()=>true; security rests on signature + InResponseTo replay
 * protection inside SamlProtocol. Phase 4.
 */
class SamlController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    /**
     * The SAML endpoints are intentionally pre-auth AND CSRF-exempt. The ACS is a
     * cross-site HTTP-POST from the IdP that cannot carry the WebGUI CSRF token;
     * its integrity is guaranteed instead by the assertion's XML-DSig signature
     * and the single-use InResponseTo check in SamlProtocol. Bypass the base
     * auth/CSRF gate (which would 403 the IdP POST) for this controller.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        return true;
    }

    /** GET /api/sso/saml/login?provider=<name> */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        // No session needed here: SamlProtocol persists in-flight state server-side
        // keyed by the AuthnRequest id (the assertion POST is cross-site, so the
        // SameSite=Lax session cookie would not survive the round-trip anyway).
        try {
            $provider = $this->request->get('provider');
            $protocol = $this->protocolFor($provider);
            // OpenVPN deferred web-auth: carry the one-time VPN session id in the
            // server-side state so the ACS can authorize the tunnel. Captive Portal:
            // carry the zone id + the client's original destination likewise.
            $vpn = (string)$this->request->get('vpn');
            $cp = (string)($this->request->get('cp') ?? '');
            $cpurl = (string)($this->request->get('cpurl') ?? '');
            $url = $protocol->startLogin((string)($this->request->get('url') ?? '/'), $vpn, $cp, $cpurl);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        $this->response->redirect($url, true);
        return 'Redirecting to identity provider...';
    }

    /** POST /api/sso/saml/acs */
    public function acsAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        try {
            // Recover in-flight state via the response InResponseTo (single use).
            $inResponseTo = SamlProtocol::peekInResponseTo($_POST);
            $state = SamlProtocol::consumeState($inResponseTo);
            if ($state === null) {
                throw new \RuntimeException('unknown or replayed SAML response');
            }
            $provider = $state['provider'];
            $auth = $this->authServer($provider);
            $protocol = $this->protocolFor($provider, $auth);

            $identity = $protocol->handleCallback($_POST, $inResponseTo, $state);
            $identity->authServer = (string)$provider;

            // Captive Portal path: authorize the captive client's IP in its zone
            // straight from the verified assertion (no local account, no WebGUI
            // session), before any identity mapping.
            $cp = (string)($state['cp'] ?? '');
            if ($cp !== '') {
                $cpRes = CaptivePortalAuthorizer::authorize(
                    $cp,
                    (string)$provider,
                    $identity,
                    (string)($_SERVER['REMOTE_ADDR'] ?? '')
                );
                $this->response->setContentType('text/html', 'UTF-8');
                return CaptivePortalAuthorizer::donePage($cpRes['username'], (string)($state['cpurl'] ?? ''));
            }

            $username = (new IdentityMapper(new GroupMapper()))->resolve(
                $identity,
                (bool)$auth->ssoCreateUsers,
                (array)$auth->ssoDefaultGroups
            );

            // OpenVPN deferred web-auth path: authorize the tunnel, no WebGUI session.
            $vpn = (string)($state['vpn'] ?? '');
            if ($vpn !== '') {
                VpnAuthorizer::authorize($vpn, $username, (string)($_SERVER['REMOTE_ADDR'] ?? ''));
                $this->response->setContentType('text/html', 'UTF-8');
                return VpnAuthorizer::donePage($username);
            }

            $this->startSession();
            (new SessionEstablisher())->establish($username, (string)$provider);
            // Keep what Single Logout needs, in the fresh session.
            $_SESSION['sso_logout'] = [
                'type' => 'saml',
                'provider' => (string)$provider,
                'nameid' => $protocol->getLastNameId(),
                'sessionindex' => $protocol->getLastSessionIndex(),
                'nameid_format' => $protocol->getLastNameIdFormat(),
            ];
            session_write_close();
            $returnUrl = $this->landing($this->sanitizeReturn($state['return'] ?? '/'), $auth);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        $this->response->redirect($returnUrl, true);
        return 'Login successful, redirecting...';
    }

    /** GET /api/sso/saml/icon?provider=<name> -- proxied IdP favicon. */
    public function iconAction()
    {
        try {
            $auth = $this->authServer($this->request->get('provider'));
            $icon = FaviconProxy::fetch((string)($auth->ssoIdpSsoUrl ?: $auth->ssoIdpEntityId));
        } catch (\Throwable $e) {
            $this->response->setStatusCode(404, 'Not Found');
            return '';
        }
        $this->response->setHeader('Content-Type', $icon['type']);
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
        return $icon['data'];
    }

    /** GET /api/sso/saml/metadata?provider=<name> */
    public function metadataAction()
    {
        try {
            $protocol = $this->protocolFor($this->request->get('provider'));
            $this->response->setHeader('Content-Type', 'application/samlmetadata+xml');
            return $protocol->metadata();
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
    }

    /**
     * GET /api/sso/saml/slo -- Single Logout.
     *   - no SAML param  : SP-initiated (build LogoutRequest, redirect to IdP)
     *   - SAMLResponse   : the IdP's answer to our LogoutRequest (validate, finish)
     *   - SAMLRequest    : IdP-initiated logout (process, answer with LogoutResponse)
     */
    public function sloAction()
    {
        $this->startSession();

        // Incoming SLO message (response to ours, or IdP-initiated request).
        if (!empty($_GET['SAMLResponse']) || !empty($_GET['SAMLRequest'])) {
            $redirect = '/';
            try {
                // Prefer the provider whose IdP EntityID matches the message Issuer
                // (correct for IdP-initiated SLO with several SAML providers); fall
                // back to the session, then the first configured SAML provider.
                $provider = $this->samlProviderByIssuer(SamlProtocol::peekSloIssuer($_GET))
                    ?: (($_SESSION['sso_logout']['provider'] ?? '') ?: $this->firstSamlProvider());
                $protocol = $this->protocolFor($provider);
                $reqId = (string)($_SESSION['sso_saml_logout_reqid'] ?? '');
                $redirect = $protocol->processSlo($reqId) ?: '/';
            } catch (\Throwable $e) {
                return $this->fail($e);
            }
            $this->clearSession();
            $this->response->redirect($redirect, true);
            return 'Logged out.';
        }

        // SP-initiated logout.
        $logout = $_SESSION['sso_logout'] ?? null;
        $url = '';
        try {
            if (is_array($logout) && ($logout['type'] ?? '') === 'saml' && !empty($logout['provider'])) {
                $auth = $this->authServer($logout['provider']);
                $protocol = $this->protocolFor($logout['provider'], $auth);
                $r = $protocol->buildLogoutRequest(
                    $this->baseUrlFor($auth) . '/',
                    (string)($logout['nameid'] ?? ''),
                    (string)($logout['sessionindex'] ?? ''),
                    (string)($logout['nameid_format'] ?? '')
                );
                $url = $r['url'];
                if ($url !== '') {
                    // Keep the request id + session for the round-trip, but drop the
                    // local login now.
                    $_SESSION['sso_saml_logout_reqid'] = $r['request_id'];
                    unset($_SESSION['Username']);
                    session_write_close();
                    $this->response->redirect($url, true);
                    return 'Logging out...';
                }
            }
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        // No IdP SLO configured: local logout only.
        $this->clearSession();
        $this->response->redirect('/', true);
        return 'Logged out.';
    }

    /* ------------------------------------------------------------------ */

    /** Local WebGUI logout: wipe + destroy the session (mirrors the core logout). */
    private function clearSession(): void
    {
        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000, '/', '', true, true);
        }
        @session_destroy();
    }

    /** First configured SAML auth server name (for IdP-initiated SLO without a session). */
    private function firstSamlProvider(): string
    {
        foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver as $as) {
            if ((string)$as->type === 'saml') {
                return (string)$as->name;
            }
        }
        throw new \RuntimeException('no SAML provider configured');
    }

    /** SAML auth server whose IdP EntityID matches $issuer, or '' if none. */
    private function samlProviderByIssuer(string $issuer): string
    {
        if ($issuer === '') {
            return '';
        }
        foreach (\OPNsense\Core\Config::getInstance()->object()->system->authserver as $as) {
            if ((string)$as->type === 'saml' && (string)$as->sso_idp_entity_id === $issuer) {
                return (string)$as->name;
            }
        }
        return '';
    }

    private function protocolFor($provider, $auth = null): SamlProtocol
    {
        $auth = $auth ?? $this->authServer($provider);
        $base = $this->baseUrlFor($auth);
        return new SamlProtocol([
            'provider_name' => (string)$provider,
            'base_url' => $base,
            'sp_entity_id' => $base . '/api/sso/saml/metadata',
            'acs_url' => $base . '/api/sso/saml/acs',
            'idp_entity_id' => $auth->ssoIdpEntityId,
            'idp_sso_url' => $auth->ssoIdpSsoUrl,
            // Default the SLO endpoint to the SSO URL (Keycloak/Authentik serve both
            // at /protocol/saml) when the operator left it empty.
            'idp_slo_url' => $auth->ssoIdpSloUrl ?: $auth->ssoIdpSsoUrl,
            'idp_x509' => $auth->ssoIdpX509,
            'sp_cert' => $auth->ssoSpCert,
            'sp_key' => $auth->ssoSpKey,
            'name_id_format' => $auth->ssoNameIdFormat,
            'groups_attribute' => $auth->ssoGroupsAttribute,
            'want_messages_signed' => (bool)$auth->ssoWantMessagesSigned,
        ]);
    }

    private function authServer($provider)
    {
        if (empty($provider)) {
            throw new \RuntimeException('missing provider');
        }
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth === null || $auth->getType() !== 'saml') {
            throw new \RuntimeException('unknown SAML provider');
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

    /** Same-host relative path only (open redirect / CWE-601). Rejects "//host",
     *  "/\host" (browsers fold "\"->"/") and CR/LF/TAB (header split). */
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
        syslog(LOG_ERR, 'os-sso saml: ' . $e->getMessage());
        $this->response->setStatusCode(400, 'Bad Request');
        return 'SSO login failed. See the firewall system log for details.';
    }
}
