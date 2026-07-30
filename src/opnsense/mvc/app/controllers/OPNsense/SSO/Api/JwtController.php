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
use OPNsense\SSO\RateLimiter;
use OPNsense\SSO\ReturnUrl;
use OPNsense\SSO\SourceGate;
use OPNsense\SSO\FaviconProxy;
use OPNsense\SSO\Protocol\JwtProtocol;

/**
 * JWT forward-auth endpoint. A trusted upstream proxy authenticates the user and
 * forwards a signed JWT in a header; this turns it into a WebGUI session.
 *
 * The single thing that makes header-auth safe is the SOURCE GATE: the header is only
 * honoured when the request's TCP peer (REMOTE_ADDR -- the proxy, NOT any client-set
 * X-Forwarded-For) is in the provider's trusted-proxy allowlist. Without that, anyone
 * able to reach the WebGUI could forge the header and log in as anyone. The JWT
 * signature/iss/aud/exp checks live in JwtProtocol.
 *
 * Not rate-limited per source, unlike the OIDC/SAML endpoints: every user of this
 * provider arrives from the same proxy address, so a per-IP throttle would only
 * throttle the whole organisation at once. The trusted-proxy allowlist is what bounds
 * who can reach it at all.
 */
class JwtController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    /** GET /api/sso/jwt/login?provider=<name> */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, 'Bad Request');
            return 'Already logged in.';
        }
        try {
            $auth = $this->authServer($this->request->get('provider'));

            // SOURCE GATE -- before reading any header. The TCP peer must be a
            // configured trusted proxy; client-supplied XFF is deliberately ignored.
            $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '');
            if (!SourceGate::allows($peer, (array)$auth->ssoJwtTrustedProxies)) {
                throw new \RuntimeException('JWT forward-auth from untrusted source ' . $peer);
            }

            $token = $this->readToken((string)($auth->ssoJwtHeader ?: 'X-Auth-Request-Jwt'));
            if ($token === '') {
                throw new \RuntimeException('no JWT in the configured header');
            }

            $protocol = new JwtProtocol([
                'issuer' => $auth->ssoJwtIssuer,
                'audience' => $auth->ssoJwtAudience,
                'jwks_url' => $auth->ssoJwtJwksUrl,
                'public_key' => $auth->ssoJwtPublicKey,
                'algorithms' => (array)$auth->ssoJwtAlgorithms,
                'leeway' => $auth->ssoJwtClockSkew,
                'max_age' => $auth->ssoJwtMaxAge,
                'single_use' => $auth->ssoJwtSingleUse,
                'username_claim' => $auth->ssoUsernameClaim,
                'groups_claim' => $auth->ssoGroupsClaim,
            ]);
            $identity = $protocol->verify($token);
            $identity->authServer = (string)$this->request->get('provider');

            // Provider-level door policy, before any local account is touched or created.
            AccessPolicy::assert((array)$auth->ssoRequiredGroups, $identity, (bool)$auth->ssoDeprovision);

            $username = (new IdentityMapper(new GroupMapper(
                GroupMapper::parseMap((string)$auth->ssoGroupMap),
                (bool)$auth->ssoGroupSync
            )))->resolve(
                $identity,
                (bool)$auth->ssoCreateUsers,
                (array)$auth->ssoDefaultGroups
            );

            $this->startSession();
            (new SessionEstablisher())->establish($username, (string)$this->request->get('provider'), [
                'issuer' => (string)$auth->ssoJwtIssuer,
                'sub' => $identity->subject,
                'lifetime' => (int)$auth->ssoSessionLifetime,
            ]);
            // JWT is a local logout only (no IdP redirect to end a remote session).
            $_SESSION['sso_logout'] = ['type' => 'jwt', 'provider' => (string)$this->request->get('provider')];
            $returnUrl = $this->landing((string)($this->request->get('url') ?? '/'), $auth);
        } catch (\Throwable $e) {
            return $this->fail($e);
        }
        session_write_close();
        $this->response->redirect($returnUrl, true);
        return 'Login successful, redirecting...';
    }

    /** GET /api/sso/jwt/icon?provider=<name> -- proxied issuer favicon (best effort). */
    public function iconAction()
    {
        try {
            // Pre-auth, and on a cache miss it reaches out to the IdP (DNS plus up to
            // two HTTPS fetches). Generous, because one login page pulls one icon per
            // configured provider; a failed hit just renders as a missing icon.
            RateLimiter::hit('sso-icon', $this->clientIp(), 60);
            $auth = $this->authServer($this->request->get('provider'));
            $icon = FaviconProxy::fetch((string)$auth->ssoJwtIssuer);
        } catch (\Throwable $e) {
            $this->response->setStatusCode(404, 'Not Found');
            return '';
        }
        foreach (FaviconProxy::headers($icon['type']) as $header => $value) {
            $this->response->setHeader($header, $value);
        }
        return $icon['data'];
    }

    /* ------------------------------------------------------------------ */

    private function authServer($provider)
    {
        if (empty($provider)) {
            throw new \RuntimeException('missing provider');
        }
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth === null || $auth->getType() !== 'jwt') {
            throw new \RuntimeException('unknown JWT provider');
        }
        return $auth;
    }

    /** Direct TCP peer -- never a forwardable header. */
    private function clientIp(): string
    {
        return (string)($_SERVER['REMOTE_ADDR'] ?? '');
    }

    /** Read the JWT from $_SERVER, stripping an optional "Bearer " prefix. */
    private function readToken(string $headerName): string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
        $val = (string)($_SERVER[$key] ?? '');
        if ($val === '' && strcasecmp($headerName, 'Authorization') !== 0) {
            $val = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
        }
        if (stripos($val, 'Bearer ') === 0) {
            $val = substr($val, 7);
        }
        return trim($val);
    }

    /** Post-login landing path: requested page, else the configured default (ReturnUrl). */
    private function landing(string $returnUrl, $auth): string
    {
        return ReturnUrl::landing($returnUrl, (string)($auth->ssoLoginRedirect ?? ''));
    }

    private function startSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    }

    private function fail(\Throwable $e): string
    {
        syslog(LOG_ERR, 'os-sso jwt: ' . $e->getMessage());
        $this->response->setStatusCode(400, 'Bad Request');
        return 'SSO login failed. See the firewall system log for details.';
    }
}
