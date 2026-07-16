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
            if (!$this->ipAllowed($peer, (array)$auth->ssoJwtTrustedProxies)) {
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
                'username_claim' => $auth->ssoUsernameClaim,
                'groups_claim' => $auth->ssoGroupsClaim,
            ]);
            $identity = $protocol->verify($token);
            $identity->authServer = (string)$this->request->get('provider');

            $username = (new IdentityMapper(new GroupMapper(
                GroupMapper::parseMap((string)$auth->ssoGroupMap),
                (bool)$auth->ssoGroupSync
            )))->resolve(
                $identity,
                (bool)$auth->ssoCreateUsers,
                (array)$auth->ssoDefaultGroups
            );

            $this->startSession();
            (new SessionEstablisher())->establish($username, (string)$this->request->get('provider'));
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
            $auth = $this->authServer($this->request->get('provider'));
            $icon = FaviconProxy::fetch((string)$auth->ssoJwtIssuer);
        } catch (\Throwable $e) {
            $this->response->setStatusCode(404, 'Not Found');
            return '';
        }
        $this->response->setHeader('Content-Type', $icon['type']);
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
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

    /**
     * Is $ip within any of the configured IPs/CIDRs? IPv4 + IPv6, binary compare.
     */
    private function ipAllowed(string $ip, array $cidrs): bool
    {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            $cidr = trim((string)$cidr);
            if ($cidr === '') {
                continue;
            }
            if (strpos($cidr, '/') === false) {
                $netBin = @inet_pton($cidr);
                if ($netBin !== false && $netBin === $ipBin) {
                    return true;
                }
                continue;
            }
            [$net, $bitsRaw] = explode('/', $cidr, 2);
            $netBin = @inet_pton($net);
            if ($netBin === false || strlen($netBin) !== strlen($ipBin)) {
                continue;
            }
            $bits = (int)$bitsRaw;
            // Reject a prefix length outside the address width: an over-long prefix
            // would index past the address bytes below and spuriously over-match.
            if ($bits < 0 || $bits > strlen($ipBin) * 8) {
                continue;
            }
            $bytes = intdiv($bits, 8);
            $rem = $bits % 8;
            if ($bytes > 0 && strncmp($ipBin, $netBin, $bytes) !== 0) {
                continue;
            }
            if ($rem === 0) {
                return true;
            }
            $mask = chr((0xff << (8 - $rem)) & 0xff);
            if (((ord($ipBin[$bytes]) ^ ord($netBin[$bytes])) & ord($mask)) === 0) {
                return true;
            }
        }
        return false;
    }

    /** Post-login landing: explicit requested page wins, else the configured default. */
    private function landing(string $returnUrl, $auth): string
    {
        $returnUrl = $this->sanitizeReturn($returnUrl);
        if ($returnUrl !== '/') {
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
