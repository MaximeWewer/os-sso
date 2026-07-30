<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\SSO\SamlMetadata;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\SiteUrl;
use OPNsense\SSO\StateDir;
use OPNsense\SSO\Protocol\OidcProtocol;

/**
 * Read-only diagnostics behind the WebGUI ACL (no doAuth override here: this one is
 * for administrators, unlike the pre-auth login endpoints).
 *
 * Debugging an SSO setup otherwise means reading syslog and guessing. This answers the
 * questions that actually come up: does the IdP resolve, is the certificate the one I
 * think, which URLs do I have to register there, who is logged in right now -- and it
 * lets an operator drop the discovery/JWKS/metadata caches after changing something at
 * the IdP instead of waiting out a TTL.
 */
class DiagnosticsController extends ApiControllerBase
{
    /** GET /api/sso/diagnostics/providers -- configured providers and their URLs. */
    public function providersAction()
    {
        $out = [];
        foreach ($this->ssoServers() as $server) {
            $name = (string)$server->name;
            $type = (string)$server->type;
            $auth = (new AuthenticationFactory())->get($name);
            if ($auth === null) {
                continue;
            }
            $base = SiteUrl::forProvider($auth);
            $row = [
                'name' => $name,
                'type' => $type,
                'base_url' => $base,
                'base_url_configured' => trim((string)($auth->ssoBaseUrl ?? '')) !== '',
                'create_users' => !empty($auth->ssoCreateUsers),
                'group_sync' => !empty($auth->ssoGroupSync),
                'deprovision' => !empty($auth->ssoDeprovision),
                'required_groups' => implode(', ', (array)$auth->ssoRequiredGroups),
                'default_groups' => implode(', ', (array)$auth->ssoDefaultGroups),
                'session_lifetime' => (int)($auth->ssoSessionLifetime ?? 0),
                'scim' => !empty($auth->ssoScimEnabled),
                'urls' => $this->urlsFor($type, $base, $name, !empty($auth->ssoScimEnabled)),
            ];
            $out[] = $row;
        }
        return ['providers' => $out];
    }

    /**
     * GET /api/sso/diagnostics/check/$provider -- talk to the IdP and report.
     * Everything here is a live fetch, so it is also the way to find out that a
     * firewall rule, a proxy or a certificate is in the way.
     */
    public function checkAction($provider = null)
    {
        $name = (string)$provider;
        $auth = $name !== '' ? (new AuthenticationFactory())->get($name) : null;
        if ($auth === null || !in_array($auth->getType(), ['oidc', 'saml', 'jwt'], true)) {
            $this->response->setStatusCode(404, 'Not Found');
            return ['status' => 'failed', 'message' => 'unknown SSO provider'];
        }
        try {
            switch ($auth->getType()) {
                case 'oidc':
                    return $this->checkOidc($auth) + ['status' => 'ok'];
                case 'saml':
                    return $this->checkSaml($auth) + ['status' => 'ok'];
                default:
                    return $this->checkJwt($auth) + ['status' => 'ok'];
            }
        } catch (\Throwable $e) {
            return ['status' => 'failed', 'message' => $e->getMessage()];
        }
    }

    /** GET /api/sso/diagnostics/sessions -- WebGUI sessions os-sso opened. */
    public function sessionsAction()
    {
        $rows = [];
        foreach (SessionRegistry::listActive() as $entry) {
            $rows[] = [
                // A handle, not the session id: enough to name a row, useless as a cookie.
                'id' => (string)($entry['id'] ?? ''),
                'username' => (string)($entry['username'] ?? ''),
                'provider' => (string)($entry['provider'] ?? ''),
                'subject' => (string)($entry['sub'] ?? ''),
                'started' => (int)($entry['started'] ?? 0),
                'expires_at' => (int)($entry['expires_at'] ?? 0),
            ];
        }
        return ['sessions' => $rows, 'total' => count($rows)];
    }

    /**
     * POST /api/sso/diagnostics/endSession/$id -- end one open SSO session.
     *
     * The page could already say who is signed in and until when; ending one of them
     * meant disabling the account or waiting out a timeout. $id is the handle
     * sessionsAction reports, which is a digest of the session id and not the id.
     */
    public function endSessionAction($id = null)
    {
        return $this->ending(fn() => SessionRegistry::destroyById((string)$id));
    }

    /** POST /api/sso/diagnostics/endAllSessions -- end every open SSO session. */
    public function endAllSessionsAction()
    {
        return $this->ending(fn() => SessionRegistry::destroyAll());
    }

    /** Shared POST-only wrapper for the two session-ending actions. */
    private function ending(callable $end): array
    {
        if (!$this->request->isPost()) {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $ended = (int)$end();
        if ($ended > 0) {
            syslog(LOG_NOTICE, sprintf(
                'os-sso: %d SSO session(s) ended from the diagnostics page by %s',
                $ended,
                (string)($this->session->get('Username') ?? 'an administrator')
            ));
        }
        return ['status' => 'ok', 'ended' => $ended];
    }

    /**
     * POST /api/sso/diagnostics/flushCaches -- drop the cached discovery documents,
     * JWKS, SAML metadata and icons, so the next login refetches everything.
     */
    public function flushCachesAction()
    {
        if (!$this->request->isPost()) {
            $this->response->setStatusCode(405, 'Method Not Allowed');
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $removed = 0;
        foreach (['oidc', 'jwt', 'saml-md', 'icons'] as $bucket) {
            try {
                foreach (glob(StateDir::path($bucket) . '/*.json') ?: [] as $file) {
                    $removed += (int)@unlink($file);
                }
            } catch (\RuntimeException $e) {
                // directory unavailable: nothing cached there to drop
            }
        }
        return ['status' => 'ok', 'removed' => $removed];
    }

    /* ------------------------------------------------------------------ */

    private function checkOidc($auth): array
    {
        $protocol = new OidcProtocol([
            'provider' => '',
            'issuer' => $auth->ssoIssuer,
            'client_id' => $auth->ssoClientId,
            'client_secret' => $auth->ssoClientSecret,
            // So the reported token_auth_method is the one a login would really use,
            // not what "auto" would have negotiated.
            'token_auth_method' => $auth->ssoTokenAuthMethod,
            'assertion_alg' => $auth->ssoAssertionAlg,
            'private_key' => $auth->ssoPrivateKey,
            'private_key_id' => $auth->ssoPrivateKeyId,
            'tls_cert' => $auth->ssoMtlsCert,
            'tls_key' => $auth->ssoMtlsKey,
        ]);
        $disco = $protocol->describe();
        return [
            'issuer' => (string)($disco['issuer'] ?? ''),
            'authorization_endpoint' => (string)($disco['authorization_endpoint'] ?? ''),
            'token_endpoint' => (string)($disco['token_endpoint'] ?? ''),
            'userinfo_endpoint' => (string)($disco['userinfo_endpoint'] ?? ''),
            'end_session_endpoint' => (string)($disco['end_session_endpoint'] ?? ''),
            'jwks_uri' => (string)($disco['jwks_uri'] ?? ''),
            'signing_keys' => (int)($disco['signing_keys'] ?? 0),
            'token_auth_method' => (string)($disco['token_auth_method'] ?? ''),
        ];
    }

    private function checkSaml($auth): array
    {
        $url = trim((string)($auth->ssoIdpMetadataUrl ?? ''));
        if ($url === '') {
            return [
                'source' => 'manual configuration',
                'entity_id' => (string)$auth->ssoIdpEntityId,
                'sso_url' => (string)$auth->ssoIdpSsoUrl,
                'slo_url' => (string)($auth->ssoIdpSloUrl ?: $auth->ssoIdpSsoUrl),
                'certificates' => trim((string)$auth->ssoIdpX509) !== '' ? 1 : 0,
            ];
        }
        $meta = SamlMetadata::fetch($url, (string)$auth->ssoIdpEntityId);
        return [
            'source' => 'metadata document',
            'entity_id' => $meta['entity_id'],
            'sso_url' => $meta['sso_url'],
            'slo_url' => $meta['slo_url'],
            'certificates' => max(count($meta['x509_signing']), $meta['x509'] !== '' ? 1 : 0),
        ];
    }

    private function checkJwt($auth): array
    {
        $jwks = trim((string)$auth->ssoJwtJwksUrl);
        if ($jwks === '') {
            return [
                'source' => 'static public key',
                'issuer' => (string)$auth->ssoJwtIssuer,
                'audience' => (string)$auth->ssoJwtAudience,
                'signing_keys' => trim((string)$auth->ssoJwtPublicKey) !== '' ? 1 : 0,
            ];
        }
        $doc = json_decode((string)$this->fetchJson($jwks), true);
        return [
            'source' => 'JWKS endpoint',
            'issuer' => (string)$auth->ssoJwtIssuer,
            'audience' => (string)$auth->ssoJwtAudience,
            'jwks_uri' => $jwks,
            'signing_keys' => is_array($doc) ? count((array)($doc['keys'] ?? [])) : 0,
        ];
    }

    /** Minimal verified https GET, only used by the JWKS check above. */
    private function fetchJson(string $url): string
    {
        if (stripos($url, 'https://') !== 0) {
            throw new \RuntimeException('JWKS URL must be https');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false) {
            throw new \RuntimeException('JWKS fetch failed: ' . $err);
        }
        if ($code < 200 || $code >= 300) {
            throw new \RuntimeException('JWKS HTTP ' . $code);
        }
        return (string)$body;
    }

    /** The URLs an operator has to register at the IdP for this provider. */
    private function urlsFor(string $type, string $base, string $name, bool $scim = false): array
    {
        $q = '?provider=' . rawurlencode($name);
        switch ($type) {
            case 'oidc':
                $urls = [
                    'Redirect / callback' => $base . '/api/sso/oidc/callback',
                    'Back-channel logout' => $base . '/api/sso/oidc/backchannel' . $q,
                    'Post-logout redirect' => $base . '/',
                    // Only of interest with private_key_jwt, but cheap to always show:
                    // it is where the IdP reads our client public key from.
                    'Client JWKS' => $base . '/api/sso/oidc/jwks' . $q,
                ];
                break;
            case 'saml':
                $urls = [
                    'ACS' => $base . '/api/sso/saml/acs' . $q,
                    'EntityID / metadata' => $base . '/api/sso/saml/metadata' . $q,
                    'SLO' => $base . '/api/sso/saml/slo' . $q,
                ];
                break;
            default:
                $urls = ['Forward-auth login' => $base . '/api/sso/jwt/login' . $q];
                break;
        }
        if ($scim) {
            // One base URL for every provider: the bearer token is what says which
            // one a request belongs to.
            $urls['SCIM base URL'] = $base . '/api/sso/scim';
        }
        return $urls;
    }

    /** @return \SimpleXMLElement[] */
    private function ssoServers(): array
    {
        $out = [];
        $cnf = Config::getInstance()->object();
        foreach (($cnf->system->authserver ?? []) as $server) {
            if (in_array((string)$server->type, ['oidc', 'saml', 'jwt'], true)) {
                $out[] = $server;
            }
        }
        return $out;
    }
}
