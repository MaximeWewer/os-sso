<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\SSO\SiteUrl;

/**
 * Read-only helper for the Captive Portal login page. The portal is served from a
 * per-zone origin (port 8000 + zoneid), so it reads the available SSO providers from
 * here cross-origin and renders a button per provider. Pre-auth + CSRF-exempt: the
 * list is public and carries no secrets; the actual authorization still happens in
 * the OIDC/SAML callback against a verified identity.
 */
class PortalController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    public function beforeExecuteRoute($dispatcher)
    {
        $this->allowPortalOrigin();
        return true;
    }

    /**
     * CORS, but only for this firewall's own captive-portal origins.
     *
     * The portal listens on port 8000 + zone id, so the login page really is a
     * different origin from this API and really does need the header. A wildcard,
     * though, let any site on the internet read which authentication servers this
     * firewall has and where their login endpoints live. Reflect the Origin when it is
     * one of ours and send nothing otherwise -- a same-origin caller never needed it.
     */
    private function allowPortalOrigin(): void
    {
        $origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
        if ($origin === '' || !$this->isOwnPortalOrigin($origin)) {
            return;
        }
        $this->response->setHeader('Access-Control-Allow-Origin', $origin);
        $this->response->setHeader('Vary', 'Origin');
        $this->response->setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET');
    }

    private function isOwnPortalOrigin(string $origin): bool
    {
        $parts = parse_url($origin);
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        if (!in_array($scheme, ['http', 'https'], true) || empty($parts['host'])) {
            return false;
        }
        if (!SiteUrl::isOwnHost((string)$parts['host'])) {
            return false;
        }
        // Core serves zone N on 8000 + N, whether over http or https.
        $port = (int)($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        return $port >= 8000 && $port <= 8999;
    }

    /** GET /api/sso/portal/providers -- SSO providers offered to captive portals. */
    public function providersAction()
    {
        if ($this->request->isOptions()) {
            return [];
        }
        $out = [];
        foreach ((new AuthenticationFactory())->listSSOproviders('cp') as $provider) {
            $out[] = [
                'id' => $provider->id,
                'type' => $provider->appcode,
                'name' => $provider->name,
                'login_uri' => $provider->login_uri,
            ];
        }
        return ['providers' => $out];
    }
}
