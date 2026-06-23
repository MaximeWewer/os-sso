<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Auth\AuthenticationFactory;

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
        $this->response->setHeader('Access-Control-Allow-Origin', '*');
        $this->response->setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET');
        return true;
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
