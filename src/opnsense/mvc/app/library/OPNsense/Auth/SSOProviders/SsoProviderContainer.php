<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Auth\SSOProviders;

use OPNsense\Core\Config;

/**
 * Single coupling point with the login page. Implements the core ISSOContainer
 * extension point: authgui.inc already loops listSSOproviders('WebGui') and calls
 * renderLink() on each. So the login button is added with ZERO template patching --
 * this replaces the "LoginInjector" concept from the original plan.
 *
 * Discovered automatically: AuthenticationFactory reflects over SSOProviders/*.php
 * for ISSOContainer implementers.
 */
class SsoProviderContainer implements ISSOContainer
{
    private const TYPES = ['oidc', 'saml', 'jwt'];

    public function listProviders(): \Generator
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->authserver)) {
            return;
        }

        $providers = [];
        $cpProviders = [];
        foreach ($cnf->system->authserver as $server) {
            $type = (string)$server->type;
            if (!in_array($type, self::TYPES, true)) {
                continue;
            }
            $name = (string)$server->name;
            $label = trim((string)($server->sso_button_label ?? ''));
            if ($label === '') {
                $label = $name;
            }

            $loginUri = sprintf('/api/sso/%s/login?provider=%s', $type, rawurlencode($name));
            $iconUri = sprintf('/api/sso/%s/icon?provider=%s', $type, rawurlencode($name));

            // Captive Portal variant: same login endpoint, exposed under the 'cp'
            // service so listSSOproviders('cp') (and a portal template) can render it.
            // The zone id + return URL are appended by the portal page at click time.
            // JWT forward-auth is proxy-header based and does not fit a captive client,
            // so it is offered on the WebGUI only.
            if ($type !== 'jwt') {
                $cpProviders[] = new Provider([
                    'id' => 'sso-cp-' . $type . '-' . $name,
                    'appcode' => $type,
                    'service' => 'cp',
                    'name' => $label,
                    'login_uri' => $loginUri,
                ]);
            }

            // Full-width button: "Login with XXX" with the IdP favicon to the right.
            $html = sprintf(
                '<a href="%s" class="btn btn-default btn-block" '
                . 'style="margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:8px;">'
                . '<span>%s</span>'
                . '<img src="%s" alt="" style="height:16px;width:16px;" '
                . 'onerror="this.style.display=&quot;none&quot;">'
                . '</a>',
                htmlspecialchars($loginUri, ENT_QUOTES),
                htmlspecialchars($label, ENT_QUOTES),
                htmlspecialchars($iconUri, ENT_QUOTES)
            );

            $providers[] = new Provider([
                'id' => 'sso-' . $type . '-' . $name,
                'service' => 'WebGui',
                'name' => $label,
                'login_uri' => $loginUri,
                'html_content' => $html,
            ]);
        }

        if (empty($providers)) {
            return;
        }

        // Thin rule that visually separates the standard login from the SSO buttons.
        yield new Provider([
            'id' => 'sso-separator',
            'service' => 'WebGui',
            'html_content' => '<hr style="margin:10px 0 8px;border:0;border-top:1px solid #ddd;">',
        ]);
        foreach ($providers as $provider) {
            yield $provider;
        }
        // Captive Portal providers (consumed by a portal template via
        // listSSOproviders('cp') / the providers API, never on the WebGUI page).
        foreach ($cpProviders as $provider) {
            yield $provider;
        }
    }
}
