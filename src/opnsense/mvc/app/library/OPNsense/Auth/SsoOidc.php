<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Auth;

/**
 * Thin IAuthConnector shim that registers the "oidc" server type under
 * System > Access > Servers and declares its configuration fields. The real
 * ceremony lives in OPNsense\SSO -- this connector's authenticate() is inert:
 * the browser flow runs through the SSO API controllers, never the password
 * authenticate() path.
 *
 * Extends Local so the existing user-database helpers and the Servers UI plumbing
 * keep working unchanged.
 */
class SsoOidc extends Local implements IAuthConnector
{
    public $ssoIssuer = null;
    public $ssoClientId = null;
    public $ssoClientSecret = null;
    public $ssoScopes = ['openid', 'email', 'profile'];
    public $ssoUsernameClaim = 'preferred_username';
    public $ssoGroupsClaim = 'groups';
    public $ssoUsePkce = true;
    public $ssoCreateUsers = false;
    public $ssoDefaultGroups = [];
    public $ssoGroupMap = null;
    public $ssoButtonLabel = null;
    public $ssoBaseUrl = null;
    public $ssoLoginRedirect = null;

    public static function getType()
    {
        return 'oidc';
    }

    public function getDescription()
    {
        return "<i class='fa fa-openid fa-fw'></i> " . gettext('OpenID Connect');
    }

    public function setProperties($config)
    {
        $map = [
            'sso_issuer' => 'ssoIssuer',
            'sso_client_id' => 'ssoClientId',
            'sso_client_secret' => 'ssoClientSecret',
            'sso_username_claim' => 'ssoUsernameClaim',
            'sso_groups_claim' => 'ssoGroupsClaim',
            'sso_button_label' => 'ssoButtonLabel',
            'sso_base_url' => 'ssoBaseUrl',
            'sso_login_redirect' => 'ssoLoginRedirect',
            'sso_group_map' => 'ssoGroupMap',
        ];
        foreach ($map as $k => $prop) {
            if (!empty($config[$k]) && property_exists($this, $prop)) {
                $this->$prop = $config[$k];
            }
        }
        $this->ssoUsePkce = !empty($config['sso_use_pkce']);
        $this->ssoCreateUsers = !empty($config['sso_create_users']);
        if (!empty($config['sso_scopes'])) {
            $this->ssoScopes = array_filter(array_map('trim', explode(',', $config['sso_scopes'])));
        }
        $this->ssoDefaultGroups = array_filter(array_map('trim', explode(',', $config['sso_default_groups'] ?? '')));
    }

    public function getConfigurationOptions()
    {
        $base = trim((string)$this->ssoBaseUrl) !== '' ? rtrim((string)$this->ssoBaseUrl, '/') : 'https://{opnsense}';
        $callback = gettext('Set the redirect/callback URL at the IdP to') .
            ' <code>' . htmlspecialchars($base) . '/api/sso/oidc/callback</code>.';
        return [
            'sso_issuer' => [
                'name' => gettext('Issuer URL'),
                'help' => gettext('OIDC issuer base URL (the part before /.well-known/openid-configuration).') . ' ' . $callback,
                'type' => 'text',
                'validate' => fn($v) => filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0
                    ? [] : [gettext('Issuer must be a valid https URL.')],
            ],
            'sso_client_id' => [
                'name' => gettext('Client ID'),
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('Client ID is required.')],
            ],
            'sso_client_secret' => [
                'name' => gettext('Client Secret'),
                'help' => gettext('Secret of the confidential client created at the IdP (public clients are not supported).'),
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('Client Secret is required (public clients unsupported).')],
            ],
            'sso_scopes' => [
                'name' => gettext('Scopes'),
                'help' => gettext('Comma separated. "openid" is required.'),
                'type' => 'text',
                'default' => join(',', $this->ssoScopes),
            ],
            'sso_use_pkce' => [
                'name' => gettext('Use PKCE (S256)'),
                'help' => gettext('Proof Key for Code Exchange. Recommended; keep enabled unless the IdP does not support it.'),
                'type' => 'checkbox',
                'default' => '1',
            ],
            'sso_username_claim' => [
                'name' => gettext('Username claim'),
                'help' => gettext('Claim mapped to the local username, e.g. preferred_username or email.'),
                'type' => 'text',
                'default' => $this->ssoUsernameClaim,
            ],
            'sso_groups_claim' => [
                'name' => gettext('Groups claim'),
                'help' => gettext('Claim listing the user\'s groups/roles (array, or comma/space separated).'),
                'type' => 'text',
                'default' => $this->ssoGroupsClaim,
            ],
            'sso_create_users' => [
                'name' => gettext('Automatic user creation'),
                'help' => gettext('Discouraged on a firewall. Persists new users to config.xml with no local password.'),
                'type' => 'checkbox',
            ],
            'sso_default_groups' => [
                'name' => gettext('Default groups'),
                'help' => gettext('Comma separated OPNsense groups granted to mapped users.'),
                'type' => 'text',
            ],
            'sso_group_map' => [
                'name' => gettext('Group mapping'),
                'help' => gettext('Optional explicit IdP-group to OPNsense-group map, comma separated '
                    . 'as "idpGroup:opnsenseGroup". Mapped groups are trusted and may target privileged '
                    . 'groups (e.g. admins). Unmapped IdP groups fall back to a 1:1 name match that '
                    . 'refuses privileged groups.'),
                'type' => 'text',
            ],
            'sso_button_label' => [
                'name' => gettext('Login button label'),
                'help' => gettext('Text shown on the login-page button (defaults to the server name).'),
                'type' => 'text',
            ],
            'sso_base_url' => [
                'name' => gettext('Base URL (override)'),
                'help' => gettext('Public base URL of this firewall (https://host[:port]) used to build the OIDC '
                    . 'redirect/callback URL registered at the IdP (and the post-logout URL). '
                    . 'Leave empty to auto-detect from the request Host. Set it when behind a reverse proxy '
                    . 'or port-forward so the callback matches what the IdP has registered.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || (filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0)
                    ? [] : [gettext('Base URL must be a valid https URL.')],
            ],
            'sso_login_redirect' => [
                'name' => gettext('Default landing URL'),
                'help' => gettext('Same-site relative path where users land after a successful WebGUI login '
                    . 'when no specific page was requested (e.g. /ui/dashboard or /index.php). '
                    . 'Leave empty to use the originally requested page, or the dashboard.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || ($v[0] === '/' && !str_starts_with($v, '//') && strpbrk($v, "\\\r\n\t") === false)
                    ? [] : [gettext('Landing URL must be a same-site path starting with "/".')],
            ],
            // Hidden carrier: JS shows the live redirect/callback URL under Base URL.
            '__sso_oidc_script' => [
                'name' => '',
                'help' => '<script>' . $this->formScript() . '</script>',
            ],
        ];
    }

    /** JS that shows the computed redirect/callback URL (live) under the Base URL field. */
    private function formScript()
    {
        return <<<'JS'
(function () {
    function init() {
        // The legacy form renders every auth type's fields (one row per type, tagged
        // auth_<type>); there are multiple [name=sso_base_url], so scope to ours.
        var base = document.querySelector('tr.auth_oidc [name="sso_base_url"]')
            || document.querySelector('[name="sso_base_url"]');
        if (!base || base._ssoDisp) { return; }
        var box = document.createElement('div');
        box.style.marginTop = '6px';
        function upd() {
            var b = (base.value || (location.protocol + '//' + location.host)).replace(/\/+$/, '');
            box.innerHTML = 'Redirect/callback URL to register at the IdP:<br>'
                + '<code>' + b + '/api/sso/oidc/callback</code>';
        }
        base.addEventListener('input', upd);
        upd();
        base.parentNode.appendChild(box);
        base._ssoDisp = 1;
        var a = document.getElementById('help_for_field_oidc___sso_oidc_script');
        if (a) { var tr = a.closest('tr'); if (tr) { tr.style.display = 'none'; } }
    }
    if (document.readyState !== 'loading') { init(); }
    else { document.addEventListener('DOMContentLoaded', init); }
})();
JS;
    }

    public function getLastAuthProperties()
    {
        return [];
    }

    public function preauth($username)
    {
        return false;
    }

    /** Inert: SSO never authenticates via the password path. */
    public function authenticate($username, $password)
    {
        return false;
    }
}
