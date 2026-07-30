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
    public $ssoMaxAge = 0;
    public $ssoFormPost = false;
    public $ssoRequiredAcr = [];
    public $ssoExtraParams = null;
    public $ssoSessionLifetime = 0;
    public $ssoScimEnabled = false;
    public $ssoScimToken = null;
    public $ssoScimTrusted = [];
    public $ssoCreateUsers = false;
    public $ssoRequiredGroups = [];
    public $ssoDeprovision = false;
    public $ssoDefaultGroups = [];
    public $ssoGroupMap = null;
    public $ssoGroupSync = false;
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
            'sso_scim_token' => 'ssoScimToken',
            'sso_extra_params' => 'ssoExtraParams',
        ];
        foreach ($map as $k => $prop) {
            if (!empty($config[$k]) && property_exists($this, $prop)) {
                $this->$prop = $config[$k];
            }
        }
        $this->ssoUsePkce = !empty($config['sso_use_pkce']);
        $this->ssoFormPost = !empty($config['sso_form_post']);
        if (isset($config['sso_max_age']) && $config['sso_max_age'] !== '') {
            $this->ssoMaxAge = (int)$config['sso_max_age'];
        }
        $this->ssoCreateUsers = !empty($config['sso_create_users']);
        $this->ssoScimEnabled = !empty($config['sso_scim_enabled']);
        $this->ssoScimTrusted = array_filter(array_map('trim', explode(',', $config['sso_scim_trusted'] ?? '')));
        $this->ssoDeprovision = !empty($config['sso_deprovision']);
        if (isset($config['sso_session_lifetime']) && $config['sso_session_lifetime'] !== '') {
            $this->ssoSessionLifetime = (int)$config['sso_session_lifetime'];
        }
        $this->ssoGroupSync = !empty($config['sso_group_sync']);
        if (!empty($config['sso_scopes'])) {
            $this->ssoScopes = array_filter(array_map('trim', explode(',', $config['sso_scopes'])));
        }
        $this->ssoRequiredAcr = array_filter(array_map('trim', explode(',', $config['sso_required_acr'] ?? '')));
        $this->ssoRequiredGroups = array_filter(array_map('trim', explode(',', $config['sso_required_groups'] ?? '')));
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
            'sso_max_age' => [
                'name' => gettext('Maximum authentication age (s)'),
                'help' => gettext('Send max_age so the IdP re-authenticates anyone whose session there is '
                    . 'older than this, and refuse the login if the returned auth_time says otherwise. '
                    . '0 disables it (the IdP session is then accepted whatever its age).'),
                'type' => 'text',
                'default' => '0',
                'validate' => fn($v) => ($v === '' || ctype_digit((string)$v))
                    ? [] : [gettext('Maximum authentication age must be a number of seconds (0 = disabled).')],
            ],
            'sso_form_post' => [
                'name' => gettext('Use form_post response mode'),
                'help' => gettext('Ask the IdP to POST the authorization response instead of putting the code '
                    . 'in the callback URL, keeping it out of browser history, Referer headers and proxy logs. '
                    . 'Enable only if the IdP supports response_mode=form_post.'),
                'type' => 'checkbox',
            ],
            'sso_required_acr' => [
                'name' => gettext('Required authentication context (acr)'),
                'help' => gettext('Comma separated authentication context class references, in preference '
                    . 'order - typically the one your IdP uses for MFA. They are sent as acr_values AND the '
                    . '"acr" claim that comes back must be one of them. Both halves matter: requesting a '
                    . 'context is voluntary per the spec, so an IdP is free to ignore it and return an '
                    . 'ordinary session - only the returned acr proves anything. Empty accepts whatever '
                    . 'context the IdP used.'),
                'type' => 'text',
            ],
            'sso_extra_params' => [
                'name' => gettext('Extra authorization parameters'),
                'help' => gettext('Optional "key=value" pairs, comma separated, appended to the authorization '
                    . 'request (e.g. "prompt=login, ui_locales=fr"). Parameters that carry the security of the '
                    . 'flow (state, nonce, redirect_uri, PKCE, max_age, acr_values...) are ignored here - use '
                    . 'the dedicated fields, which also verify what comes back.'),
                'type' => 'text',
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
            'sso_session_lifetime' => [
                'name' => gettext('Maximum session lifetime (s)'),
                'help' => gettext('End the WebGUI session this long after login whatever the user is doing, '
                    . 'unlike the idle timeout. Enforced when the "sso expire_sessions" action runs (schedule '
                    . 'it under System > Settings > Cron) and on every SSO login. 0 keeps sessions until they '
                    . 'idle out.'),
                'type' => 'text',
                'default' => '0',
                'validate' => fn($v) => ($v === '' || ctype_digit((string)$v))
                    ? [] : [gettext('Maximum session lifetime must be a number of seconds (0 = disabled).')],
            ],
            'sso_create_users' => [
                'name' => gettext('Automatic user creation'),
                'help' => gettext('Discouraged on a firewall. Persists new users to config.xml with no local password.'),
                'type' => 'checkbox',
            ],
            'sso_required_groups' => [
                'name' => gettext('Required groups'),
                'help' => gettext('Access gate: comma separated IdP group names, at least one of which the '
                    . 'user must hold to log in through this provider (WebGUI, Captive Portal and VPN alike). '
                    . 'Evaluated on the IdP-asserted groups, before any local account is matched, created or '
                    . 'updated. Leave empty to let every account the IdP authenticates log in.'),
                'type' => 'text',
            ],
            'sso_deprovision' => [
                'name' => gettext('Deprovision on refused login'),
                'help' => gettext('When a login is refused by the required groups above, also disable the '
                    . 'local account it belongs to and end its open sessions. This is how a revocation at the '
                    . 'IdP reaches the firewall: a login attempt is the only moment we hear about it. Only '
                    . 'os-sso-managed accounts are touched, never a privileged one, and they are disabled, '
                    . 'not deleted. Needs a required-groups list to be of any use.'),
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
            'sso_group_sync' => [
                'name' => gettext('Strict group sync'),
                'help' => gettext('Reconcile group membership on every login: remove the user from '
                    . 'groups os-sso previously granted but the IdP no longer asserts. Only groups '
                    . 'os-sso itself granted are touched (manual assignments are kept), and the last '
                    . 'member of a privileged group is never removed. Off = additive (memberships are '
                    . 'only ever added).'),
                'type' => 'checkbox',
            ],
            'sso_scim_enabled' => [
                'name' => gettext('Enable SCIM provisioning'),
                'help' => gettext('Let this IdP push account lifecycle to the firewall over SCIM 2.0, instead '
                    . 'of os-sso only learning about changes when someone logs in. Base URL to register at the '
                    . 'IdP: <code>https://{opnsense}/api/sso/scim</code>. Accounts are created disabled-free, '
                    . 'never privileged, and a SCIM delete deactivates rather than removes.'),
                'type' => 'checkbox',
            ],
            'sso_scim_token' => [
                'name' => gettext('SCIM bearer token'),
                'help' => gettext('Shared secret the IdP presents as "Authorization: Bearer ...". It is the '
                    . 'whole authentication of a write API into the account database - generate a long random '
                    . 'value and treat it as a credential.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || strlen($v) >= 32
                    ? [] : [gettext('The SCIM token should be at least 32 characters.')],
            ],
            'sso_scim_trusted' => [
                'name' => gettext('SCIM source IPs/CIDRs'),
                'help' => gettext('Comma separated addresses the IdP connects from. REQUIRED when SCIM is '
                    . 'enabled: it bounds who can even attempt to use the token, and an empty list refuses '
                    . 'every request rather than accepting any source. Matched on the direct TCP peer, never '
                    . 'on a forwardable header.'),
                'type' => 'text',
            ],
            'sso_button_label' => [
                'name' => gettext('Login button label'),
                'help' => gettext('Text shown on the login-page button (defaults to the server name).'),
                'type' => 'text',
            ],
            'sso_base_url' => [
                'name' => gettext('Base URL'),
                'help' => gettext('Public base URL of this firewall (https://host[:port]) used to build the OIDC '
                    . 'redirect/callback URL registered at the IdP (and the post-logout URL). Required: '
                    . 'without it the URL is derived from the request Host header, which the client controls. '
                    . 'Set it to exactly what the IdP has registered (mind a reverse proxy or port-forward).'),
                'type' => 'text',
                'validate' => fn($v) => !empty($v) && filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0
                    ? [] : [gettext('Base URL is required and must be a valid https URL.')],
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
        var nameEl = document.querySelector('tr.auth_oidc [name="name"]')
            || document.querySelector('[name="name"]');
        function upd() {
            var b = (base.value || (location.protocol + '//' + location.host)).replace(/\/+$/, '');
            var q = '?provider=' + encodeURIComponent((nameEl && nameEl.value) || '{name}');
            box.innerHTML = 'Redirect/callback URL to register at the IdP:<br>'
                + '<code>' + b + '/api/sso/oidc/callback</code><br>'
                + 'Back-channel logout URL (optional):<br>'
                + '<code>' + b + '/api/sso/oidc/backchannel' + q + '</code>';
        }
        base.addEventListener('input', upd);
        if (nameEl) { nameEl.addEventListener('input', upd); }
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
