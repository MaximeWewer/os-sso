<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Auth;

/**
 * IAuthConnector shim registering the "jwt" forward-auth server type. The firewall
 * sits behind a trusted upstream proxy that authenticates the user and forwards a
 * SIGNED JWT in a header; os-sso verifies it and opens the session. Like
 * the other shims, authenticate() is inert -- the flow runs through the SSO API
 * controller (JwtController).
 */
class SsoJwt extends Local implements IAuthConnector
{
    public $ssoJwtIssuer = null;
    public $ssoJwtAudience = null;
    public $ssoJwtHeader = 'X-Auth-Request-Jwt';
    public $ssoJwtJwksUrl = null;
    public $ssoJwtPublicKey = null;
    // Common asymmetric algorithms supported out-of-the-box (the verifier rejects
    // symmetric HS*/none regardless). RS256 stays first: it is the default applied
    // to JWKS keys lacking an "alg" and to a static PEM key. PS384/PS512/ES512 are
    // not in the vendored firebase/php-jwt and so are intentionally absent.
    public $ssoJwtAlgorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384', 'EdDSA'];
    public $ssoJwtClockSkew = 60;
    public $ssoJwtTrustedProxies = [];
    public $ssoUsernameClaim = 'preferred_username';
    public $ssoGroupsClaim = 'groups';
    public $ssoCreateUsers = false;
    public $ssoDefaultGroups = [];
    public $ssoGroupMap = null;
    public $ssoGroupSync = false;
    public $ssoButtonLabel = null;
    public $ssoLoginRedirect = null;

    public static function getType()
    {
        return 'jwt';
    }

    public function getDescription()
    {
        return "<i class='fa fa-key fa-fw'></i> " . gettext('JWT - Forward-auth');
    }

    public function setProperties($config)
    {
        $map = [
            'sso_jwt_issuer' => 'ssoJwtIssuer',
            'sso_jwt_audience' => 'ssoJwtAudience',
            'sso_jwt_header' => 'ssoJwtHeader',
            'sso_jwt_jwks_url' => 'ssoJwtJwksUrl',
            'sso_jwt_public_key' => 'ssoJwtPublicKey',
            'sso_username_claim' => 'ssoUsernameClaim',
            'sso_groups_claim' => 'ssoGroupsClaim',
            'sso_button_label' => 'ssoButtonLabel',
            'sso_login_redirect' => 'ssoLoginRedirect',
            'sso_group_map' => 'ssoGroupMap',
        ];
        foreach ($map as $k => $prop) {
            if (!empty($config[$k]) && property_exists($this, $prop)) {
                $this->$prop = $config[$k];
            }
        }
        $this->ssoCreateUsers = !empty($config['sso_create_users']);
        $this->ssoGroupSync = !empty($config['sso_group_sync']);
        if (!empty($config['sso_jwt_algorithms'])) {
            $this->ssoJwtAlgorithms = array_filter(array_map('trim', explode(',', $config['sso_jwt_algorithms'])));
        }
        if (isset($config['sso_jwt_clock_skew']) && $config['sso_jwt_clock_skew'] !== '') {
            $this->ssoJwtClockSkew = (int)$config['sso_jwt_clock_skew'];
        }
        $this->ssoJwtTrustedProxies = array_filter(array_map('trim', explode(',', $config['sso_jwt_trusted_proxies'] ?? '')));
        $this->ssoDefaultGroups = array_filter(array_map('trim', explode(',', $config['sso_default_groups'] ?? '')));
    }

    public function getConfigurationOptions()
    {
        $help = gettext('Point your reverse proxy at') .
            ' <code>https://{opnsense}/api/sso/jwt/login?provider={name}</code> ' .
            gettext('and have it inject the signed JWT in the configured header.');
        return [
            'sso_jwt_issuer' => [
                'name' => gettext('Issuer (iss)'),
                'help' => gettext('Expected token issuer.') . ' ' . $help,
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('Issuer is required.')],
            ],
            'sso_jwt_audience' => [
                'name' => gettext('Audience (aud)'),
                'help' => gettext('Expected audience -- must identify this firewall.'),
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('Audience is required.')],
            ],
            'sso_jwt_trusted_proxies' => [
                'name' => gettext('Trusted proxy IPs/CIDRs'),
                'help' => gettext('Comma separated source IPs or CIDRs of the proxy allowed to '
                    . 'present the JWT header. REQUIRED: the header is ignored from any other source '
                    . '(otherwise anyone could forge it). The check uses the direct TCP peer '
                    . '(REMOTE_ADDR), never a forwardable header -- so list the IP that actually '
                    . 'connects to the firewall. If another reverse proxy sits in front of the WebGUI, '
                    . 'this must be that proxy IP, and that proxy must strip the JWT header from '
                    . 'untrusted clients.'),
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('At least one trusted proxy IP/CIDR is required.')],
            ],
            'sso_jwt_header' => [
                'name' => gettext('JWT header'),
                'help' => gettext('Request header carrying the token (e.g. X-Auth-Request-Jwt or Authorization).'),
                'type' => 'text',
                'default' => 'X-Auth-Request-Jwt',
            ],
            'sso_jwt_jwks_url' => [
                'name' => gettext('JWKS URL'),
                'help' => gettext('HTTPS JWKS endpoint of the signer (preferred, supports key rotation).'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || (filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0)
                    ? [] : [gettext('JWKS URL must be a valid https URL.')],
            ],
            'sso_jwt_public_key' => [
                'name' => gettext('Static public key (PEM)'),
                'help' => gettext('Alternative to JWKS: the signer PEM public key. The first algorithm below must match it.'),
                'type' => 'text',
            ],
            'sso_jwt_algorithms' => [
                'name' => gettext('Algorithms'),
                'help' => gettext('Comma separated, asymmetric only (RS256/ES256/PS256...). Symmetric HS* is rejected.'),
                'type' => 'text',
                'default' => join(',', $this->ssoJwtAlgorithms),
            ],
            'sso_jwt_clock_skew' => [
                'name' => gettext('Clock skew tolerance (s)'),
                'help' => gettext('Allowed clock difference (seconds) when checking exp/nbf. Default 60, max 300.'),
                'type' => 'text',
                'default' => (string)$this->ssoJwtClockSkew,
                'validate' => fn($v) => ($v === '' || (ctype_digit((string)$v) && (int)$v <= 300))
                    ? [] : [gettext('Clock skew must be a number of seconds (0-300).')],
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
            'sso_group_sync' => [
                'name' => gettext('Strict group sync'),
                'help' => gettext('Reconcile group membership on every login: remove the user from '
                    . 'groups os-sso previously granted but the IdP no longer asserts. Only groups '
                    . 'os-sso itself granted are touched (manual assignments are kept), and the last '
                    . 'member of a privileged group is never removed. Off = additive (memberships are '
                    . 'only ever added).'),
                'type' => 'checkbox',
            ],
            'sso_button_label' => [
                'name' => gettext('Login button label'),
                'help' => gettext('Text shown on the login-page button (defaults to the server name).'),
                'type' => 'text',
            ],
            'sso_login_redirect' => [
                'name' => gettext('Default landing URL'),
                'help' => gettext('Same-site relative path where users land after login (e.g. /ui/dashboard). '
                    . 'Leave empty for the requested page or the dashboard.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || ($v[0] === '/' && !str_starts_with($v, '//') && strpbrk($v, "\\\r\n\t") === false)
                    ? [] : [gettext('Landing URL must be a same-site path starting with "/".')],
            ],
            // Upgrade the PEM input to a textarea (legacy Servers form renders text only).
            '__sso_jwt_script' => [
                'name' => '',
                'help' => '<script>' . $this->formScript() . '</script>',
            ],
        ];
    }

    /** JS that turns the PEM input into a textarea in the legacy Servers form. */
    private function formScript()
    {
        return <<<'JS'
(function () {
    function toTextarea(name) {
        var el = document.querySelector('[name="' + name + '"]');
        if (!el || el.tagName.toLowerCase() === 'textarea') { return; }
        var ta = document.createElement('textarea');
        for (var i = 0; i < el.attributes.length; i++) {
            ta.setAttribute(el.attributes[i].name, el.attributes[i].value);
        }
        ta.value = el.value;
        ta.setAttribute('rows', '5');
        ta.style.width = '100%';
        ta.style.fontFamily = 'monospace';
        el.parentNode.replaceChild(ta, el);
    }
    function apply() {
        toTextarea('sso_jwt_public_key');
        var a = document.getElementById('help_for_field_jwt___sso_jwt_script');
        if (a) { var tr = a.closest('tr'); if (tr) { tr.style.display = 'none'; } }
    }
    if (document.readyState !== 'loading') { apply(); }
    else { document.addEventListener('DOMContentLoaded', apply); }
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
