<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Auth;

/**
 * IAuthConnector shim registering the "saml" server type. Mirror of SsoOidc;
 * authenticate() is inert -- the SAML browser flow runs through the SSO API
 * controllers.
 */
class SsoSaml extends Local implements IAuthConnector
{
    public $ssoIdpEntityId = null;
    public $ssoIdpSsoUrl = null;
    public $ssoIdpSloUrl = null;
    public $ssoIdpX509 = null;
    public $ssoSpCert = null;
    public $ssoSpKey = null;
    public $ssoNameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    public $ssoGroupsAttribute = 'groups';
    public $ssoWantMessagesSigned = false;
    public $ssoCreateUsers = false;
    public $ssoDefaultGroups = [];
    public $ssoGroupMap = null;
    public $ssoButtonLabel = null;
    public $ssoBaseUrl = null;
    public $ssoLoginRedirect = null;

    public static function getType()
    {
        return 'saml';
    }

    public function getDescription()
    {
        return "<i class='fa fa-id-card fa-fw'></i> " . gettext('SAML 2.0');
    }

    public function setProperties($config)
    {
        $map = [
            'sso_idp_entity_id' => 'ssoIdpEntityId',
            'sso_idp_sso_url' => 'ssoIdpSsoUrl',
            'sso_idp_slo_url' => 'ssoIdpSloUrl',
            'sso_idp_x509' => 'ssoIdpX509',
            'sso_sp_cert' => 'ssoSpCert',
            'sso_sp_key' => 'ssoSpKey',
            'sso_nameid_format' => 'ssoNameIdFormat',
            'sso_groups_attribute' => 'ssoGroupsAttribute',
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
        $this->ssoCreateUsers = !empty($config['sso_create_users']);
        $this->ssoWantMessagesSigned = !empty($config['sso_want_messages_signed']);
        $this->ssoDefaultGroups = array_filter(array_map('trim', explode(',', $config['sso_default_groups'] ?? '')));
    }

    public function getConfigurationOptions()
    {
        $base = trim((string)$this->ssoBaseUrl) !== '' ? rtrim((string)$this->ssoBaseUrl, '/') : 'https://{opnsense}';
        $b = htmlspecialchars($base);
        $acs = gettext('SP ACS URL is') . ' <code>' . $b . '/api/sso/saml/acs</code>, ' .
            gettext('metadata at') . ' <code>' . $b . '/api/sso/saml/metadata</code>.';
        return [
            'sso_idp_entity_id' => [
                'name' => gettext('IdP EntityID'),
                'help' => $acs,
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('IdP EntityID is required.')],
            ],
            'sso_idp_sso_url' => [
                'name' => gettext('IdP SSO URL'),
                'help' => gettext('IdP Single Sign-On endpoint (HTTP-Redirect binding).'),
                'type' => 'text',
                'validate' => fn($v) => filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0
                    ? [] : [gettext('A valid https SSO URL is required.')],
            ],
            'sso_idp_slo_url' => [
                'name' => gettext('IdP SLO URL'),
                'help' => gettext('IdP Single Logout endpoint (HTTP-Redirect). Leave empty to disable SLO; defaults to the SSO URL on Keycloak.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || (filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0)
                    ? [] : [gettext('SLO URL must be a valid https URL.')],
            ],
            'sso_idp_x509' => [
                'name' => gettext('IdP x509 certificate'),
                'help' => gettext('PEM certificate (or the bare base64 body) of the IdP signing cert, NOT a fingerprint.'),
                // 'text' so the legacy form renders an input at all; the script
                // field below upgrades it to a multi-line textarea.
                'type' => 'text',
                'validate' => fn($v) => !empty($v) ? [] : [gettext('IdP certificate is required.')],
            ],
            'sso_sp_cert' => [
                'name' => gettext('SP certificate'),
                'help' => gettext('Optional PEM certificate for the SP (only if the IdP requires signed requests).'),
                'type' => 'text',
            ],
            'sso_sp_key' => [
                'name' => gettext('SP private key'),
                'help' => gettext('Optional PEM private key matching the SP certificate.'),
                'type' => 'text',
            ],
            'sso_nameid_format' => [
                'name' => gettext('NameID format'),
                'help' => gettext('Requested NameID format. "persistent" suits most setups; some IdPs need "unspecified" or "emailAddress".'),
                'type' => 'text',
                'default' => $this->ssoNameIdFormat,
            ],
            'sso_groups_attribute' => [
                'name' => gettext('Groups attribute'),
                'help' => gettext('SAML assertion attribute carrying the user\'s groups.'),
                'type' => 'text',
                'default' => $this->ssoGroupsAttribute,
            ],
            'sso_want_messages_signed' => [
                'name' => gettext('Require signed response'),
                'help' => gettext('Require the SAML Response (message) itself to be signed, not only the assertion. Enable when the IdP supports it (mitigates signature-wrapping).'),
                'type' => 'checkbox',
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
                'help' => gettext('Public base URL of this firewall (https://host[:port]) used to build the SP '
                    . 'EntityID, ACS, SLO and metadata URLs. Leave empty to auto-detect from the request Host. '
                    . 'Set it when behind a reverse proxy or port-forward so the signed Destination/ACS match.'),
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
            // The legacy Servers form only renders text/dropdown/checkbox, so this
            // hidden field carries JS that upgrades the cert/key inputs to multi-line
            // textareas (and hides its own row).
            '__sso_saml_script' => [
                'name' => '',
                'help' => '<script>' . $this->formScript() . '</script>',
            ],
        ];
    }

    /** JS that turns the PEM inputs into textareas in the legacy Servers form. */
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
        ta.setAttribute('rows', '6');
        ta.style.width = '100%';
        ta.style.fontFamily = 'monospace';
        el.parentNode.replaceChild(ta, el);
    }
    function showUrls() {
        // Multiple auth types render a [name=sso_base_url]; pick the SAML one.
        var base = document.querySelector('tr.auth_saml [name="sso_base_url"]')
            || document.querySelector('[name="sso_base_url"]');
        if (!base || base._ssoDisp) { return; }
        var box = document.createElement('div');
        box.style.marginTop = '6px';
        function upd() {
            var b = (base.value || (location.protocol + '//' + location.host)).replace(/\/+$/, '');
            box.innerHTML = 'SP ACS URL (give to the IdP):<br><code>' + b + '/api/sso/saml/acs</code><br>'
                + 'SP EntityID / metadata:<br><code>' + b + '/api/sso/saml/metadata</code>';
        }
        base.addEventListener('input', upd);
        upd();
        base.parentNode.appendChild(box);
        base._ssoDisp = 1;
    }
    function apply() {
        ['sso_idp_x509', 'sso_sp_cert', 'sso_sp_key'].forEach(toTextarea);
        showUrls();
        var a = document.getElementById('help_for_field_saml___sso_saml_script');
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
