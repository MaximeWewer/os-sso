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
    public $ssoIdpMetadataUrl = null;
    public $ssoIdpEntityId = null;
    public $ssoIdpSsoUrl = null;
    public $ssoIdpSloUrl = null;
    public $ssoIdpX509 = null;
    public $ssoSpCert = null;
    public $ssoSpKey = null;
    public $ssoNameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    public $ssoGroupsAttribute = 'groups';
    public $ssoUsernameAttribute = null;
    public $ssoEmailAttribute = null;
    public $ssoDisplayNameAttribute = null;
    public $ssoWantMessagesSigned = false;
    public $ssoAllowSha1 = false;
    public $ssoAuthnPostBinding = false;
    public $ssoAuthnRequestsSigned = false;
    public $ssoForceAuthn = false;
    public $ssoRequiredAcr = [];
    public $ssoMaxAge = 0;
    public $ssoAllowIdpInitiated = false;
    public $ssoWantAssertionsEncrypted = false;
    public $ssoWantNameIdEncrypted = false;
    public $ssoSessionLifetime = 0;
    public $ssoScimEnabled = false;
    public $ssoScimToken = null;
    public $ssoScimTrusted = [];
    public $ssoServices = [];
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
        return 'saml';
    }

    public function getDescription()
    {
        return "<i class='fa fa-id-card fa-fw'></i> " . gettext('SAML 2.0');
    }

    public function setProperties($config)
    {
        $map = [
            'sso_idp_metadata_url' => 'ssoIdpMetadataUrl',
            'sso_idp_entity_id' => 'ssoIdpEntityId',
            'sso_idp_sso_url' => 'ssoIdpSsoUrl',
            'sso_idp_slo_url' => 'ssoIdpSloUrl',
            'sso_idp_x509' => 'ssoIdpX509',
            'sso_sp_cert' => 'ssoSpCert',
            'sso_sp_key' => 'ssoSpKey',
            'sso_nameid_format' => 'ssoNameIdFormat',
            'sso_groups_attribute' => 'ssoGroupsAttribute',
            'sso_username_attribute' => 'ssoUsernameAttribute',
            'sso_email_attribute' => 'ssoEmailAttribute',
            'sso_display_name_attribute' => 'ssoDisplayNameAttribute',
            'sso_button_label' => 'ssoButtonLabel',
            'sso_base_url' => 'ssoBaseUrl',
            'sso_login_redirect' => 'ssoLoginRedirect',
            'sso_group_map' => 'ssoGroupMap',
            'sso_scim_token' => 'ssoScimToken',
        ];
        foreach ($map as $k => $prop) {
            if (!empty($config[$k]) && property_exists($this, $prop)) {
                $this->$prop = $config[$k];
            }
        }
        $this->ssoServices = \OPNsense\SSO\ServiceScope::parse($config['sso_services'] ?? '');
        $this->ssoCreateUsers = !empty($config['sso_create_users']);
        $this->ssoScimEnabled = !empty($config['sso_scim_enabled']);
        $this->ssoScimTrusted = array_filter(array_map('trim', explode(',', $config['sso_scim_trusted'] ?? '')));
        $this->ssoDeprovision = !empty($config['sso_deprovision']);
        if (isset($config['sso_session_lifetime']) && $config['sso_session_lifetime'] !== '') {
            $this->ssoSessionLifetime = (int)$config['sso_session_lifetime'];
        }
        $this->ssoGroupSync = !empty($config['sso_group_sync']);
        $this->ssoWantMessagesSigned = !empty($config['sso_want_messages_signed']);
        $this->ssoAllowSha1 = !empty($config['sso_allow_sha1']);
        $this->ssoAuthnPostBinding = !empty($config['sso_authn_post_binding']);
        $this->ssoAuthnRequestsSigned = !empty($config['sso_authn_requests_signed']);
        $this->ssoForceAuthn = !empty($config['sso_force_authn']);
        $this->ssoRequiredAcr = array_filter(array_map('trim', explode(',', $config['sso_required_acr'] ?? '')));
        if (isset($config['sso_max_age']) && $config['sso_max_age'] !== '') {
            $this->ssoMaxAge = (int)$config['sso_max_age'];
        }
        $this->ssoAllowIdpInitiated = !empty($config['sso_allow_idp_initiated']);
        $this->ssoWantAssertionsEncrypted = !empty($config['sso_want_assertions_encrypted']);
        $this->ssoWantNameIdEncrypted = !empty($config['sso_want_nameid_encrypted']);
        $this->ssoRequiredGroups = array_filter(array_map('trim', explode(',', $config['sso_required_groups'] ?? '')));
        $this->ssoDefaultGroups = array_filter(array_map('trim', explode(',', $config['sso_default_groups'] ?? '')));
    }

    public function getConfigurationOptions()
    {
        $base = trim((string)$this->ssoBaseUrl) !== '' ? rtrim((string)$this->ssoBaseUrl, '/') : 'https://{opnsense}';
        $b = htmlspecialchars($base);
        // Every SP endpoint carries ?provider=<server name>: each SAML server is its
        // own SP identity, so two IdPs never share an EntityID/ACS.
        $acs = gettext('SP ACS URL is') . ' <code>' . $b . '/api/sso/saml/acs?provider={name}</code>, ' .
            gettext('metadata at') . ' <code>' . $b . '/api/sso/saml/metadata?provider={name}</code> ' .
            gettext('({name} = this server\'s name; the live URLs are shown under Base URL).');
        return [
            'sso_idp_metadata_url' => [
                'name' => gettext('IdP metadata URL'),
                'help' => gettext('Optional https URL of the IdP SAML metadata document. When set, the '
                    . 'EntityID, SSO/SLO endpoints and signing certificate below may be left empty and are '
                    . 'read from it (cached 24h) -- which also means an IdP signing-key rotation is picked '
                    . 'up on its own. Anything you fill in by hand wins over the document.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || (filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0)
                    ? [] : [gettext('Metadata URL must be a valid https URL.')],
            ],
            'sso_idp_entity_id' => [
                'name' => gettext('IdP EntityID'),
                'help' => $acs . ' ' . gettext('Required unless an IdP metadata URL is set above.'),
                'type' => 'text',
            ],
            'sso_idp_sso_url' => [
                'name' => gettext('IdP SSO URL'),
                'help' => gettext('IdP Single Sign-On endpoint (HTTP-Redirect binding). '
                    . 'Required unless an IdP metadata URL is set.'),
                'type' => 'text',
                'validate' => fn($v) => empty($v) || (filter_var($v, FILTER_VALIDATE_URL) && stripos($v, 'https://') === 0)
                    ? [] : [gettext('SSO URL must be a valid https URL.')],
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
                'help' => gettext('PEM certificate (or the bare base64 body) of the IdP signing cert, NOT a '
                    . 'fingerprint. Required unless an IdP metadata URL is set; pinning one here also stops '
                    . 'the metadata document from rotating it.'),
                // 'text' so the legacy form renders an input at all; the script
                // field below upgrades it to a multi-line textarea.
                'type' => 'text',
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
            'sso_username_attribute' => [
                'name' => gettext('Username attribute'),
                'help' => gettext('Assertion attribute mapped to the local username. Leave empty to try '
                    . '"uid", "username", "preferred_username" and then fall back to the NameID. Set it when '
                    . 'the IdP emits OID-style names (e.g. urn:oid:0.9.2342.19200300.100.1.1) or its own.'),
                'type' => 'text',
            ],
            'sso_email_attribute' => [
                'name' => gettext('Email attribute'),
                'help' => gettext('Assertion attribute carrying the email. Empty tries "email" then "mail".'),
                'type' => 'text',
            ],
            'sso_display_name_attribute' => [
                'name' => gettext('Display name attribute'),
                'help' => gettext('Assertion attribute carrying the full name. Empty tries "displayName", '
                    . '"cn" then "name".'),
                'type' => 'text',
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
            'sso_allow_sha1' => [
                'name' => gettext('Accept SHA-1 signatures'),
                'help' => gettext('Legacy escape hatch. By default an assertion signed - or digested - with '
                    . 'SHA-1 (or MD5, or RIPEMD-160) is refused: the certificate may be the right one, but a '
                    . 'signature over a broken hash proves the IdP signed some document, not this one. Tick '
                    . 'this only for an IdP that cannot be reconfigured for RSA-SHA256 yet, and untick it '
                    . 'once it can.'),
                'type' => 'checkbox',
            ],
            'sso_force_authn' => [
                'name' => gettext('Force re-authentication'),
                'help' => gettext('Send ForceAuthn, asking the IdP to authenticate the user again instead '
                    . 'of silently reusing its existing session. Combine with the maximum authentication '
                    . 'age below, which checks the IdP actually did: ForceAuthn is only a request.'),
                'type' => 'checkbox',
            ],
            'sso_max_age' => [
                'name' => gettext('Maximum authentication age (s)'),
                'help' => gettext('Refuse the login when the assertion says the user authenticated at the '
                    . 'IdP longer ago than this (its AuthnInstant). The SAML counterpart of the OIDC '
                    . 'max_age check. An assertion with no AuthnInstant is refused rather than trusted. '
                    . '0 disables it (any session age is accepted).'),
                'type' => 'text',
                'default' => '0',
                'validate' => fn($v) => ($v === '' || ctype_digit((string)$v))
                    ? [] : [gettext('Maximum authentication age must be a number of seconds (0 = disabled).')],
            ],
            'sso_required_acr' => [
                'name' => gettext('Required authentication context'),
                'help' => gettext('Comma separated AuthnContextClassRef values, typically the one your IdP '
                    . 'uses for MFA (e.g. urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor or an IdP '
                    . 'specific one). They are sent as a RequestedAuthnContext AND the '
                    . 'AuthnContextClassRef that comes back must be one of them - both halves matter, '
                    . 'because honouring the request is voluntary, so only the answer proves anything. An '
                    . 'assertion carrying no context at all is refused rather than trusted. Empty accepts '
                    . 'whatever context the IdP used. The SAML counterpart of the OIDC acr check.'),
                'type' => 'text',
            ],
            'sso_authn_requests_signed' => [
                'name' => gettext('Sign the AuthnRequest'),
                'help' => gettext('Sign the login request we send, and declare it in the SP metadata. '
                    . 'Needs the SP certificate and private key below. Required by some IdPs (ADFS in a '
                    . 'strict configuration, Keycloak with "Client signature required"); harmless '
                    . 'otherwise, since the IdP learns our signing certificate from the same metadata.'),
                'type' => 'checkbox',
            ],
            'sso_authn_post_binding' => [
                'name' => gettext('Send AuthnRequest by HTTP-POST'),
                'help' => gettext('Deliver the login request in a self-submitting form instead of a redirect. '
                    . 'Enable when the IdP only accepts the HTTP-POST binding, and point the IdP SSO URL above '
                    . 'at its POST endpoint.'),
                'type' => 'checkbox',
            ],
            'sso_allow_idp_initiated' => [
                'name' => gettext('Allow IdP-initiated login'),
                'help' => gettext('Accept an assertion that answers no request of ours (the "launch from the '
                    . 'IdP dashboard" flow), posted to this server\'s own ACS URL. Off by default and worth '
                    . 'keeping off: an unsolicited assertion carries no proof the browser receiving it asked '
                    . 'to log in, so anyone who can obtain one can silently sign a visitor in as that account. '
                    . 'Signature, audience, expiry and single-use replay checks all still apply.'),
                'type' => 'checkbox',
            ],
            'sso_want_assertions_encrypted' => [
                'name' => gettext('Require encrypted assertions'),
                'help' => gettext('Require the IdP to encrypt the assertion to the SP certificate. Needs an '
                    . 'SP certificate and private key above, and the IdP configured to encrypt. Decryption '
                    . 'works whenever the SP key is set; this makes an unencrypted assertion a failure.'),
                'type' => 'checkbox',
            ],
            'sso_want_nameid_encrypted' => [
                'name' => gettext('Require encrypted NameID'),
                'help' => gettext('Same, for the NameID element alone.'),
                'type' => 'checkbox',
            ],
            'sso_session_lifetime' => [
                'name' => gettext('Maximum session lifetime (s)'),
                'help' => gettext('End the WebGUI session this long after login whatever the user is doing, '
                    . 'unlike the idle timeout. Enforced by the scheduled "os-sso: expire SSO sessions" job '
                    . '(added for you under System > Settings > Cron) and on every SSO login. 0 keeps sessions '
                    . 'until they idle out.'),
                'type' => 'text',
                'default' => '0',
                'validate' => fn($v) => ($v === '' || ctype_digit((string)$v))
                    ? [] : [gettext('Maximum session lifetime must be a number of seconds (0 = disabled).')],
            ],
            'sso_services' => [
                'name' => gettext('Applies to'),
                'help' => gettext('Where this provider may be used, comma separated: "webgui", "portal" '
                    . '(captive portal), "vpn". Empty means all three, which is what it was before this '
                    . 'setting existed. It matters because every provider otherwise puts a button on the '
                    . 'firewall login page: a provider added for guest wifi, or for the VPN, is also a '
                    . 'WebGUI door - and one left without required groups because the portal zone does its '
                    . 'own group check then admits the whole directory to the WebGUI.'),
                'type' => 'text',
                'validate' => fn($v) => empty(\OPNsense\SSO\ServiceScope::unknown((string)$v))
                    ? [] : [gettext('Applies to accepts only: ') . join(', ', \OPNsense\SSO\ServiceScope::SERVICES)],
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
                'help' => gettext('Public base URL of this firewall (https://host[:port]) used to build the SP '
                    . 'EntityID, ACS, SLO and metadata URLs. Required: without it those URLs are derived from '
                    . 'the request Host header, which the client controls. Set it to the public URL the IdP '
                    . 'reaches (mind a reverse proxy or port-forward) so the signed Destination/ACS match.'),
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
        // Each SAML server is its own SP: the endpoints carry ?provider=<name>.
        var nameEl = document.querySelector('tr.auth_saml [name="name"]')
            || document.querySelector('[name="name"]');
        function upd() {
            var b = (base.value || (location.protocol + '//' + location.host)).replace(/\/+$/, '');
            var q = '?provider=' + encodeURIComponent((nameEl && nameEl.value) || '{name}');
            box.innerHTML = 'SP ACS URL (give to the IdP):<br><code>' + b + '/api/sso/saml/acs' + q + '</code><br>'
                + 'SP EntityID / metadata:<br><code>' + b + '/api/sso/saml/metadata' + q + '</code><br>'
                + 'SP SLO URL:<br><code>' + b + '/api/sso/saml/slo' + q + '</code>';
        }
        base.addEventListener('input', upd);
        if (nameEl) { nameEl.addEventListener('input', upd); }
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
