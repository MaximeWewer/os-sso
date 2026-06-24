<?php

/*
 * Lab helper: register an os-sso auth server (OIDC or SAML) in config.xml.
 * Run inside the OPNsense VM as root, e.g.:
 *   AS_TYPE=oidc AS_NAME=keycloak AS_ISSUER=... AS_CLIENT_ID=... AS_CLIENT_SECRET=... \
 *     php /home/vagrant/os-sso/vagrant/add_authserver.php
 *   AS_TYPE=saml AS_NAME=keycloak-saml AS_IDP_ENTITY=... AS_IDP_SSO=... AS_IDP_X509=... \
 *     php /home/vagrant/os-sso/vagrant/add_authserver.php
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$type = getenv('AS_TYPE') ?: 'oidc';
$name = getenv('AS_NAME') ?: $type;

$cfg = Config::getInstance()->object();

foreach ($cfg->system->authserver as $existing) {
    if ((string)$existing->name === $name) {
        fwrite(STDERR, "authserver '$name' already present; leaving as-is\n");
        exit(0);
    }
}

$as = $cfg->system->addChild('authserver');
$as->addChild('refid', uniqid());
$as->addChild('type', $type);
$as->addChild('name', $name);
$as->addChild('sso_create_users', '1');
// AS_DEFAULT_GROUPS may be set to '' to register with no default groups (e.g. to
// exercise the privilege-gated 1:1 group fallback); unset defaults to 'admins'.
$dg = getenv('AS_DEFAULT_GROUPS');
$as->addChild('sso_default_groups', $dg === false ? 'admins' : $dg);
// Optional operator group map ("idpGroup:opnsenseGroup,...") -- trusted, may target
// privileged groups (see GroupMapper::parseMap / the sso_group_map field).
$gm = getenv('AS_GROUP_MAP');
if ($gm !== false && $gm !== '') {
    $as->addChild('sso_group_map', $gm);
}
$as->addChild('sso_button_label', getenv('AS_LABEL') ?: ucfirst($name));

if ($type === 'oidc') {
    $as->addChild('sso_issuer', getenv('AS_ISSUER'));
    $as->addChild('sso_client_id', getenv('AS_CLIENT_ID'));
    $as->addChild('sso_client_secret', getenv('AS_CLIENT_SECRET'));
    $as->addChild('sso_use_pkce', '1');
    $as->addChild('sso_username_claim', getenv('AS_USERNAME_CLAIM') ?: 'preferred_username');
    $as->addChild('sso_groups_claim', 'groups');
    $as->addChild('sso_scopes', 'openid,email,profile');
} else { // saml
    $as->addChild('sso_idp_entity_id', getenv('AS_IDP_ENTITY'));
    $as->addChild('sso_idp_sso_url', getenv('AS_IDP_SSO'));
    $as->addChild('sso_idp_x509', getenv('AS_IDP_X509'));
    $as->addChild('sso_nameid_format', getenv('AS_NAMEID') ?: 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified');
    $as->addChild('sso_groups_attribute', getenv('AS_GROUPS_ATTR') ?: 'groups');
}

Config::getInstance()->save();
echo "added $type authserver '$name'\n";
