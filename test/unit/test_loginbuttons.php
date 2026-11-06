<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * What the WebGUI login page offers. A forward-auth proxy that starts the login itself
 * injects the header on that one request; a click on the page's button arrives without
 * it and can only fail, on the LAN login page as much as behind the proxy. Hiding the
 * button must not close the door it stands for, and must not take anything else along.
 */

use OPNsense\Auth\SSOProviders\SsoProviderContainer;

/** The providers the login page would get, keyed by id, for a set of <authserver> nodes. */
function loginProviders(array $servers): array
{
    $root = new SimpleXMLElement('<opnsense><system/></opnsense>');
    foreach ($servers as $server) {
        $node = $root->system->addChild('authserver');
        foreach ($server as $key => $value) {
            $node->addChild($key, htmlspecialchars($value, ENT_XML1));
        }
    }
    \OPNsense\Core\Config::useTree($root);
    $out = [];
    foreach ((new SsoProviderContainer())->listProviders() as $provider) {
        $out[$provider->id] = $provider;
    }
    return $out;
}

T::group('Login page: a button per WebGUI provider, unless hidden');

$jwt = ['type' => 'jwt', 'name' => 'proxy', 'sso_services' => 'webgui'];

$shown = loginProviders([$jwt]);
truthy(isset($shown['sso-jwt-proxy']), 'a JWT provider gets a button by default (upgrades change nothing)');
truthy(isset($shown['sso-separator']), 'with the separator above it');
eq('/api/sso/jwt/login?provider=proxy', $shown['sso-jwt-proxy']->login_uri, 'pointing at the forward-auth endpoint');

$hidden = loginProviders([$jwt + ['sso_hide_button' => '1']]);
eq([], array_keys($hidden), 'a hidden button leaves nothing on the page, not even a lone separator');

$both = loginProviders([
    $jwt + ['sso_hide_button' => '1'],
    ['type' => 'oidc', 'name' => 'kc', 'sso_services' => 'webgui'],
]);
falsy(isset($both['sso-jwt-proxy']), 'hiding one button');
truthy(isset($both['sso-oidc-kc']), 'keeps the others');
truthy(isset($both['sso-separator']), 'and their separator');

$portal = loginProviders([
    $jwt + ['sso_hide_button' => '1'],
    ['type' => 'oidc', 'name' => 'guest', 'sso_services' => 'portal'],
]);
truthy(isset($portal['sso-cp-oidc-guest']), 'a portal provider is still offered to the portal without any WebGUI button');
falsy(isset($portal['sso-separator']), 'without a separator for an empty WebGUI list');

$portalOnly = loginProviders([['type' => 'oidc', 'name' => 'guest', 'sso_services' => 'portal']]);
eq(['sso-cp-oidc-guest'], array_keys($portalOnly), 'a portal-only setup still reaches the portal');

T::group('Login page: OIDC and SAML buttons can be hidden too');

// Their buttons work when clicked; hiding one is about the page, for a provider users
// reach another way (a direct link, an IdP app launcher, IdP-initiated SAML).
$idps = loginProviders([
    ['type' => 'oidc', 'name' => 'kc', 'sso_services' => 'webgui', 'sso_hide_button' => '1'],
    ['type' => 'saml', 'name' => 'adfs', 'sso_services' => 'webgui,portal', 'sso_hide_button' => '1'],
    ['type' => 'oidc', 'name' => 'entra', 'sso_services' => 'webgui'],
]);
falsy(isset($idps['sso-oidc-kc']), 'a hidden OIDC button is gone');
falsy(isset($idps['sso-saml-adfs']), 'so is a hidden SAML one');
truthy(isset($idps['sso-oidc-entra']), 'the provider left visible keeps its button');
truthy(isset($idps['sso-cp-saml-adfs']), 'and hiding the WebGUI button leaves the portal offer alone');
