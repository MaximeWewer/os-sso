<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\Api\DiagnosticsController;
use OPNsense\SSO\Protocol\OidcProtocol;

require_once dirname(__DIR__, 2) . '/src/opnsense/mvc/app/controllers/OPNsense/SSO/Api/DiagnosticsController.php';

T::group('Provider diagnostics: register the URL used by OIDC logout');

$diagnostics = new DiagnosticsController();
$urlsFor = new ReflectionMethod($diagnostics, 'urlsFor');
$urls = $urlsFor->invoke($diagnostics, 'oidc', 'https://firewall.example', 'idp');
eq('https://firewall.example/api/sso/oidc/loggedout', $urls['Post-logout redirect'], 'diagnostics reports the signed-out page instead of the WebGUI root');
$protocol = new OidcProtocol(['issuer' => 'https://idp.example', 'client_id' => 'firewall']);
$discovery = new ReflectionProperty($protocol, 'discovery');
$discovery->setValue($protocol, ['end_session_endpoint' => 'https://idp.example/logout']);
$logoutUrl = $protocol->buildLogoutUrl('id-token-hint', 'https://firewall.example' . OidcProtocol::POST_LOGOUT_PATH);
parse_str((string)parse_url($logoutUrl, PHP_URL_QUERY), $logoutParameters);
eq($urls['Post-logout redirect'], $logoutParameters['post_logout_redirect_uri'], 'the documented IdP registration matches the actual logout request');
