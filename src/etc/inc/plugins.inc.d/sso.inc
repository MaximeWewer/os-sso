<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

function sso_configure()
{
	return [
		'bootup' => ['sso_openvpn_bootup'],
		'crl' => ['sso_openvpn_sync:0'],
	];
}


function sso_openvpn_sync(): void
{
	try {
		$result = \OPNsense\SSO\OpenVpnIntegration::synchronize();
		if ($result['changed']) {
			syslog(LOG_NOTICE, 'os-sso: restored managed OpenVPN web-auth directives');
		}
		foreach ($result['errors'] as $error) {
			$detail = str_replace(["\r", "\n"], ' ', $error);
			syslog(LOG_ERR, 'os-sso: OpenVPN integration skipped an invalid selection: ' . $detail);
		}
	} catch (\Throwable $exception) {
		/*
		 * Log, never rethrow. plugins_configure() only catches \Error, so an exception
		 * escaping here kills the whole run: at boot that is rc.bootup, and every
		 * bootup hook after this one (unbound, ...) never runs. The directives already
		 * in config.xml stay as they were, and the config syshook retries on the next
		 * save.
		 */
		syslog(LOG_ERR, 'os-sso: OpenVPN integration failed: ' . $exception->getMessage());
	}
}


function sso_openvpn_bootup(): void
{
	sso_openvpn_sync();
}


function sso_xmlrpc_sync(): array
{
	return [[
		'description' => gettext('Single Sign-On'),
		'help' => gettext(
			'Synchronize os-sso OpenVPN web-auth profiles to the other HA host. '
			. 'Enable Authentication Servers, OpenVPN, Users and Groups, and Certificates separately when used.'
		),
		'section' => 'OPNsense.SSO',
		'id' => 'sso',
		'services' => ['openvpn'],
	]];
}
