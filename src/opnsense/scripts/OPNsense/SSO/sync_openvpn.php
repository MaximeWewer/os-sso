#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('script/load_phalcon.php');

use OPNsense\SSO\OpenVpnIntegration;

if (($argv[1] ?? '') === '--stop-managed') {
	// @ - the manifest is absent before the first managed profile is applied.
	$manifest = json_decode((string)@file_get_contents(OpenVpnIntegration::MANIFEST), true);
	$instances = is_array($manifest['instances'] ?? null) ? $manifest['instances'] : [];
	$backend = new OPNsense\Core\Backend();
	foreach (array_keys($instances) as $uuid) {
		if (is_string($uuid) && preg_match('/^[0-9a-f-]{36}$/D', $uuid) === 1) {
			$backend->configdpRun('openvpn stop', [$uuid]);
			printf("stopped managed OpenVPN instance %s\n", $uuid);
		}
	}
	exit(0);
}

try {
	$result = OpenVpnIntegration::synchronize();
	printf(
		"OK: %d managed OpenVPN instance(s)%s\n",
		count($result['instances']),
		$result['changed'] ? ', config updated' : '',
	);
} catch (Throwable $exception) {
	syslog(LOG_ERR, 'os-sso: OpenVPN integration failed: ' . $exception->getMessage());
	fwrite(STDERR, 'ERROR: ' . $exception->getMessage() . "\n");
	exit(1);
}
