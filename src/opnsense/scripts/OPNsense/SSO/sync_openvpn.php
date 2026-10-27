#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('script/load_phalcon.php');
require_once('util.inc');

use OPNsense\SSO\OpenVpnIntegration;
use OPNsense\SSO\OpenVpnRuntime;
use OPNsense\SSO\StateDir;

$runtimeLock = null;
try {
	if (in_array('--repair-running', $argv, true)) {
		// Serialize overlapping configuration events without holding the core
		// config.xml lock while configd regenerates/restarts OpenVPN.
		$runtimeLock = @fopen(StateDir::path('run') . '/openvpn-runtime.lock', 'c'); // @ - report a controlled error below
		if ($runtimeLock === false || !flock($runtimeLock, LOCK_EX)) {
			throw new RuntimeException('could not lock OpenVPN runtime repair');
		}
	}
	$result = OpenVpnIntegration::synchronize();
	$runtime = ['restarted' => [], 'errors' => []];
	if (in_array('--repair-running', $argv, true)) {
		// A previous event may already have repaired config.xml. Always inspect
		// generated files, even when this reconciliation reports changed=0.
		$runtime = (new OpenVpnRuntime())->repair($result['instances']);
		foreach ($runtime['restarted'] as $uuid) {
			syslog(LOG_NOTICE, 'os-sso: restarted OpenVPN instance missing the managed verifier: ' . $uuid);
		}
	}
	$errors = array_map(
		static fn(string $error): string => str_replace(["\r", "\n"], ' ', $error),
		array_merge($result['errors'], $runtime['errors']),
	);
	printf(
		"%s: changed=%d managed=%d%s\n",
		$errors === [] ? 'OK' : 'PARTIAL',
		$result['changed'] ? 1 : 0,
		count($result['instances']),
		$errors === [] ? '' : '; ' . implode(' | ', $errors),
	);
} catch (Throwable $exception) {
	syslog(LOG_ERR, 'os-sso: OpenVPN integration failed: ' . $exception->getMessage());
	fwrite(STDERR, 'ERROR: ' . $exception->getMessage() . "\n");
	exit(1);
} finally {
	if (is_resource($runtimeLock)) {
		flock($runtimeLock, LOCK_UN);
		fclose($runtimeLock);
	}
}
