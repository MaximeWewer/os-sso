#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

require_once('script/load_phalcon.php');

use OPNsense\SSO\OpenVpnIntegration;

try {
	$result = OpenVpnIntegration::synchronize();
	$errors = array_map(
		static fn(string $error): string => str_replace(["\r", "\n"], ' ', $error),
		$result['errors'],
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
}
