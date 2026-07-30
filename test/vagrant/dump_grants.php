<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * List the accesses os-sso recorded, one per line:
 *
 *   <kind> <username> <cp_session|-> <vpn_cn|->
 *
 * What the diagnostics page shows, without a session: the suites use it to find the
 * handle of the access they just created and then check it really went away.
 */

require_once('config.inc');
require_once('util.inc');

use OPNsense\SSO\SessionRegistry;

$kind = strtolower(trim((string)($argv[1] ?? '')));
foreach (SessionRegistry::listActive() as $entry) {
    $entryKind = (string)($entry['kind'] ?? 'webgui');
    if ($kind !== '' && $entryKind !== $kind) {
        continue;
    }
    printf(
        "%s %s %s %s\n",
        $entryKind,
        (string)($entry['username'] ?? '-') ?: '-',
        (string)($entry['cp_session'] ?? '-') ?: '-',
        (string)($entry['vpn_cn'] ?? '-') ?: '-'
    );
}
