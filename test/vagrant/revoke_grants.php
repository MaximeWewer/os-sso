<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * End the accesses os-sso recorded, by kind.
 *
 *   revoke_grants.php portal        # disconnect captive-portal clients
 *   revoke_grants.php vpn           # kill the tunnels
 *   revoke_grants.php               # everything
 *
 * The same call every revocation path makes (back-channel logout, SAML SLO, a SCIM
 * deactivation, the diagnostics button), so the suites can drive it without an IdP
 * round-trip. Prints how many accesses were ended.
 */

require_once('config.inc');
require_once('util.inc');

use OPNsense\SSO\SessionRegistry;

$kind = strtolower(trim((string)($argv[1] ?? '')));
$ended = SessionRegistry::destroyWhere(
    fn(array $entry) => $kind === '' || (string)($entry['kind'] ?? 'webgui') === $kind
);
echo $ended, "\n";
