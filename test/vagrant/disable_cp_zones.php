<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Disable the captive portal zones the SSO suites created, without deleting them.
 *
 * An enabled zone on the LAN interface installs pf rdr rules that intercept http/https
 * on that interface -- the same interface the host-side suites use as their origin
 * (SSO_GUI_URL=https://192.168.60.10). Leaving zones enabled after cp.sh or portal.sh
 * therefore breaks the NEXT run of oidc.sh/saml.sh with a TLS handshake error that looks
 * nothing like a captive portal problem.
 *
 * They are disabled rather than removed so add_cp_zone.php still finds them by
 * description and reuses the same zoneid across runs.
 */

require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\CaptivePortal\CaptivePortal;

$mdl = new CaptivePortal();
$disabled = 0;
foreach ($mdl->zones->zone->iterateItems() as $zone) {
    // Only the suites' own zones: anything else in this VM belongs to whoever made it.
    if (strncmp((string)$zone->description, 'sso-', 4) !== 0) {
        continue;
    }
    if ((string)$zone->enabled === '1') {
        $zone->enabled = '0';
        $disabled++;
    }
}
if ($disabled > 0) {
    $mdl->serializeToConfig();
    Config::getInstance()->save();
}
printf("disabled %d captive portal zone(s)\n", $disabled);
