<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Print one field of the os-sso VPN web-auth model, so a suite can restore what it found.
 */

require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\SSO\Settings;

$field = $argv[1] ?? '';
if ($field === '') {
    fwrite(STDERR, "usage: dump_vpn_settings.php <field>\n");
    exit(1);
}
$model = new Settings();
echo isset($model->vpn->$field) ? (string)$model->vpn->$field : '', "\n";
