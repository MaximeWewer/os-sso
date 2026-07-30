<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Set fields of the os-sso VPN web-auth model and re-render vpn.conf.
 *
 *   set_vpn_settings.php provider=authentik protocol=oidc
 *
 * Goes through the model rather than editing config.xml directly, so validation runs and
 * the generated /usr/local/etc/sso/vpn.conf matches what the GUI would have produced --
 * which is the file auth-user-pass-verify.sh actually reads.
 */

require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\SSO\Settings;

$argvCopy = $argv;
array_shift($argvCopy);
if ($argvCopy === []) {
    fwrite(STDERR, "usage: set_vpn_settings.php key=value [key=value ...]\n");
    exit(1);
}

$model = new Settings();
foreach ($argvCopy as $pair) {
    [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
    if (!isset($model->vpn->$key)) {
        fwrite(STDERR, "unknown vpn setting '$key'\n");
        exit(1);
    }
    $model->vpn->$key = $value;
    echo "vpn.$key=" . ($value === '' ? '(cleared)' : $value) . "\n";
}

$messages = $model->performValidation();
if ($messages->count() > 0) {
    foreach ($messages as $message) {
        fwrite(STDERR, $message->getField() . ': ' . $message->getMessage() . "\n");
    }
    exit(1);
}
$model->serializeToConfig();
OPNsense\Core\Config::getInstance()->save();

// The verify and verdict scripts read the generated file, not config.xml.
echo trim((string)(new Backend())->configdRun('template reload OPNsense/SSO')), "\n";
