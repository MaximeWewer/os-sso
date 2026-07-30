<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Set fields of an os-sso VPN web-auth profile and re-render vpn.conf.
 *
 *   set_vpn_settings.php provider=authentik protocol=oidc
 *   set_vpn_settings.php profile=contractors provider=keycloak host=vpn.example.com
 *
 * Goes through the model rather than editing config.xml directly, so validation runs and
 * the generated /usr/local/etc/sso/vpn.conf matches what the GUI would have produced --
 * which is the file auth-user-pass-verify.sh actually reads. Without a "profile=" the
 * first profile is edited, or one named "default" is created: the lab drives a single
 * VPN and should not have to care.
 */

require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\SSO\Settings;

$argvCopy = $argv;
array_shift($argvCopy);
if ($argvCopy === []) {
    fwrite(STDERR, "usage: set_vpn_settings.php [profile=<name>] key=value [key=value ...]\n");
    exit(1);
}

$fields = [];
foreach ($argvCopy as $pair) {
    [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
    $fields[$key] = $value;
}
$wanted = (string)($fields['profile'] ?? '');
unset($fields['profile']);

$model = new Settings();

/* The profile to edit: the one named, else the first there is, else a fresh "default". */
$profile = null;
foreach ($model->vpn->profiles->profile->iterateItems() as $item) {
    if ($wanted === '' || (string)$item->name === $wanted) {
        $profile = $item;
        break;
    }
}
if ($profile === null) {
    $profile = $model->vpn->profiles->profile->Add();
    $profile->name = $wanted !== '' ? $wanted : 'default';
    $profile->enabled = '1';
    echo "created profile '" . (string)$profile->name . "'\n";
}

foreach ($fields as $key => $value) {
    if (!isset($profile->$key)) {
        fwrite(STDERR, "unknown vpn profile setting '$key'\n");
        exit(1);
    }
    $profile->$key = $value;
    echo (string)$profile->name . ".$key=" . ($value === '' ? '(cleared)' : $value) . "\n";
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
