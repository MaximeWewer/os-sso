<?php

/*
 * Lab helper: ensure a plain (non-privileged) local group exists and print its gid.
 * Used by the SCIM suite, which needs a group it is actually allowed to fill --
 * os-sso refuses membership writes on anything carrying admin privileges.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = $argv[1] ?? 'vpnusers';
$cfg = Config::getInstance()->object();

foreach ($cfg->system->group as $group) {
    if ((string)$group->name === $name) {
        echo (string)$group->gid;
        exit(0);
    }
}

$gid = (int)($cfg->system->nextgid ?? 2000) + 1;
$group = $cfg->system->addChild('group');
$group->addChild('name', $name);
$group->addChild('description', 'created by the os-sso lab');
$group->addChild('scope', 'local');
$group->addChild('gid', (string)$gid);
$cfg->system->nextgid = (string)$gid;
Config::getInstance()->save();
echo (string)$gid;
