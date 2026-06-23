<?php

/*
 * Lab helper: create (once) a Captive Portal zone bound to an SSO provider, print
 * its zoneid. Env: CP_DESC CP_AUTH CP_ENFORCE
 * Run as root in the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\CaptivePortal\CaptivePortal;

$desc = getenv('CP_DESC') ?: 'sso-cp-test';
$mdl = new CaptivePortal();

foreach ($mdl->zones->zone->iterateItems() as $z) {
    if ((string)$z->description === $desc) {
        echo (string)$z->zoneid;
        exit(0);
    }
}

$zone = $mdl->zones->zone->Add();
$zone->enabled = '1';
$zone->description = $desc;
$zone->authservers = getenv('CP_AUTH') ?: 'keycloak';
if (getenv('CP_ENFORCE')) {
    // AuthGroupField stores the gid -- resolve the given group NAME to its gid.
    $gname = getenv('CP_ENFORCE');
    foreach (Config::getInstance()->object()->system->group as $g) {
        if (strcasecmp((string)$g->name, $gname) === 0) {
            $zone->authEnforceGroup = (string)$g->gid;
            break;
        }
    }
}
$mdl->serializeToConfig();
Config::getInstance()->save();

// zoneid is auto-assigned on serialize.
echo (string)$zone->zoneid;
