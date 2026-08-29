<?php

/*
 * Lab helper: create (once) a Captive Portal zone bound to an SSO provider, print
 * its zoneid. Env: CP_DESC CP_AUTH CP_ENFORCE
 * Run as root in the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\CaptivePortal\CaptivePortal;

$desc = getenv('CP_DESC') ?: 'sso-cp-test';
$mdl = new CaptivePortal();

// Reuse the zone of that description if it is already here -- but re-enable it rather
// than hand it back as found: the suites disable their zones on the way out (a live
// zone installs pf rdr rules that hijack http/https on the LAN and break the NEXT
// run), so the one waiting here is a disabled one, and a disabled zone authorizes
// nobody.
$zone = null;
foreach ($mdl->zones->zone->iterateItems() as $z) {
    if ((string)$z->description === $desc) {
        $zone = $z;
        break;
    }
}
if ($zone === null) {
    $zone = $mdl->zones->zone->Add();
}
$zone->enabled = '1';
// A zone with no interface is not served at all: the template then renders
// captiveportal_enable="NO", the service never starts, its cp_clients table is never
// created, and core's allow.py dies on "no such table" -- which reaches the caller as
// a bare "captive portal authorization failed".
$zone->interfaces = getenv('CP_INTERFACE') ?: 'lan';
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

// Make the zone real, not just present in config.xml. Two steps, in this order, and
// neither is optional:
//   1. render the templates -- this is what writes captiveportal_enable=YES into
//      rc.conf.d plus the zone's own ini. Without it the service refuses to start;
//   2. start the service -- which is what creates the cp_clients table. Skip it and
//      core's own allow.py dies on "no such table: cp_clients", surfacing here as a
//      bare "captive portal authorization failed".
// Writing config.xml directly (which is what this helper does) is exactly the path
// that skips both, so the helper owes its callers the rest -- portal.sh only ever
// worked when cp.sh had happened to run first and done it by hand.
$backend = new Backend();
$backend->configdRun('template reload OPNsense/Captiveportal');
$backend->configdRun('captiveportal start');

// zoneid is auto-assigned on serialize.
echo (string)$zone->zoneid;
