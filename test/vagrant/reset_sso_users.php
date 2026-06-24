<?php

/*
 * Lab helper: remove SSO-provisioned test users and strip their group memberships,
 * so the binding/group suites run against a clean config. Needed because os-sso now
 * refuses to (re)bind the username claim to a pre-existing privileged/password
 * account -- stale accounts left by a previous run would otherwise block re-runs.
 *
 * Env RESET_USERS overrides the default name list (comma separated).
 * Run as root inside the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$names = array_filter(array_map('trim', explode(',', getenv('RESET_USERS')
    ?: 'jwtuser,grpprobe,kctest,cptester,akadmin')));
$cfg = Config::getInstance()->object();

$uids = [];
for ($i = count($cfg->system->user) - 1; $i >= 0; $i--) {
    $u = $cfg->system->user[$i];
    if (in_array((string)$u->name, $names, true)) {
        $uids[(string)$u->uid] = true;
        unset($cfg->system->user[$i]);
    }
}
foreach ($cfg->system->group as $g) {
    $keep = array_values(array_filter(
        array_filter(explode(',', (string)$g->member)),
        fn($m) => !isset($uids[$m])
    ));
    unset($g->member);
    if ($keep) {
        $g->addChild('member', implode(',', $keep));
    }
}
Config::getInstance()->save();
echo 'reset users: ' . (empty($uids) ? '(none)' : implode(',', array_keys($uids))) . "\n";
