<?php

/*
 * Lab helper: print "uid=<n> groups=<g1,g2,...>" for a local user (exit 0), or
 * nothing (exit 1) if absent. Arg: username. Group membership is resolved by uid
 * so tests can assert what the GroupMapper actually granted.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = $argv[1] ?? '';
$cfg = Config::getInstance()->object();

$uid = null;
foreach ($cfg->system->user as $u) {
    if ((string)$u->name === $name) {
        $uid = (string)$u->uid;
        break;
    }
}
if ($uid === null) {
    exit(1);
}

$groups = [];
foreach ($cfg->system->group as $g) {
    foreach (array_filter(explode(',', (string)$g->member)) as $m) {
        if ($m === $uid) {
            $groups[] = (string)$g->name;
        }
    }
}
echo 'uid=' . $uid . ' groups=' . implode(',', $groups) . "\n";
exit(0);
