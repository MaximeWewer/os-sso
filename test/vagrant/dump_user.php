<?php

/* Lab helper: print "uid=<n>" if a local user exists, else nothing. Arg: username. */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = $argv[1] ?? '';
foreach (Config::getInstance()->object()->system->user as $u) {
    if ((string)$u->name === $name) {
        echo 'uid=' . (string)$u->uid . ' groups-ok' . "\n";
        exit(0);
    }
}
exit(1);
