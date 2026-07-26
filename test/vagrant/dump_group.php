<?php

/* Lab helper: print a group's gid by name. */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = $argv[1] ?? '';
foreach (Config::getInstance()->object()->system->group as $group) {
    if (strcasecmp((string)$group->name, $name) === 0) {
        echo (string)$group->gid;
        exit(0);
    }
}
fwrite(STDERR, "group '$name' not found\n");
exit(1);
