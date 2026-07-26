<?php

/*
 * Lab helper: set (or clear) fields on an existing os-sso auth server.
 * Run inside the OPNsense VM as root:
 *   php set_authserver.php keycloak sso_required_groups=ops sso_deprovision=1
 * An empty value clears the field, which is how a test case resets what the
 * previous one set -- otherwise cases silently inherit each other's state.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$argvCopy = $argv;
array_shift($argvCopy);
$name = array_shift($argvCopy);
if ($name === null) {
    fwrite(STDERR, "usage: set_authserver.php <name> key=value [key=value ...]\n");
    exit(1);
}

$cfg = Config::getInstance()->object();
$node = null;
foreach ($cfg->system->authserver as $server) {
    if ((string)$server->name === $name) {
        $node = $server;
        break;
    }
}
if ($node === null) {
    fwrite(STDERR, "authserver '$name' not found\n");
    exit(1);
}

foreach ($argvCopy as $pair) {
    [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
    if (isset($node->$key)) {
        $node->$key = $value;
    } else {
        $node->addChild($key, $value);
    }
    echo "$name.$key=" . ($value === '' ? '(cleared)' : $value) . "\n";
}

Config::getInstance()->save();
