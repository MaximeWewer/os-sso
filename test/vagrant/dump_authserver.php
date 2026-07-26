<?php

/*
 * Lab helper: print one field of an auth server, so a test can save a value before
 * changing it and put it back afterwards.
 *   php dump_authserver.php keycloak-saml sso_idp_entity_id
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = $argv[1] ?? '';
$field = $argv[2] ?? '';
if ($name === '' || $field === '') {
    fwrite(STDERR, "usage: dump_authserver.php <name> <field>\n");
    exit(1);
}

foreach (Config::getInstance()->object()->system->authserver as $server) {
    if ((string)$server->name === $name) {
        echo (string)($server->$field ?? '') . "\n";
        exit(0);
    }
}
fwrite(STDERR, "authserver '$name' not found\n");
exit(1);
