<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Set authserver fields from a JSON object, for values the key=value helper
 * (set_authserver.php) cannot carry through a shell: JSON, PEM blocks.
 *
 *   php set_authserver_json.php <name> '{"sso_claims_request": "{...}"}'
 *   php set_authserver_json.php <name> b64:<base64 of the same>   (through nested quoting)
 *
 * An empty string removes the field. Run as root inside the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = (string)($argv[1] ?? '');
$arg = (string)($argv[2] ?? '');
$fields = json_decode(str_starts_with($arg, 'b64:') ? (string)base64_decode(substr($arg, 4)) : $arg, true);
if ($name === '' || !is_array($fields)) {
    fwrite(STDERR, "usage: set_authserver_json.php <name> '<json object>'\n");
    exit(1);
}
$cfg = Config::getInstance()->object();
foreach ($cfg->system->authserver as $as) {
    if ((string)$as->name !== $name) {
        continue;
    }
    foreach ($fields as $field => $value) {
        unset($as->$field);
        if ((string)$value !== '') {
            $as->addChild($field, htmlspecialchars((string)$value, ENT_XML1));
        }
    }
    Config::getInstance()->save();
    echo "updated $name\n";
    exit(0);
}
fwrite(STDERR, "no authserver '$name'\n");
exit(1);
