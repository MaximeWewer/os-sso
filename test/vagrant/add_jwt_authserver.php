<?php

/*
 * Lab helper: create/update a JWT forward-auth auth server in config.xml.
 * Env: JWT_NAME JWT_ISS JWT_AUD JWT_TRUSTED JWT_CLAIM JWT_GROUPS JWT_PUBKEY
 * Run as root inside the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;

$name = getenv('JWT_NAME') ?: 'jwttest';
$cfg = Config::getInstance()->object();

$node = null;
foreach ($cfg->system->authserver as $as) {
    if ((string)$as->name === $name) {
        $node = $as;
        break;
    }
}
if ($node === null) {
    $node = $cfg->system->addChild('authserver');
    $node->addChild('refid', uniqid());
    $node->addChild('type', 'jwt');
    $node->addChild('name', $name);
}

$set = function ($k, $v) use ($node) {
    if (isset($node->$k)) {
        $node->$k = $v;
    } else {
        $node->addChild($k, $v);
    }
};

$set('sso_create_users', '1');
$set('sso_default_groups', getenv('JWT_GROUPS') ?: 'admins');
$set('sso_jwt_issuer', getenv('JWT_ISS') ?: 'https://idp.test');
$set('sso_jwt_audience', getenv('JWT_AUD') ?: 'opnsense');
$set('sso_jwt_trusted_proxies', getenv('JWT_TRUSTED') ?: '127.0.0.1');
$set('sso_jwt_algorithms', 'RS256');
$set('sso_username_claim', getenv('JWT_CLAIM') ?: 'preferred_username');
$set('sso_groups_claim', 'groups');
$set('sso_jwt_public_key', getenv('JWT_PUBKEY') ?: '');

Config::getInstance()->save();
echo "jwt authserver '$name' set (trusted=" . (getenv('JWT_TRUSTED') ?: '127.0.0.1') . ")\n";
