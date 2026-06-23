<?php

/*
 * Lab helper: sign a test JWT with a PEM private key (RS256), print the token.
 * Env: PRIV (path) JWT_ISS JWT_AUD JWT_SUB JWT_USER JWT_TTL
 */
require_once('/usr/local/opnsense/mvc/app/library/OPNsense/SSO/vendor/autoload.php');

use Firebase\JWT\JWT;

$priv = file_get_contents(getenv('PRIV'));
$now = time();
$payload = [
    'iss' => getenv('JWT_ISS') ?: 'https://idp.test',
    'aud' => getenv('JWT_AUD') ?: 'opnsense',
    'sub' => getenv('JWT_SUB') ?: 'user-123',
    'preferred_username' => getenv('JWT_USER') ?: 'jwtuser',
    'email' => (getenv('JWT_USER') ?: 'jwtuser') . '@idp.test',
    'email_verified' => true,
    'name' => 'JWT Test User',
    'groups' => ['admins'],
    'iat' => $now,
    'nbf' => $now - 5,
    'exp' => $now + (int)(getenv('JWT_TTL') ?: 300),
];
echo JWT::encode($payload, $priv, 'RS256');
