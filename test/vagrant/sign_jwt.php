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
    // JWT_IAT_AGE backdates the token so the max-age check can be exercised;
    // JWT_NO_IAT drops the claim entirely (a token of unknown age).
    'iat' => $now - (int)(getenv('JWT_IAT_AGE') ?: 0),
    'nbf' => $now - 5,
    'exp' => $now + (int)(getenv('JWT_TTL') ?: 300),
    // A jti makes the token individually identifiable, which is what the single-use
    // guard keys on. JWT_JTI pins it so a test can replay the very same token.
    'jti' => getenv('JWT_JTI') ?: bin2hex(random_bytes(8)),
];
if (getenv('JWT_NO_IAT') === '1') {
    unset($payload['iat']);
}
echo JWT::encode($payload, $priv, 'RS256');
