<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use OPNsense\SSO\JwkSet;
use OPNsense\SSO\Protocol\JwtProtocol;
use OPNsense\SSO\Protocol\OidcProtocol;

T::group('JWK algorithms: discovery order does not select the token signature');

$signingKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($signingKey, $signingPem);
$signingDetails = openssl_pkey_get_details($signingKey);
$encodeUrl = fn(string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$rawKeys = ['keys' => [[
	'kty' => 'RSA', 'use' => 'sig', 'kid' => 'algorithm-test',
	'n' => $encodeUrl($signingDetails['rsa']['n']),
	'e' => $encodeUrl($signingDetails['rsa']['e']),
]]];
$tokenClaims = [
	'iss' => 'https://idp.example', 'aud' => 'firewall', 'sub' => 'alice-sub',
	'preferred_username' => 'alice', 'iat' => time(), 'exp' => time() + 60, 'nonce' => 'test-nonce',
];
foreach (['RS256', 'RS512'] as $algorithm) {
	$signedToken = JWT::encode($tokenClaims, $signingPem, $algorithm, 'algorithm-test');
	foreach ([['RS256', 'RS512'], ['RS512', 'RS256']] as $allowed) {
		$parsedKeys = JwkSet::parse($rawKeys, $allowed, $signedToken);
		eq($algorithm, $parsedKeys['algorithm-test']->getAlgorithm(), 'the key follows ' . $algorithm . ' with ' . implode(',', $allowed));
		eq('alice-sub', JWT::decode($signedToken, $parsedKeys)->sub, 'the signed token verifies');
		$proxy = new JwtProtocol([
			'issuer' => 'https://idp.example', 'audience' => 'firewall',
			'public_key' => $signingDetails['key'], 'algorithms' => $allowed,
		]);
		eq('alice', $proxy->verify($signedToken)->username, 'static-key forward auth accepts an allowed algorithm regardless of list order');
	}
}

$rsToken = JWT::encode($tokenClaims, $signingPem, 'RS256', 'algorithm-test');
throws(fn() => JwkSet::parse($rawKeys, ['RS512'], $rsToken), 'not allowed', 'the token cannot select an algorithm outside the allowlist');
$explicitKeys = $rawKeys;
$explicitKeys['keys'][0]['alg'] = 'RS512';
throws(fn() => JWT::decode($rsToken, JwkSet::parse($explicitKeys, ['RS256', 'RS512'], $rsToken)), 'Incorrect key', 'an explicit key algorithm is never overwritten by the token');
$hmacToken = JWT::encode($tokenClaims, str_repeat('a', 32), 'HS256', 'algorithm-test');
throws(fn() => JwkSet::parse($rawKeys, [], $hmacToken), 'not allowed', 'an HMAC header cannot turn an RSA public key into a shared secret');
throws(fn() => JwkSet::algorithm('malformed', []), 'not allowed', 'a malformed token is refused');
$restrictedProxy = new JwtProtocol([
	'issuer' => 'https://idp.example', 'audience' => 'firewall',
	'public_key' => $signingDetails['key'], 'algorithms' => ['RS512'],
]);
throws(fn() => $restrictedProxy->verify($rsToken), 'not allowed', 'the forward-auth allowlist is enforced for static keys too');
$parts = explode('.', $rsToken);
$parts[0] = $encodeUrl(json_encode(['typ' => 'JWT', 'alg' => 'RS512', 'kid' => 'algorithm-test']));
$tamperedToken = implode('.', $parts);
throws(fn() => JWT::decode($tamperedToken, JwkSet::parse($rawKeys, ['RS256', 'RS512'], $tamperedToken)), 'Signature verification failed', 'changing the header does not bypass cryptographic verification');

T::group('JWK algorithms: OIDC ID tokens and signed UserInfo');
if (!stateDirUsable()) {
	T::skip('OIDC cached-key signature integration', 'state directory unavailable');
} else {
	$oidc = new OidcProtocol(['issuer' => 'https://idp.example', 'client_id' => 'firewall']);
	$cache = new ReflectionMethod($oidc, 'cacheSet');
	$cache->invoke($oidc, 'jwks_https://idp.example/algorithm-test', $rawKeys);
	$discovery = [
		'issuer' => 'https://idp.example', 'jwks_uri' => 'https://idp.example/algorithm-test',
		'id_token_signing_alg_values_supported' => ['RS512', 'RS256'],
		'userinfo_signing_alg_values_supported' => ['RS512'],
	];
	$validateToken = new ReflectionMethod($oidc, 'validateIdToken');
	eq('alice-sub', $validateToken->invoke($oidc, $discovery, $rsToken, 'test-nonce')->sub, 'the OIDC token path uses the token algorithm');
	$userInfoToken = JWT::encode($tokenClaims, $signingPem, 'RS512', 'algorithm-test');
	$discovery['id_token_signing_alg_values_supported'] = ['RS256'];
	$decodeUserInfo = new ReflectionMethod($oidc, 'decodeSignedUserinfo');
	eq('alice-sub', $decodeUserInfo->invoke($oidc, $discovery, $userInfoToken)['sub'], 'signed UserInfo uses its own advertised algorithms');
}
