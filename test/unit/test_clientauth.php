<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use OPNsense\SSO\ClientAuth;

$disco = [
    'issuer' => 'https://idp.example',
    'token_endpoint' => 'https://idp.example/token',
    'token_endpoint_auth_methods_supported' => ['client_secret_post', 'private_key_jwt'],
    'mtls_endpoint_aliases' => ['token_endpoint' => 'https://mtls.idp.example/token'],
];
$secret = str_repeat('s', 40);

$rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($rsa, $rsaPem);
$rsaPub = openssl_pkey_get_details($rsa)['key'];

/** Run apply() and hand back what it produced. */
function applied(array $cfg, string $method, array $disco): array
{
    $body = [];
    $headers = [];
    $options = [];
    (new ClientAuth($cfg))->apply($disco, $method, $body, $headers, $options);
    return ['body' => $body, 'headers' => $headers, 'options' => $options];
}

T::group('ClientAuth: auto only ever negotiates the secret methods');

$auto = new ClientAuth(['client_id' => 'cid', 'client_secret' => $secret]);
// The discovery document advertises private_key_jwt; auto must not silently pick it,
// because the key it would need is not registered at the IdP yet.
eq(ClientAuth::POST, $auto->method($disco), 'post is chosen when basic is not advertised');
eq(
    ClientAuth::BASIC,
    $auto->method(['token_endpoint' => 'x']),
    'basic is the default when nothing is advertised'
);
eq(
    ClientAuth::BASIC,
    $auto->method(['token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post']]),
    'basic wins when both are advertised'
);
eq(
    ClientAuth::PRIVATE_KEY_JWT,
    (new ClientAuth(['client_id' => 'c', 'token_auth_method' => 'private_key_jwt']))->method($disco),
    'an explicit method is honoured'
);
throws(
    fn() => new ClientAuth(['client_id' => 'c', 'token_auth_method' => 'magic']),
    'unknown token endpoint authentication method',
    'an unknown method is refused at construction'
);

T::group('ClientAuth: client_secret_basic and _post');

$basic = applied(['client_id' => 'c id', 'client_secret' => 'p@ss'], ClientAuth::BASIC, $disco);
eq(
    'Authorization: Basic ' . base64_encode(rawurlencode('c id') . ':' . rawurlencode('p@ss')),
    $basic['headers'][0],
    'basic percent-encodes the pair before base64'
);
eq([], $basic['body'], 'and puts nothing in the body');

$post = applied(['client_id' => 'cid', 'client_secret' => 'p@ss'], ClientAuth::POST, $disco);
eq('cid', $post['body']['client_id'], 'post carries the client id');
eq('p@ss', $post['body']['client_secret'], 'and the secret');
eq([], $post['headers'], 'and adds no header');

T::group('ClientAuth: client_secret_jwt');

$cs = applied(
    ['client_id' => 'cid', 'client_secret' => $secret, 'assertion_alg' => 'HS256'],
    ClientAuth::SECRET_JWT,
    $disco
);
eq(
    'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    $cs['body']['client_assertion_type'],
    'the RFC 7523 assertion type is set'
);
falsy(isset($cs['body']['client_secret']), 'the secret itself never reaches the body');
$claims = JWT::decode($cs['body']['client_assertion'], new Key($secret, 'HS256'));
eq('cid', $claims->iss, 'iss is the client id');
eq('cid', $claims->sub, 'sub is the client id');
eq('https://idp.example/token', $claims->aud, 'aud is the token endpoint');
eq(60, $claims->exp - $claims->iat, 'the assertion is short-lived');
truthy(strlen($claims->jti) >= 16, 'it carries a jti');

// A second assertion must not repeat the first: an IdP with a jti cache would refuse it.
$again = applied(
    ['client_id' => 'cid', 'client_secret' => $secret],
    ClientAuth::SECRET_JWT,
    $disco
);
$other = JWT::decode($again['body']['client_assertion'], new Key($secret, 'HS256'));
truthy($claims->jti !== $other->jti, 'each assertion gets a fresh jti');

// RFC 7518 requires the HMAC key to be at least as long as its digest, and the signer
// enforces it -- so say which field is too short instead of surfacing "key is too short".
throws(
    fn() => applied(['client_id' => 'c', 'client_secret' => 'short'], ClientAuth::SECRET_JWT, $disco),
    'needs a client secret of at least 32 characters',
    'a short secret is refused with the number that matters'
);

T::group('ClientAuth: private_key_jwt');

$pj = applied(
    ['client_id' => 'cid', 'private_key' => $rsaPem, 'assertion_alg' => 'RS256', 'private_key_id' => 'k1'],
    ClientAuth::PRIVATE_KEY_JWT,
    $disco
);
falsy(isset($pj['body']['client_secret']), 'no shared secret is sent');
$verified = nothrow(
    fn() => JWT::decode($pj['body']['client_assertion'], new Key($rsaPub, 'RS256')),
    'the assertion verifies against the public half of the key'
);
eq('cid', $verified->iss ?? null, 'iss is the client id');
$header = json_decode(base64_decode(strtr(explode('.', $pj['body']['client_assertion'])[0], '-_', '+/')), true);
eq('k1', $header['kid'], 'the configured kid is in the header, so a rollover is possible');
eq('RS256', $header['alg'], 'the configured algorithm is used');

throws(
    fn() => applied(['client_id' => 'c', 'assertion_alg' => 'RS256'], ClientAuth::PRIVATE_KEY_JWT, $disco),
    'needs a client private key',
    'no key is refused'
);
// A symmetric alg with an asymmetric key is the alg-confusion shape; refuse it outright.
throws(
    fn() => applied(
        ['client_id' => 'c', 'private_key' => $rsaPem, 'assertion_alg' => 'HS256'],
        ClientAuth::PRIVATE_KEY_JWT,
        $disco
    ),
    'not an asymmetric signing algorithm',
    'HS256 is refused for private_key_jwt'
);
throws(
    fn() => applied(['client_id' => 'c', 'private_key' => $rsaPem], ClientAuth::PRIVATE_KEY_JWT, []),
    'no token_endpoint to address the assertion to',
    'an assertion with nobody to address is refused'
);

T::group('ClientAuth: mutual TLS');

throws(
    fn() => applied(['client_id' => 'c'], ClientAuth::TLS, $disco),
    'needs a client certificate',
    'mTLS without a certificate is refused'
);
// RFC 8705: the mTLS token endpoint is frequently a different host or port.
$mtls = new ClientAuth(['client_id' => 'c', 'token_auth_method' => 'tls_client_auth']);
eq('https://mtls.idp.example/token', $mtls->tokenEndpoint($disco, ClientAuth::TLS), 'the mTLS alias is used');
eq('https://idp.example/token', $mtls->tokenEndpoint($disco, ClientAuth::BASIC), 'other methods use the normal one');
eq(
    'https://idp.example/token',
    $mtls->tokenEndpoint(['token_endpoint' => 'https://idp.example/token'], ClientAuth::TLS),
    'with no alias published, the normal endpoint is used'
);

// curl wants paths, so the certificate pair is staged on disk. Named after its own
// digest, a rotated key is written beside the old one -- and the old one is a private
// key, so it must not stay there for good.
if (stateDirUsable()) {
    $stagedDir = \OPNsense\SSO\StateDir::path('oidc-mtls');
    $pair = ['client_id' => 'c', 'tls_cert' => "-- CERT --\n", 'tls_key' => "-- KEY --\n"];
    $options = [];
    $headers = [];
    $body = [];
    (new ClientAuth($pair))->apply($disco, ClientAuth::TLS, $body, $headers, $options);
    $cert = (string)($options[CURLOPT_SSLCERT] ?? '');
    truthy(is_file($cert), 'the certificate is staged on disk');
    eq(0, fileperms($cert) & 0077, 'and readable by nobody else');

    $stale = $stagedDir . '/cert-' . str_repeat('0', 64) . '.pem';
    file_put_contents($stale, 'old');
    touch($stale, time() - 60 * 86400);
    (new ClientAuth($pair))->apply($disco, ClientAuth::TLS, $body, $headers, $options);
    falsy(is_file($stale), 'material nothing has presented in a month is dropped');
    truthy(is_file($cert), 'while the pair still in use is kept');
    @unlink($cert);
    @unlink((string)($options[CURLOPT_SSLKEY] ?? ''));
}

T::group('ClientAuth: the published JWKS carries public material only');

$jwks = ClientAuth::publicJwks($rsaPem, 'RS256', 'k1');
eq(1, count($jwks['keys']), 'one key is published');
$jwk = $jwks['keys'][0];
eq('RSA', $jwk['kty'], 'the key type is RSA');
eq('sig', $jwk['use'], 'it is marked for signing');
eq('RS256', $jwk['alg'], 'the algorithm is carried');
eq('k1', $jwk['kid'], 'so is the kid');
truthy(isset($jwk['n'], $jwk['e']), 'the public modulus and exponent are present');
// The whole point: no path in publicJwks may emit a private parameter.
foreach (['d', 'p', 'q', 'dp', 'dq', 'qi'] as $private) {
    falsy(isset($jwk[$private]), "the private parameter '{$private}' is absent");
}

$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
openssl_pkey_export($ec, $ecPem);
$ecJwk = ClientAuth::publicJwks($ecPem, 'ES256', '')['keys'][0];
eq('EC', $ecJwk['kty'], 'an EC key is published as EC');
eq('P-256', $ecJwk['crv'], 'with its JWK curve name');
truthy(isset($ecJwk['x'], $ecJwk['y']), 'and its public coordinates');
falsy(isset($ecJwk['kid']), 'no kid is emitted when none is configured');
falsy(isset($ecJwk['d']), 'the EC private scalar is absent');

throws(fn() => ClientAuth::publicJwks('', 'RS256', ''), 'no client private key', 'no key means no JWKS');
throws(fn() => ClientAuth::publicJwks('not a pem', 'RS256', ''), 'not a readable PEM', 'junk is refused');
