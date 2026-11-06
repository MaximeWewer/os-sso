<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OneLogin\Saml2\Utils;
use OPNsense\SSO\Protocol\SamlProtocol;

T::group('SAML: signed SP metadata');

$spKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
$csr = openssl_csr_new(['commonName' => 'fw.example'], $spKey, ['digest_alg' => 'sha256']);
openssl_x509_export(openssl_csr_sign($csr, null, $spKey, 365, ['digest_alg' => 'sha256']), $spCert);
openssl_pkey_export($spKey, $spKeyPem);

$base = [
    'provider_name' => 'kc',
    'base_url' => 'https://fw.example',
    'sp_entity_id' => 'https://fw.example/api/sso/saml/metadata?provider=kc',
    'acs_url' => 'https://fw.example/api/sso/saml/acs?provider=kc',
    'idp_entity_id' => 'https://idp.example',
    'idp_sso_url' => 'https://idp.example/sso',
    'idp_x509' => $spCert,
    'sp_cert' => $spCert,
    'sp_key' => $spKeyPem,
];

$plain = (new SamlProtocol($base))->metadata();
falsy(str_contains($plain, 'SignatureValue'), 'metadata is unsigned by default');

$signed = (new SamlProtocol($base + ['sign_metadata' => true]))->metadata();
truthy(str_contains($signed, 'SignatureValue'), 'with the option, the document carries a signature');
truthy(Utils::validateSign($signed, $spCert), 'and it verifies against the SP certificate');
truthy(str_contains($signed, 'xmlenc#sha256'), 'with a SHA-256 digest, not php-saml\'s SHA-1 default');
// validateSign() throws on a broken reference rather than returning false.
$verifies = function (string $xml) use ($spCert): bool {
    try {
        return Utils::validateSign($xml, $spCert);
    } catch (\Throwable $e) {
        return false;
    }
};
falsy(
    $verifies(str_replace('https://fw.example/api/sso/saml/acs', 'https://evil.example/acs', $signed)),
    'a tampered document no longer verifies'
);

$noKey = $base;
unset($noKey['sp_key']);
throws(
    fn() => (new SamlProtocol($noKey + ['sign_metadata' => true]))->metadata(),
    'requires an SP certificate and private key',
    'asking for a signature without the SP key says why'
);
