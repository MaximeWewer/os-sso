<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Give the lab WebGUI a certificate signed by the lab CA (test/idp/certs), for the LAN
 * address, so that the IdP containers -- which trust that CA -- can call the firewall
 * over verified HTTPS: back-channel logout tokens, a request_uri fetched by the IdP.
 * With the default self-signed certificate those calls fail TLS before reaching os-sso.
 *
 *   php set_webgui_cert.php <lan ip> <ca dir>
 *
 * Idempotent: a certificate already issued for that address is left in place.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Trust\Cert;

$ip = (string)($argv[1] ?? '');
$caDir = rtrim((string)($argv[2] ?? ''), '/');
$descr = 'os-sso lab: WebGUI (lab CA) ' . $ip;
if (filter_var($ip, FILTER_VALIDATE_IP) === false || !is_file("$caDir/ca.crt") || !is_file("$caDir/ca.key")) {
    fwrite(STDERR, "usage: set_webgui_cert.php <lan ip> <dir with ca.crt and ca.key>\n");
    exit(1);
}

$cfg = Config::getInstance()->object();
$current = (string)($cfg->system->webgui->{'ssl-certref'} ?? '');
foreach ($cfg->cert as $cert) {
    if ((string)$cert->refid === $current && (string)$cert->descr === $descr) {
        echo "already in place\n";
        exit(0);
    }
}

$cnf = tempnam(sys_get_temp_dir(), 'sso-cert');
file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[ext]\n"
    . "subjectAltName=IP:$ip\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n");
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
$csr = openssl_csr_new(['commonName' => $ip], $key, ['config' => $cnf, 'digest_alg' => 'sha256']);
$signed = openssl_csr_sign(
    $csr,
    file_get_contents("$caDir/ca.crt"),
    file_get_contents("$caDir/ca.key"),
    365,
    ['config' => $cnf, 'x509_extensions' => 'ext', 'digest_alg' => 'sha256'],
    random_int(1, PHP_INT_MAX)
);
unlink($cnf);
openssl_x509_export($signed, $crtPem);
openssl_pkey_export($key, $keyPem);

$model = new Cert();
$node = $model->cert->Add();
$refid = uniqid();
$node->refid = $refid;
$node->descr = $descr;
$node->crt = base64_encode($crtPem);
$node->prv = base64_encode($keyPem);
$model->serializeToConfig(false, true);
Config::getInstance()->object()->system->webgui->{'ssl-certref'} = $refid;
Config::getInstance()->save();
echo "issued for $ip, refid $refid\n";
