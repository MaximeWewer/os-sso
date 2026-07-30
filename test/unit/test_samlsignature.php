<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * php-saml verifies whatever SignatureMethod the message declares, and the vendored
 * version has no option to refuse a broken one -- so the plugin reads the algorithms
 * back off the validated document itself. What matters here is that the lookup finds
 * them whatever prefix the IdP used, and looks only where a validated signature lives.
 */

use OPNsense\SSO\Protocol\SamlProtocol;

T::group('SamlProtocol: broken signature algorithms');

/** A response carrying one signature, at $where ('response' or 'assertion'). */
function samlResponse(string $sigAlg, string $digestAlg, string $where = 'assertion', string $prefix = 'saml2'): string
{
    $p = $prefix;
    $signature = "<ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
        . "<ds:SignedInfo>"
        . "<ds:SignatureMethod Algorithm='{$sigAlg}'/>"
        . "<ds:Reference URI='#a1'><ds:DigestMethod Algorithm='{$digestAlg}'/>"
        . "<ds:DigestValue>x</ds:DigestValue></ds:Reference>"
        . "</ds:SignedInfo><ds:SignatureValue>y</ds:SignatureValue></ds:Signature>";
    return "<{$p}p:Response xmlns:{$p}p='urn:oasis:names:tc:SAML:2.0:protocol' "
        . "xmlns:{$p}='urn:oasis:names:tc:SAML:2.0:assertion' ID='r1'>"
        . ($where === 'response' ? $signature : '')
        . "<{$p}:Assertion ID='a1'>"
        . ($where === 'assertion' ? $signature : '')
        . "<{$p}:Subject><{$p}:NameID>alice</{$p}:NameID></{$p}:Subject>"
        . "</{$p}:Assertion></{$p}p:Response>";
}

$rsaSha256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
$rsaSha1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
$sha256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
$sha1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

eq('', SamlProtocol::weakAlgorithm(samlResponse($rsaSha256, $sha256)), 'RSA-SHA256 over SHA-256 passes');
eq($rsaSha1, SamlProtocol::weakAlgorithm(samlResponse($rsaSha1, $sha256)), 'an RSA-SHA1 signature is named');
// A strong signature over a SHA-1 digest commits to nothing more than the digest does.
eq($sha1, SamlProtocol::weakAlgorithm(samlResponse($rsaSha256, $sha1)), 'a SHA-1 reference digest is caught too');
eq(
    $rsaSha1,
    SamlProtocol::weakAlgorithm(samlResponse($rsaSha1, $sha256, 'response')),
    'the response-level signature is checked as well as the assertion one'
);

// Prefixes are the IdP's choice: Keycloak sends saml2p/saml2, Authentik samlp/saml,
// ADFS its own. The lookup goes by namespace URI.
foreach (['saml2', 'saml', 'x'] as $prefix) {
    eq(
        $rsaSha1,
        SamlProtocol::weakAlgorithm(samlResponse($rsaSha1, $sha256, 'assertion', $prefix)),
        "found under the {$prefix} prefix"
    );
}

eq('', SamlProtocol::weakAlgorithm(''), 'nothing to read is not a failure');
eq('', SamlProtocol::weakAlgorithm('<not xml'), 'nor is a document we cannot parse (php-saml already did)');

// A signature somewhere else in the document is not one php-saml validated, so it must
// not refuse an otherwise sound response.
$elsewhere = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' "
    . "xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><saml:Advice>"
    . "<ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo>"
    . "<ds:SignatureMethod Algorithm='{$rsaSha1}'/></ds:SignedInfo></ds:Signature>"
    . "</saml:Advice></samlp:Response>";
eq('', SamlProtocol::weakAlgorithm($elsewhere), 'a signature outside the validated positions is ignored');

T::group('SamlProtocol: the authentication context that came back');

/** A response whose assertion declares $contexts (none when empty). */
function samlContexts(array $contexts): string
{
    $statements = '';
    foreach ($contexts as $context) {
        $statements .= "<saml:AuthnStatement AuthnInstant='2026-01-01T00:00:00Z'><saml:AuthnContext>"
            . "<saml:AuthnContextClassRef>{$context}</saml:AuthnContextClassRef>"
            . "</saml:AuthnContext></saml:AuthnStatement>";
    }
    return "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' "
        . "xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'><saml:Assertion>"
        . ($statements ?: "<saml:AuthnStatement AuthnInstant='2026-01-01T00:00:00Z'/>")
        . "</saml:Assertion></samlp:Response>";
}

$mfa = 'urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor';
$password = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

eq([$mfa], SamlProtocol::authnContexts(samlContexts([$mfa])), 'the declared context is read back');
eq([$password, $mfa], SamlProtocol::authnContexts(samlContexts([$password, $mfa])), 'several statements are all read');
eq([$mfa], SamlProtocol::authnContexts(samlContexts([$mfa, $mfa])), 'repeats collapse');
// An assertion that says nothing about how the user authenticated is the case that
// matters: it must read as absent, so the caller refuses rather than assumes.
eq([], SamlProtocol::authnContexts(samlContexts([])), 'an assertion with no context reads as none');
eq([], SamlProtocol::authnContexts(''), 'nothing to read is not a context');
eq([], SamlProtocol::authnContexts('<not xml'), 'nor is an unparsable document');
