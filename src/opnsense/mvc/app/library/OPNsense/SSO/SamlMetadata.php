<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OneLogin\Saml2\Constants;
use OneLogin\Saml2\IdPMetadataParser;
use OPNsense\SSO\Protocol\SamlProtocol;

/**
 * Reads an IdP's SAML metadata document so the operator does not have to retype the
 * EntityID, the SSO/SLO endpoints and the signing certificate -- and, more usefully,
 * so a rotated IdP signing key is picked up on its own instead of breaking every
 * login until someone pastes the new PEM.
 *
 * php-saml ships a parser but its remote fetch is not usable as-is: it allows plain
 * http and defaults CURLOPT_SSL_VERIFYPEER to false, i.e. the document that decides
 * which key signs our assertions would be fetched over an unauthenticated channel.
 * We fetch it ourselves (https, verified, bounded) and hand the parser only the XML.
 */
final class SamlMetadata
{
    private const TIMEOUT = 8;
    private const MAX_BODY = 1048576; // 1 MiB
    private const TTL = 86400;        // metadata is stable; a rotation lands next day
    private const MISS_TTL = 300;     // retry a failed fetch soon, but not every login

    /**
     * @param string $url https URL of the IdP metadata document
     * @param string $entityId pick this EntityDescriptor when the document holds several
     * @param string $signingCert PEM the document's own XML signature must verify
     *        against; '' trusts TLS alone (see assertSigned)
     * @return array{entity_id:string,sso_url:string,slo_url:string,x509:string,x509_signing:string[]}
     * @throws \RuntimeException when the document cannot be fetched, verified or parsed
     */
    public static function fetch(string $url, string $entityId = '', string $signingCert = ''): array
    {
        $signingCert = trim($signingCert);
        // The certificate is part of the cache identity, not just of the fetch: an
        // operator who pins one after the fact must not be handed the document that was
        // cached while nothing was being checked.
        $cached = self::cacheGet($url, $entityId, $signingCert);
        if (is_array($cached)) {
            return $cached;
        }
        if ($cached === false) {
            throw new \RuntimeException('SAML: IdP metadata unavailable (cached failure)');
        }
        try {
            $xml = self::get($url);
            self::assertSigned($xml, $signingCert);
            $parsed = self::parse($xml, $entityId);
        } catch (\Throwable $e) {
            self::cacheSet($url, $entityId, $signingCert, null);
            throw new \RuntimeException('SAML: IdP metadata: ' . $e->getMessage());
        }
        self::cacheSet($url, $entityId, $signingCert, $parsed);
        return $parsed;
    }

    /** Where a metadata signature may sit: on the entity, or on a federation aggregate. */
    private const SIGNATURE_PATHS = [
        '/md:EntityDescriptor/ds:Signature',
        '/md:EntitiesDescriptor/ds:Signature',
    ];

    /**
     * Verify the document's own XML signature against the pinned certificate.
     *
     * Optional, because most deployments point at their own IdP over TLS and that is the
     * whole trust chain they have -- but TLS only says the document came from that host,
     * and this document is what names the keys every future assertion is checked with. A
     * federation signs its metadata for exactly that reason, and it is the one place the
     * signature is worth more than the transport: whoever can answer for the host, or
     * mint a certificate for it, otherwise replaces the IdP wholesale.
     *
     * Refuses an unsigned document once a certificate is configured -- pinning something
     * that is then silently not checked is worse than not offering the field -- and holds
     * it to the same algorithms as an assertion, since a SHA-1 signature over the key
     * list proves no more than one over the assertion.
     */
    private static function assertSigned(string $xml, string $signingCert): void
    {
        if ($signingCert === '') {
            return;
        }
        $weak = SamlProtocol::weakAlgorithmAt($xml, self::SIGNATURE_PATHS);
        if ($weak !== '') {
            throw new \RuntimeException('the document is signed with a broken algorithm (' . $weak . ')');
        }
        foreach (self::SIGNATURE_PATHS as $path) {
            try {
                if (\OneLogin\Saml2\Utils::validateSign($xml, $signingCert, null, 'sha256', $path)) {
                    return;
                }
            } catch (\Throwable $e) {
                // No signature at that position, or one that does not verify there; the
                // other position and the refusal below are the answer.
            }
        }
        throw new \RuntimeException(
            'the document is unsigned, or its signature does not verify against the configured '
            . 'metadata signing certificate'
        );
    }

    /**
     * @return array{entity_id:string,sso_url:string,slo_url:string,x509:string,x509_signing:string[]}
     */
    private static function parse(string $xml, string $entityId): array
    {
        // The parser runs before anything is verified, so refuse a DTD outright:
        // LIBXML_NONET stops external entities but not internal expansion, and no
        // legitimate metadata document carries one.
        if (preg_match('/<!DOCTYPE|<!ENTITY/i', $xml)) {
            throw new \RuntimeException('metadata document carries a DTD');
        }
        if (!class_exists(IdPMetadataParser::class)) {
            require_once __DIR__ . '/vendor/autoload.php';
        }
        $info = IdPMetadataParser::parseXML(
            $xml,
            $entityId !== '' ? $entityId : null,
            null,
            Constants::BINDING_HTTP_REDIRECT,
            Constants::BINDING_HTTP_REDIRECT
        );
        $idp = $info['idp'] ?? [];
        $signing = $idp['x509certMulti']['signing'] ?? [];
        $out = [
            'entity_id' => (string)($idp['entityId'] ?? ''),
            'sso_url' => (string)($idp['singleSignOnService']['url'] ?? ''),
            'slo_url' => (string)($idp['singleLogoutService']['url'] ?? ''),
            'x509' => (string)($idp['x509cert'] ?? ''),
            'x509_signing' => array_values(array_map('strval', (array)$signing)),
        ];
        // An IdP with no EntityID, no SSO endpoint or no signing key is not something
        // we can build a trust relationship on -- say so rather than half-configure.
        if ($out['entity_id'] === '' || $out['sso_url'] === '') {
            throw new \RuntimeException('document has no IDPSSODescriptor with an EntityID and SSO endpoint');
        }
        // The parser only promotes to a single x509cert when the document holds one
        // certificate overall; a lone signing cert alongside an encryption cert stays
        // in the list. Collapse that case so the settings always carry a certificate.
        if ($out['x509'] === '' && count($out['x509_signing']) === 1) {
            $out['x509'] = $out['x509_signing'][0];
        }
        if ($out['x509'] === '' && empty($out['x509_signing'])) {
            throw new \RuntimeException('document carries no signing certificate');
        }
        return $out;
    }

    /** Fetch the document: https only, peer verified, size and time bounded. */
    private static function get(string $url): string
    {
        if (stripos($url, 'https://') !== 0) {
            throw new \RuntimeException('metadata URL must be https');
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept: application/samlmetadata+xml, application/xml, text/xml'],
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => fn($c, $dt, $dn) => $dn > self::MAX_BODY ? 1 : 0,
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false) {
            throw new \RuntimeException('fetch failed: ' . $err);
        }
        if ($code < 200 || $code >= 300) {
            throw new \RuntimeException('HTTP ' . $code);
        }
        return (string)$body;
    }

    /* ---- disk cache, positive and negative --------------------------- */

    /** @return array|false|null parsed metadata, false for a cached failure, null for a miss */
    private static function cacheGet(string $url, string $entityId, string $signingCert)
    {
        try {
            $f = self::cacheFile($url, $entityId, $signingCert);
        } catch (\RuntimeException $e) {
            return null;
        }
        if (!is_file($f)) {
            return null;
        }
        $entry = json_decode((string)@file_get_contents($f), true);
        if (!is_array($entry)) {
            return null;
        }
        $miss = empty($entry['entity_id']);
        if ((time() - (int)@filemtime($f)) > ($miss ? self::MISS_TTL : self::TTL)) {
            return null;
        }
        return $miss ? false : $entry;
    }

    private static function cacheSet(string $url, string $entityId, string $signingCert, ?array $parsed): void
    {
        try {
            $f = self::cacheFile($url, $entityId, $signingCert);
        } catch (\RuntimeException $e) {
            return;
        }
        @file_put_contents($f, json_encode($parsed ?? []), LOCK_EX);
        @chmod($f, 0600);
    }

    private static function cacheFile(string $url, string $entityId, string $signingCert): string
    {
        return StateDir::path('saml-md') . '/'
            . hash('sha256', $url . '|' . $entityId . '|' . $signingCert) . '.json';
    }
}
