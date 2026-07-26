<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OneLogin\Saml2\Constants;
use OneLogin\Saml2\IdPMetadataParser;

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
     * @return array{entity_id:string,sso_url:string,slo_url:string,x509:string,x509_signing:string[]}
     * @throws \RuntimeException when the document cannot be fetched or parsed
     */
    public static function fetch(string $url, string $entityId = ''): array
    {
        $cached = self::cacheGet($url, $entityId);
        if (is_array($cached)) {
            return $cached;
        }
        if ($cached === false) {
            throw new \RuntimeException('SAML: IdP metadata unavailable (cached failure)');
        }
        try {
            $parsed = self::parse(self::get($url), $entityId);
        } catch (\Throwable $e) {
            self::cacheSet($url, $entityId, null);
            throw new \RuntimeException('SAML: IdP metadata: ' . $e->getMessage());
        }
        self::cacheSet($url, $entityId, $parsed);
        return $parsed;
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
    private static function cacheGet(string $url, string $entityId)
    {
        try {
            $f = self::cacheFile($url, $entityId);
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

    private static function cacheSet(string $url, string $entityId, ?array $parsed): void
    {
        try {
            $f = self::cacheFile($url, $entityId);
        } catch (\RuntimeException $e) {
            return;
        }
        @file_put_contents($f, json_encode($parsed ?? []), LOCK_EX);
        @chmod($f, 0600);
    }

    private static function cacheFile(string $url, string $entityId): string
    {
        return StateDir::path('saml-md') . '/' . hash('sha256', $url . '|' . $entityId) . '.json';
    }
}
