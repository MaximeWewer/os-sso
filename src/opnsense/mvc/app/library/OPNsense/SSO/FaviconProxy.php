<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Fetches an IdP's favicon server-side so the login page can show it from our own
 * (already-trusted) origin -- the browser does not trust the IdP's TLS cert in a
 * lab, and same-origin keeps it simple. Best-effort: tries /favicon.ico, then the
 * <link rel="icon"> of the IdP home page.
 *
 * SSRF hardening (this endpoint is pre-auth):
 *   - https only (CURLOPT_PROTOCOLS).
 *   - everything stays inside the operator-configured issuer origin, port included:
 *     redirects are followed by us rather than by curl and each hop is checked
 *     BEFORE it is requested, and an absolute <link href> pointing off-origin is
 *     ignored. Letting curl chase a Location would put the request on the wire first
 *     and leave us judging the effective URL afterwards, which is a blind SSRF.
 *   - literal private / loopback / link-local / reserved IPs are refused outright,
 *     and the vetted addresses are pinned into curl (no attacker-timed re-resolve).
 *   - the result is cached on disk, so an anonymous caller cannot use the pre-auth
 *     icon endpoint as an outbound request amplifier.
 *   - only raster image types come back out (see asIcon).
 */
final class FaviconProxy
{
    private const TIMEOUT = 6;
    private const MAX_BYTES = 262144; // 256 KiB
    private const CACHE_TTL = 86400;  // a favicon is not a moving target
    private const MISS_TTL = 3600;    // remember "no icon" too, or we retry forever
    private const MAX_REDIRECTS = 3;  // hops followed inside the pinned origin

    /**
     * Cached favicon fetch.
     *
     * The icon endpoint is pre-auth (the login page has to render before anyone is
     * logged in), so without a cache every anonymous hit on it costs the firewall up
     * to two outbound HTTPS requests -- a free amplifier pointed at our own IdP. The
     * result, including the failure, is therefore remembered on disk.
     *
     * @param string $baseUrl issuer / IdP SSO URL to derive the host from
     * @return array{type:string,data:string}
     * @throws \RuntimeException when no icon could be fetched
     */
    public static function fetch(string $baseUrl): array
    {
        $cached = self::cacheGet($baseUrl);
        if (is_array($cached)) {
            return $cached;
        }
        if ($cached === false) {
            throw new \RuntimeException('icon: no favicon found (cached)');
        }
        try {
            $icon = self::fetchLive($baseUrl);
        } catch (\Throwable $e) {
            self::cacheSet($baseUrl, null); // negative entry, shorter TTL
            throw $e;
        }
        self::cacheSet($baseUrl, $icon);
        return $icon;
    }

    /**
     * @return array{type:string,data:string}
     * @throws \RuntimeException when no icon could be fetched
     */
    private static function fetchLive(string $baseUrl): array
    {
        $p = parse_url($baseUrl);
        if (empty($p['scheme']) || $p['scheme'] !== 'https' || empty($p['host'])) {
            throw new \RuntimeException('icon: issuer must be https');
        }
        $host = (string)$p['host'];
        if (self::isBlockedHost($host)) {
            throw new \RuntimeException('icon: refusing non-public issuer host');
        }
        // Resolve the host once and vet every address, then pin curl to those IPs.
        // Closes the DNS-rebinding window an origin check on its own cannot:
        // a hostname that resolves to an internal/loopback IP is refused here, and
        // curl is not allowed a second (attacker-timed) resolution.
        $ips = self::resolveHostIps($host);
        if (empty($ips)) {
            throw new \RuntimeException('icon: issuer host does not resolve to a public address');
        }
        $port = (int)($p['port'] ?? 443);
        $resolve = [sprintf('%s:%d:%s', $host, $port, implode(',', $ips))];
        $origin = 'https://' . $host . (isset($p['port']) ? ':' . $p['port'] : '');

        // 1. the conventional /favicon.ico
        $icon = self::asIcon(self::get($origin . '/favicon.ico', $origin, $resolve));
        if ($icon !== null) {
            return $icon;
        }

        // 2. parse the home page for a <link rel="icon" href="...">
        $home = self::get($origin . '/', $origin, $resolve);
        if ($home !== null && preg_match(
            '/<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>/i',
            $home['data'],
            $m
        ) && preg_match('/href=["\']([^"\']+)["\']/i', $m[0], $h)) {
            $href = self::resolveHref($h[1], $origin);
            if ($href !== null) {
                $icon = self::asIcon(self::get($href, $origin, $resolve));
                if ($icon !== null) {
                    return $icon;
                }
            }
        }

        throw new \RuntimeException('icon: no favicon found');
    }

    /**
     * Response headers for serving one of these back.
     *
     * fetch() only ever returns a raster type; these make sure the browser treats it as
     * one. nosniff stops a mislabelled body being reinterpreted, and the CSP neuters
     * the response as a document should anyone navigate straight to the /icon endpoint,
     * which is a pre-auth GET on the firewall's own origin.
     *
     * @return array<string,string>
     */
    public static function headers(string $type): array
    {
        return [
            'Content-Type' => $type,
            'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'none'; sandbox",
            'Cache-Control' => 'public, max-age=86400',
        ];
    }

    /** Raster favicon formats. Anything else is not something we will re-serve. */
    private const SAFE_TYPES = [
        'image/png',
        'image/x-icon',
        'image/vnd.microsoft.icon',
        'image/gif',
        'image/jpeg',
        'image/webp',
    ];

    /**
     * Accept a fetched response as an icon, with its Content-Type normalised to the
     * bare media type the caller will echo back.
     *
     * Deliberately an allowlist and not "image/*": image/svg+xml is a document, script
     * elements and all, and the /icon endpoints are pre-auth GETs served from the
     * firewall's own origin -- navigating directly to one would run the IdP's markup
     * there, against the WebGUI. Raster formats only; the endpoints additionally send
     * nosniff so a mislabelled body cannot be reinterpreted.
     */
    private static function asIcon(?array $fetched): ?array
    {
        if ($fetched === null) {
            return null;
        }
        $type = strtolower(trim(explode(';', (string)($fetched['type'] ?? ''))[0]));
        return in_array($type, self::SAFE_TYPES, true)
            ? ['type' => $type, 'data' => (string)$fetched['data']]
            : null;
    }

    /* ---- on-disk cache (positive + negative), inside the vetted state dir ---- */

    /**
     * @return array{type:string,data:string}|false|null the cached icon, false for a
     *         cached failure, null when nothing usable is cached
     */
    private static function cacheGet(string $baseUrl)
    {
        try {
            $f = self::cacheFile($baseUrl);
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
        $miss = empty($entry['type']);
        if ((time() - (int)@filemtime($f)) > ($miss ? self::MISS_TTL : self::CACHE_TTL)) {
            return null;
        }
        if ($miss) {
            return false;
        }
        // Re-check the type on the way out: a cache file written by an older build may
        // hold something we no longer serve. An entry that fails is simply a miss.
        return self::asIcon([
            'type' => (string)$entry['type'],
            'data' => (string)base64_decode((string)($entry['data'] ?? '')),
        ]);
    }

    /** @param array{type:string,data:string}|null $icon null records a failure */
    private static function cacheSet(string $baseUrl, ?array $icon): void
    {
        try {
            $f = self::cacheFile($baseUrl);
        } catch (\RuntimeException $e) {
            return; // no usable cache directory: just run uncached
        }
        $entry = $icon === null
            ? []
            : ['type' => $icon['type'], 'data' => base64_encode($icon['data'])];
        @file_put_contents($f, json_encode($entry), LOCK_EX);
        @chmod($f, 0600);
    }

    private static function cacheFile(string $baseUrl): string
    {
        return StateDir::path('icons') . '/' . hash('sha256', $baseUrl) . '.json';
    }

    /**
     * Resolve a <link href> against the origin, refusing anything that would point off
     * it (an absolute URL elsewhere is an SSRF lever).
     *
     * Compared as a whole origin, port included: only the origin we resolved and pinned
     * is reachable over the pinned IPs, so a same-host href on a different port would
     * be fetched with a fresh, unpinned DNS lookup.
     */
    private static function resolveHref(string $href, string $origin): ?string
    {
        if (str_starts_with($href, '//')) {
            $href = 'https:' . $href;
        } elseif ($href !== '' && $href[0] === '/') {
            return $origin . $href; // same-origin absolute path
        } elseif (!preg_match('#^https?://#i', $href)) {
            return $origin . '/' . $href; // relative
        }
        return self::isSameOrigin($href, $origin) ? $href : null;
    }

    /** Normalised https origin of a URL ('' when it is not usable as one). */
    private static function originOf(string $url): string
    {
        $p = parse_url($url);
        if (empty($p['scheme']) || strtolower((string)$p['scheme']) !== 'https' || empty($p['host'])) {
            return '';
        }
        return 'https://' . strtolower((string)$p['host'])
            . (isset($p['port']) ? ':' . (int)$p['port'] : '');
    }

    private static function isSameOrigin(string $url, string $origin): bool
    {
        $a = self::originOf($url);
        return $a !== '' && $a === self::originOf($origin);
    }

    /**
     * One HTTPS GET inside the pinned origin, following redirects ourselves.
     *
     * @param string $allowedOrigin the origin resolved and pinned by fetchLive; every
     *                              hop must stay inside it
     * @return array{type:string,data:string}|null
     */
    private static function get(string $url, string $allowedOrigin, array $resolve = [], int $depth = 0): ?array
    {
        if (stripos($url, 'https://') !== 0) {
            return null;
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            // Redirects are followed below, by us, not by curl: CURLOPT_RESOLVE only
            // pins the hop we hand it, so curl chasing a Location to another host would
            // resolve that one freely and the request would leave the box before the
            // effective URL could be rejected -- a blind SSRF with the redirect target
            // chosen by whoever answers for the IdP host.
            CURLOPT_FOLLOWLOCATION => false,
            // https only. Blocks http://, file://, gopher:// and friends.
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            // Pin the issuer host to the pre-vetted IPs (no attacker-timed re-resolve).
            CURLOPT_RESOLVE => $resolve,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => fn($c, $dt, $dn) => $dn > self::MAX_BYTES ? 1 : 0,
        ]);
        $data = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $type = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        // Populated by curl precisely because FOLLOWLOCATION is off.
        $next = (string)curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        // Follow it only if it stays inside the origin we pinned; anything else ends
        // here, before a request is made, rather than being judged after the fact.
        if ($code >= 300 && $code < 400) {
            return $depth < self::MAX_REDIRECTS && self::isSameOrigin($next, $allowedOrigin)
                ? self::get($next, $allowedOrigin, $resolve, $depth + 1)
                : null;
        }

        if ($data === false || $code < 200 || $code >= 300 || $data === '') {
            return null;
        }
        return ['type' => $type ?: 'application/octet-stream', 'data' => (string)$data];
    }

    /**
     * Resolve a host (A + AAAA) to vetted IP literals. A literal IP is returned as-is
     * if public. A hostname is resolved and EVERY address must be public -- if it has
     * none, or any is private/loopback/reserved, the whole fetch is refused (returns
     * []). The result is pinned into curl via CURLOPT_RESOLVE so the connection cannot
     * be rebound to an internal address after this check.
     *
     * @return string[] vetted IP literals (empty => refuse)
     */
    private static function resolveHostIps(string $host): array
    {
        $host = trim($host, '[]');
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return self::isBlockedHost($host) ? [] : [$host];
        }
        $ips = [];
        foreach (@dns_get_record($host, DNS_A) ?: [] as $rec) {
            if (!empty($rec['ip'])) {
                $ips[] = (string)$rec['ip'];
            }
        }
        foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $rec) {
            if (!empty($rec['ipv6'])) {
                $ips[] = (string)$rec['ipv6'];
            }
        }
        if (empty($ips)) {
            return [];
        }
        foreach ($ips as $ip) {
            if (self::isBlockedHost($ip)) {
                return []; // any non-public address poisons the whole host
            }
        }
        return array_values(array_unique($ips));
    }

    private static function isBlockedHost(string $host): bool
    {
        $host = trim($host, '[]'); // strip IPv6 brackets
        if ($host === '' || strcasecmp($host, 'localhost') === 0) {
            return true;
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return !filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );
        }
        return false;
    }
}
