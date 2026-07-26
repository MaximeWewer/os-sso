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
 *   - https only, on the request AND on every redirect (CURLOPT_*PROTOCOLS).
 *   - the host is pinned to the operator-configured issuer origin: redirects that
 *     leave that host are rejected (effective-URL host check), and an absolute
 *     <link href> pointing off-origin is ignored.
 *   - literal private / loopback / link-local / reserved IPs are refused outright.
 *   - the result is cached on disk, so an anonymous caller cannot use the pre-auth
 *     icon endpoint as an outbound request amplifier.
 */
final class FaviconProxy
{
    private const TIMEOUT = 6;
    private const MAX_BYTES = 262144; // 256 KiB
    private const CACHE_TTL = 86400;  // a favicon is not a moving target
    private const MISS_TTL = 3600;    // remember "no icon" too, or we retry forever

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
        // Closes the DNS-rebinding window the effective-URL host check alone cannot:
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
        $icon = self::get($origin . '/favicon.ico', $host, $resolve);
        if ($icon !== null && str_starts_with($icon['type'], 'image/')) {
            return $icon;
        }

        // 2. parse the home page for a <link rel="icon" href="...">
        $home = self::get($origin . '/', $host, $resolve);
        if ($home !== null && preg_match(
            '/<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>/i',
            $home['data'],
            $m
        ) && preg_match('/href=["\']([^"\']+)["\']/i', $m[0], $h)) {
            $href = self::resolveHref($h[1], $origin, $host);
            if ($href !== null) {
                $icon = self::get($href, $host, $resolve);
                if ($icon !== null && str_starts_with($icon['type'], 'image/')) {
                    return $icon;
                }
            }
        }

        throw new \RuntimeException('icon: no favicon found');
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
        return $miss
            ? false
            : ['type' => (string)$entry['type'], 'data' => (string)base64_decode((string)($entry['data'] ?? ''))];
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
     * Resolve a <link href> against the origin, refusing anything that would point
     * off the issuer host (an absolute URL to another host is an SSRF lever).
     */
    private static function resolveHref(string $href, string $origin, string $originHost): ?string
    {
        if (str_starts_with($href, '//')) {
            $href = 'https:' . $href;
        } elseif ($href !== '' && $href[0] === '/') {
            return $origin . $href; // same-origin absolute path
        } elseif (!preg_match('#^https?://#i', $href)) {
            return $origin . '/' . $href; // relative
        }
        // Absolute URL: must be https and stay on the issuer host.
        $hp = parse_url($href);
        if (
            empty($hp['scheme']) || strtolower($hp['scheme']) !== 'https'
            || empty($hp['host']) || strcasecmp((string)$hp['host'], $originHost) !== 0
        ) {
            return null;
        }
        return $href;
    }

    /**
     * @param string $allowedHost the issuer host; the final (post-redirect) URL must
     *                            still resolve to it, otherwise the response is dropped
     * @return array{type:string,data:string}|null
     */
    private static function get(string $url, string $allowedHost, array $resolve = []): ?array
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
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            // https only -- on the initial request and on every redirect hop. Blocks
            // http://, file://, gopher:// and friends as redirect targets.
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            // Pin the issuer host to the pre-vetted IPs (no attacker-timed re-resolve).
            CURLOPT_RESOLVE => $resolve,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => fn($c, $dt, $dn) => $dn > self::MAX_BYTES ? 1 : 0,
        ]);
        $data = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $type = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $effective = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        if ($data === false || $code < 200 || $code >= 300 || $data === '') {
            return null;
        }
        // Pin the final URL to the issuer host: a redirect that left it (to an
        // internal service or a blocked IP) is rejected rather than returned.
        $effHost = (string)(parse_url($effective, PHP_URL_HOST) ?? '');
        if ($effHost === '' || strcasecmp($effHost, $allowedHost) !== 0 || self::isBlockedHost($effHost)) {
            return null;
        }
        return ['type' => $type ?: 'application/octet-stream', 'data' => (string)$data];
    }

    /**
     * Reject hosts that must never be reachable from a pre-auth proxy: localhost and
     * literal private / loopback / link-local / reserved IPs (incl. 169.254.169.254).
     * Hostnames that resolve via DNS are not pre-resolved here -- the effective-URL
     * host pin in get() is what bounds redirect-based abuse.
     */
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
