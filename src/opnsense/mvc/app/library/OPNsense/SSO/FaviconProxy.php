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
 */
final class FaviconProxy
{
    private const TIMEOUT = 6;
    private const MAX_BYTES = 262144; // 256 KiB

    /**
     * @param string $baseUrl issuer / IdP SSO URL to derive the host from
     * @return array{type:string,data:string}
     * @throws \RuntimeException when no icon could be fetched
     */
    public static function fetch(string $baseUrl): array
    {
        $p = parse_url($baseUrl);
        if (empty($p['scheme']) || $p['scheme'] !== 'https' || empty($p['host'])) {
            throw new \RuntimeException('icon: issuer must be https');
        }
        $host = (string)$p['host'];
        if (self::isBlockedHost($host)) {
            throw new \RuntimeException('icon: refusing non-public issuer host');
        }
        $origin = 'https://' . $host . (isset($p['port']) ? ':' . $p['port'] : '');

        // 1. the conventional /favicon.ico
        $icon = self::get($origin . '/favicon.ico', $host);
        if ($icon !== null && str_starts_with($icon['type'], 'image/')) {
            return $icon;
        }

        // 2. parse the home page for a <link rel="icon" href="...">
        $home = self::get($origin . '/', $host);
        if ($home !== null && preg_match(
            '/<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>/i',
            $home['data'],
            $m
        ) && preg_match('/href=["\']([^"\']+)["\']/i', $m[0], $h)) {
            $href = self::resolveHref($h[1], $origin, $host);
            if ($href !== null) {
                $icon = self::get($href, $host);
                if ($icon !== null && str_starts_with($icon['type'], 'image/')) {
                    return $icon;
                }
            }
        }

        throw new \RuntimeException('icon: no favicon found');
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
    private static function get(string $url, string $allowedHost): ?array
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
