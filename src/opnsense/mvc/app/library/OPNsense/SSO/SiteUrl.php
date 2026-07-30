<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;

/**
 * Resolves the public base URL of this firewall -- the string every externally
 * meaningful URL is built from: the OIDC redirect_uri, the SAML SP EntityID / ACS /
 * SLO, the post-logout URL.
 *
 * This is security-relevant, not cosmetic. A base URL taken from the client-supplied
 * Host header lands in the redirect_uri we hand the IdP; an IdP doing prefix or
 * wildcard redirect-uri matching would then send the authorization code to whatever
 * host the attacker put in that header. So:
 *
 *   - the operator-configured Base URL (https only) always wins, and the config form
 *     now requires it;
 *   - the legacy auto-detect fallback (for providers configured before that) accepts
 *     a Host only if it matches a name this firewall actually answers to -- its
 *     hostname/domain, the WebGUI "alternate hostnames" allowlist, or the local socket
 *     address -- and otherwise falls back to the configured hostname;
 *   - the scheme comes from the WebGUI configuration, never from the forwardable
 *     X-Forwarded-Proto header.
 */
final class SiteUrl
{
    /** Configured Base URL override for this provider, else a vetted auto-detect. */
    public static function forProvider($auth): string
    {
        $configured = trim((string)($auth->ssoBaseUrl ?? ''));
        if ($configured !== '' && stripos($configured, 'https://') === 0) {
            return rtrim($configured, '/');
        }
        return self::detect();
    }

    /**
     * Auto-detected base URL: scheme from the WebGUI config, host from the request
     * only when it is one this firewall answers to.
     */
    public static function detect(): string
    {
        $system = Config::getInstance()->object()->system ?? null;
        $scheme = (string)($system->webgui->protocol ?? 'https') === 'http' ? 'http' : 'https';

        $host = (string)($_SERVER['HTTP_HOST'] ?? '');
        // Split off the port before matching; only a well-formed host[:port] is usable.
        if (preg_match('/^([A-Za-z0-9.\-]+)(:\d{1,5})?$/', $host, $m) && self::isOwnName($system, $m[1])) {
            return $scheme . '://' . $host;
        }
        if ($host !== '') {
            syslog(LOG_WARNING, sprintf(
                'os-sso: ignoring unrecognised Host "%s" while building the base URL; ' .
                'set the provider Base URL to the firewall public URL',
                preg_replace('/[^\x20-\x7e]/', '', $host)
            ));
        }
        return $scheme . '://' . self::ownName($system);
    }

    /** Is $name one of the names this firewall answers to? */
    /**
     * True when $host is a name this firewall answers to: its hostname (bare or
     * qualified), a WebGUI alternate hostname, or its own address.
     */
    public static function isOwnHost(string $host): bool
    {
        $host = trim($host, '[]'); // IPv6 literal
        if ($host === '') {
            return false;
        }
        return self::isOwnName(Config::getInstance()->object()->system ?? null, $host);
    }

    private static function isOwnName($system, string $name): bool
    {
        foreach (self::ownNames($system) as $known) {
            if (strcasecmp($known, $name) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Names this firewall legitimately answers to: its hostname, its FQDN, the WebGUI
     * "alternate hostnames" allowlist (the same list core uses for its referrer check),
     * and the address the request actually landed on.
     *
     * SERVER_NAME is deliberately NOT in this list. Under lighttpd (and CGI generally)
     * it is derived from the request's own Host header, so trusting it would make this
     * allowlist validate the attacker's input against itself -- which is exactly what
     * the lab caught. SERVER_ADDR is the local socket address and is not client-set.
     *
     * @return string[]
     */
    private static function ownNames($system): array
    {
        $names = [];
        $hostname = trim((string)($system->hostname ?? ''));
        $domain = trim((string)($system->domain ?? ''));
        if ($hostname !== '') {
            $names[] = $hostname;
            if ($domain !== '') {
                $names[] = $hostname . '.' . $domain;
            }
        }
        foreach (preg_split('/[\s,]+/', (string)($system->webgui->althostnames ?? '')) ?: [] as $alt) {
            if (trim($alt) !== '') {
                $names[] = trim($alt);
            }
        }
        $addr = trim((string)($_SERVER['SERVER_ADDR'] ?? ''));
        if ($addr !== '') {
            $names[] = $addr;
        }
        return $names;
    }

    /** Best known name for this firewall when the request Host cannot be trusted. */
    private static function ownName($system): string
    {
        $hostname = trim((string)($system->hostname ?? ''));
        $domain = trim((string)($system->domain ?? ''));
        if ($hostname !== '') {
            return $domain !== '' ? $hostname . '.' . $domain : $hostname;
        }
        // Same reasoning as ownNames(): SERVER_NAME mirrors the Host header, so it
        // cannot be the safe fallback for a Host we just refused.
        $addr = trim((string)($_SERVER['SERVER_ADDR'] ?? ''));
        if ($addr === '') {
            return 'localhost';
        }
        // An IPv6 literal needs its brackets back to be a URL authority.
        return str_contains($addr, ':') ? '[' . trim($addr, '[]') . ']' : $addr;
    }
}
