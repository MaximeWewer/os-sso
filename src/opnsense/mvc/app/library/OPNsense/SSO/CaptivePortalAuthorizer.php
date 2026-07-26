<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\CaptivePortal\CaptivePortal;

/**
 * Authorizes a Captive Portal client after an SSO browser login, shared by the OIDC
 * and SAML controllers. Unlike the WebGUI path this never opens an admin session and
 * never needs a local config.xml account: it just grants the client's IP network
 * access in its portal zone, by delegating to the same configd action the core
 * portal uses ("captiveportal allow", which runs as root).
 *
 * Two authorization gates, both server-side:
 *   - zone <-> provider binding: the SSO provider MUST be listed in the zone's
 *     authentication servers, otherwise a client could self-authorize into an
 *     arbitrary zone just by passing its id in the login URL.
 *   - optional per-zone group enforcement, evaluated against the IdP-asserted groups.
 */
final class CaptivePortalAuthorizer
{
    /**
     * @param string $zoneId captive portal zone number (from the login URL)
     * @param string $providerName authserver name that authenticated (= SSO provider)
     * @param NormalizedIdentity $identity verified identity from the protocol
     * @param string $clientIp source IP of the browser completing the login (= the
     *                          captive client's IP, since the portal is an L3 gateway)
     * @return array{username:string,zone:string,session:array}
     * @throws \RuntimeException on an unknown zone, an unbound provider, a failed
     *                           group check, or a failed authorization write
     */
    public static function authorize(string $zoneId, string $providerName, NormalizedIdentity $identity, string $clientIp): array
    {
        $zoneId = preg_replace('/[^0-9]/', '', $zoneId);
        if ($zoneId === '') {
            throw new \RuntimeException('invalid captive portal zone');
        }
        $zone = (new CaptivePortal())->getByZoneID($zoneId);
        if ($zone === null) {
            throw new \RuntimeException('unknown captive portal zone');
        }

        // zone <-> provider binding (operator opt-in via the zone's authservers list).
        $authservers = array_filter(array_map('trim', explode(',', (string)$zone->authservers)));
        if (!in_array($providerName, $authservers, true)) {
            throw new \RuntimeException('SSO provider not enabled for this captive portal zone');
        }

        // Optional group enforcement against the IdP-asserted groups. The zone stores
        // the group as its gid (AuthGroupField), so resolve it to the group name first,
        // then match (case-insensitive) against the asserted groups.
        $enforceGid = trim((string)$zone->authEnforceGroup);
        if ($enforceGid !== '') {
            $enforceName = '';
            foreach ((Config::getInstance()->object()->system->group ?? []) as $g) {
                if ((string)$g->gid === $enforceGid) {
                    $enforceName = (string)$g->name;
                    break;
                }
            }
            $groups = array_map(fn($g) => strtolower((string)$g), $identity->groups);
            if ($enforceName === '' || !in_array(strtolower($enforceName), $groups, true)) {
                throw new \RuntimeException('user is not in the group required by this zone');
            }
        }

        $username = $identity->username !== '' ? $identity->username : $identity->subject;
        if ($username === '') {
            throw new \RuntimeException('no username in the SSO identity');
        }
        // The captive-portal path does NOT run through IdentityMapper (no local
        // account), so the username claim skips its charset validation -- yet it is
        // logged below and handed to configd. Refuse control characters / newlines
        // so a crafted claim cannot forge audit-log lines (CWE-117); a legitimate
        // username (email, preferred_username, subject) never carries them.
        if (preg_match('/[\x00-\x1f\x7f]/', $username)) {
            throw new \RuntimeException('invalid characters in the SSO username');
        }

        $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $clientIp);
        if ($ip === '') {
            throw new \RuntimeException('no client IP to authorize');
        }

        $raw = (new Backend())->configdpRun('captiveportal allow', [$zoneId, $username, $ip, $providerName]);
        $session = json_decode((string)$raw, true);
        // "allow" returns the new session (with sessionId) or, if the IP was already
        // authorized, a clientState of AUTHORIZED. Anything else is a failure.
        $ok = is_array($session)
            && (!empty($session['sessionId']) || ($session['clientState'] ?? '') === 'AUTHORIZED');
        if (!$ok) {
            throw new \RuntimeException('captive portal authorization failed');
        }

        syslog(LOG_NOTICE, sprintf("os-sso cp: authorized '%s' in zone %s from %s", $username, $zoneId, $ip));
        return ['username' => $username, 'zone' => $zoneId, 'session' => (array)$session];
    }

    /**
     * Normalise the captive client's original destination into an absolute http(s)
     * URL, or '' if it is not one.
     *
     * This MUST run server-side. The portal page filters the value too, but that
     * filter is only reached when the user came through the portal page: the login
     * endpoint takes `cpurl` straight from the query string, so a crafted link
     * (/api/sso/oidc/login?cp=1&cpurl=...) bypasses it entirely. Since the user has
     * by then authenticated at the real IdP, an unchecked bounce is a convincing
     * phishing hop -- so no scheme other than http/https, no userinfo "@" (which
     * hides the real host), no protocol-relative "//", no backslash (browsers fold
     * it to "/"), no whitespace or control characters, and a sane length.
     *
     * Core hands the destination scheme-less (host[/path]); an absolute URL is
     * accepted too. The destination itself is by nature arbitrary -- it is wherever
     * the client was going -- so this bounds the SHAPE, and donePage shows the target
     * rather than bouncing silently.
     */
    public static function sanitizeRedirect(string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '' || strlen($raw) > 512) {
            return '';
        }
        if (preg_match('/[\x00-\x20\x7f"\'<>\\\\]/', $raw) || strpos($raw, '@') !== false) {
            return '';
        }
        if (str_starts_with($raw, '//')) {
            return ''; // protocol-relative: the host is not what it looks like
        }
        if (!preg_match('#^https?://#i', $raw)) {
            if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $raw)) {
                return ''; // some other scheme (javascript:, data:, ...)
            }
            $raw = 'http://' . ltrim($raw, '/'); // core's scheme-less host[/path]
        }
        $parts = parse_url($raw);
        if (empty($parts['host']) || !preg_match('/^[A-Za-z0-9._\-\[\]:]+$/', (string)$parts['host'])) {
            return '';
        }
        return $raw;
    }

    /**
     * "You are connected" page shown to the captive client's browser, optionally
     * bouncing back to the site they originally requested.
     */
    public static function donePage(string $username, string $redirUrl = ''): string
    {
        $u = htmlspecialchars($username, ENT_QUOTES);
        // Re-validate here as well: donePage is the last thing between a verified
        // login and the browser following a URL that came in on the query string.
        $redirUrl = self::sanitizeRedirect($redirUrl);
        $meta = '';
        $link = '';
        if ($redirUrl !== '') {
            $r = htmlspecialchars($redirUrl, ENT_QUOTES);
            $meta = "<meta http-equiv='refresh' content='3;url={$r}'>";
            // Name the destination instead of bouncing silently -- the user just typed
            // credentials at their IdP and deserves to see where they are being sent.
            $link = "<p>Continuing to <a href='{$r}'>{$r}</a>&hellip;</p>";
        }
        return "<!doctype html><html><head><meta charset='utf-8'><title>Connected</title>{$meta}"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em;color:#1b5e20}"
            . "a{color:#1b5e20;word-break:break-all}</style>"
            . "</head><body><h2>&#10003; Connected</h2>"
            . "<p>Signed in as <strong>{$u}</strong>. You now have network access.</p>"
            . $link
            . "</body></html>";
    }
}
