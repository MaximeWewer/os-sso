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

        self::assertLocalAccountUsable($providerName, $identity, $username);

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
     * Refuse a client whose local account is disabled or expired.
     *
     * This path deliberately needs no local account -- it grants network access, not a
     * WebGUI session -- so it never went near config.xml. But when an account IS there,
     * skipping it made the portal the one door a revocation does not close: SCIM
     * `active: false`, "Deprovision on refused login" and the operator's own disable
     * checkbox all end in a disabled local account, and the WebGUI and VPN paths refuse
     * it (LocalAccount::assertUsable, via IdentityMapper) while the portal kept letting
     * the same person onto the network.
     *
     * Matched the way the login path matches: the durable subject binding first, then
     * the username. An account that does not exist is not an error.
     *
     * An account os-sso itself deprovisioned is re-enabled here as well. The portal is
     * otherwise the one door where that could not happen -- it needs no local account and
     * so never writes config.xml -- which would have left someone the IdP has put back in
     * the right group able to reach the WebGUI and the VPN but not the wifi. The write is
     * taken under the config lock and only when the stamp is actually there, so an
     * ordinary guest login still touches nothing.
     */
    private static function assertLocalAccountUsable(
        string $providerName,
        NormalizedIdentity $identity,
        string $username
    ): void {
        $accounts = new LocalAccountWriter();
        $find = function () use ($accounts, $providerName, $identity, $username) {
            $node = $identity->subject !== ''
                ? $accounts->findBySubject($providerName . '|' . $identity->subject)
                : null;
            return $node ?? $accounts->findByName($username);
        };

        $node = $find();
        if ($node === null) {
            return;
        }
        if (Deprovisioner::isDeprovisioned($node)) {
            ConfigLock::with(function () use ($find, $accounts) {
                // Re-find: the lock reloads config.xml, so the node found above is stale.
                $fresh = $find();
                if ($fresh !== null && Deprovisioner::reviveNode($fresh, $accounts)) {
                    $accounts->persist((string)$fresh->name);
                }
                return null;
            });
            $node = $find();
        }
        if ($node !== null) {
            LocalAccount::assertUsable($node);
        }
    }

    /**
     * Record what authorize() just granted, and take it straight back if it cannot be
     * recorded.
     *
     * The portal is the one door that reaches the network without going through
     * IdentityMapper, and therefore without the config lock -- so where every other path
     * already fails closed on an unusable state directory, this one happily let a client
     * onto the wifi and then found nowhere to write the record down. That record is the
     * only handle a back-channel logout, a SCIM deactivation, the session sweeper or the
     * diagnostics page has on a portal client: without it the access is not merely
     * untracked, it is unrevocable, which is the opposite of what this plugin promises.
     *
     * So the grant is undone rather than kept. Refusing a guest onto the wifi is a
     * visible, self-correcting failure; leaving one there with nothing able to remove
     * them is not.
     *
     * @param array $cpRes what authorize() returned
     * @param array $idpSession provider, issuer, sub, sid, lifetime
     * @throws \RuntimeException when the grant was taken back
     */
    public static function recordGrant(array $cpRes, array $idpSession): void
    {
        // Ours on the left: "+" keeps the left-hand key on a collision, and what this
        // record is FOR -- which zone, which portal session to end -- is not something a
        // caller's metadata should be able to overwrite.
        $recorded = SessionRegistry::recordGrant([
            'kind' => SessionRegistry::PORTAL,
            'username' => (string)$cpRes['username'],
            'zone' => (string)$cpRes['zone'],
            'cp_session' => (string)($cpRes['session']['sessionId'] ?? ''),
        ] + $idpSession);
        if ($recorded) {
            return;
        }
        self::disconnect($cpRes);
        throw new \RuntimeException(
            'captive portal authorization was taken back: the grant could not be recorded, '
            . 'and an access nothing has a record of is one nothing can revoke'
        );
    }

    /** Drop a portal session we just created. */
    private static function disconnect(array $cpRes): void
    {
        $session = (string)($cpRes['session']['sessionId'] ?? '');
        if ($session === '') {
            // "already AUTHORIZED": the address was on the network before this login, so
            // there is no session of ours to end and something else granted it.
            syslog(LOG_WARNING, sprintf(
                "os-sso cp: could not record the grant for '%s' and it had no session of its own to end",
                (string)$cpRes['username']
            ));
            return;
        }
        (new Backend())->configdpRun('captiveportal disconnect', [$session, 'os-sso: grant not recordable']);
        syslog(LOG_WARNING, sprintf(
            "os-sso cp: disconnected '%s' again -- the grant could not be recorded",
            (string)$cpRes['username']
        ));
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
            // A scheme, or a scheme-less "host:port"? Both start with letters and a
            // colon. What tells them apart is what follows: a port is digits and then
            // the end or a path/query/fragment. Reading "example.com:8080/x" as a
            // scheme silently dropped the bounce for any destination on a non-default
            // port, which is a shape core hands over routinely.
            if (preg_match('#^[a-z][a-z0-9+.-]*:(?![0-9]+(?:[/?\#]|$))#i', $raw)) {
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
     *
     * That destination is an arbitrary external site by construction -- it is wherever
     * the client was headed when the portal intercepted them -- so this page does
     * redirect off-site on purpose. What it must not do is take anything with it: this
     * page is rendered BY the SSO callback, whose own URL carries the authorization
     * code and state on the query string, and both a meta refresh and a clicked link
     * would hand that to the destination in the Referer. Hence the no-referrer meta,
     * which also covers the header route since the page is self-contained.
     */
    public static function donePage(string $username, string $redirUrl = ''): string
    {
        $u = htmlspecialchars($username, ENT_QUOTES);
        // Re-validate here as well: donePage is the last thing between a verified
        // login and the browser following a URL that came in on the query string.
        $redirUrl = self::sanitizeRedirect($redirUrl);
        $meta = "<meta name='referrer' content='no-referrer'>";
        $link = '';
        if ($redirUrl !== '') {
            $r = htmlspecialchars($redirUrl, ENT_QUOTES);
            $meta .= "<meta http-equiv='refresh' content='3;url={$r}'>";
            // Name the destination instead of bouncing silently -- the user just typed
            // credentials at their IdP and deserves to see where they are being sent.
            $link = '<p>' . sprintf(
                htmlspecialchars(gettext('Continuing to %s')),
                "<a rel='noreferrer noopener' href='{$r}'>{$r}</a>"
            ) . '&hellip;</p>';
        }
        $title = htmlspecialchars(gettext('Connected'), ENT_QUOTES);
        $body = sprintf(
            htmlspecialchars(gettext('Signed in as %s. You now have network access.')),
            '<strong>' . $u . '</strong>'
        );
        return "<!doctype html><html><head><meta charset='utf-8'><title>{$title}</title>{$meta}"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em;color:#1b5e20}"
            . "a{color:#1b5e20;word-break:break-all}</style>"
            . "</head><body><h2>&#10003; {$title}</h2>"
            . "<p>{$body}</p>"
            . $link
            . "</body></html>";
    }
}
