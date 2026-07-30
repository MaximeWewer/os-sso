<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;

/**
 * A record of everything os-sso granted -- a WebGUI session, a captive-portal client on
 * the network, an OpenVPN tunnel -- so it can be taken away from outside the browser,
 * the device or the tunnel that holds it.
 *
 * Everything else in this plugin happens during a login. Afterwards the IdP is out of
 * the loop: disable the account there, revoke its groups, and what was already granted
 * carries on until it times out on its own. That is the gap this closes -- it is what a
 * back-channel logout needs to find (which access belongs to that IdP subject), what an
 * absolute session lifetime needs to enforce, and what makes a SCIM deactivation reach
 * the wifi and the VPN rather than only the WebGUI.
 *
 * Killing a WebGUI session means deleting its PHP session file: the next request from
 * that browser finds no session and lands on the login page. The file path is recorded
 * at login rather than recomputed later, because the sweeper runs as root from configd
 * and its own session.save_path is not necessarily php-fpm's. The other two are handed
 * to configd, which owns the portal database and the OpenVPN management sockets.
 */
final class SessionRegistry
{
    /** What a record grants, and therefore how it is taken away. */
    public const WEBGUI = 'webgui';
    public const PORTAL = 'portal';
    public const VPN = 'vpn';

    /**
     * How long a portal or VPN grant stays on the books when nothing revokes it, and the
     * ceiling on the provider's own maximum session lifetime here.
     *
     * Neither is a PHP session we can look at to see whether it is still there: the
     * portal ends its own on an idle timeout, and a tunnel ends when the client leaves.
     * The record is only useful for revoking, so it outlives a working day and no more,
     * rather than accumulating one row per login for good.
     */
    private const GRANT_TTL = 86400;

    /**
     * Remember the session just established. Call with the native session active.
     *
     * @param array $meta provider, issuer, sub, sid (IdP session id), lifetime (s)
     */
    public static function record(array $meta): void
    {
        $sessionId = session_id();
        if ($sessionId === '' || $sessionId === false) {
            return;
        }
        $lifetime = max(0, (int)($meta['lifetime'] ?? 0));
        self::write(hash('sha256', $sessionId), [
            'kind' => self::WEBGUI,
            'file' => self::sessionFile($sessionId),
            'username' => (string)($meta['username'] ?? ''),
            'provider' => (string)($meta['provider'] ?? ''),
            'issuer' => (string)($meta['issuer'] ?? ''),
            'sub' => (string)($meta['sub'] ?? ''),
            'sid' => (string)($meta['sid'] ?? ''),
            'started' => time(),
            'expires_at' => $lifetime > 0 ? time() + $lifetime : 0,
        ]);
    }

    /**
     * Remember an access that is not a WebGUI session: a captive-portal client that was
     * let onto the network, or an OpenVPN tunnel that was allowed up.
     *
     * Without these, a revocation only reached the WebGUI. The IdP would end a session,
     * SCIM would deactivate the account, and the person stayed on the wifi and inside
     * the tunnel until those timed out on their own -- which is the half of "revoked"
     * that matters on a firewall.
     *
     * The provider's maximum session lifetime applies here as much as it does to a WebGUI
     * session, and for a better reason: a tab that idles out is at least a session that
     * ends by itself, while a tunnel and a portal client have nothing that reconsiders
     * them at all. Ignoring it meant a provider set to an hour still left both on the
     * network for a day. Bounded by GRANT_TTL either way, so the record cannot outlive
     * the point of keeping it.
     *
     * @param array $meta kind (portal|vpn), username, provider, issuer, sub, sid,
     *        lifetime (s, 0 = none), plus what it takes to take it away: cp_session +
     *        zone, or vpn_cn
     * @return bool whether the record was actually written -- a caller that grants
     *         network access has to know, since an access nothing recorded is one
     *         nothing can revoke
     */
    public static function recordGrant(array $meta): bool
    {
        $kind = (string)($meta['kind'] ?? '');
        if (!in_array($kind, [self::PORTAL, self::VPN], true)) {
            return false;
        }
        $lifetime = max(0, (int)($meta['lifetime'] ?? 0));
        return self::write(hash('sha256', $kind . '|' . bin2hex(random_bytes(16))), [
            'kind' => $kind,
            'username' => (string)($meta['username'] ?? ''),
            'provider' => (string)($meta['provider'] ?? ''),
            'issuer' => (string)($meta['issuer'] ?? ''),
            'sub' => (string)($meta['sub'] ?? ''),
            'sid' => (string)($meta['sid'] ?? ''),
            'cp_session' => (string)($meta['cp_session'] ?? ''),
            'zone' => (string)($meta['zone'] ?? ''),
            'vpn_cn' => (string)($meta['vpn_cn'] ?? ''),
            'started' => time(),
            'expires_at' => time() + ($lifetime > 0 ? min($lifetime, self::GRANT_TTL) : self::GRANT_TTL),
        ]);
    }

    /**
     * Persist one record, 0600, named by the handle the diagnostics page hands back.
     *
     * @return bool whether the record is on disk. A failure used to be a warning and
     *         nothing else, which is fine for a WebGUI session -- it still has a session
     *         file, an idle timeout and an account behind it -- and not fine for a grant
     *         whose record is the ONLY handle anything has on it.
     */
    private static function write(string $handle, array $entry): bool
    {
        try {
            $file = StateDir::path('sessions') . '/' . $handle . '.json';
        } catch (\RuntimeException $e) {
            syslog(LOG_WARNING, 'os-sso: cannot record the session: ' . $e->getMessage());
            return false;
        }
        if (@file_put_contents($file, json_encode($entry), LOCK_EX) === false) {
            syslog(LOG_WARNING, 'os-sso: cannot write the session record ' . $file);
            return false;
        }
        @chmod($file, 0600);
        return true;
    }

    /** Drop the record for a session that ended normally. */
    public static function forget(string $sessionId): void
    {
        try {
            @unlink(self::recordFile($sessionId));
        } catch (\RuntimeException $e) {
            // nothing to clean up
        }
    }

    /**
     * End every recorded session matching a filter, deleting the PHP session file.
     *
     * @param callable $matches fn(array $entry): bool
     * @return int how many sessions were ended
     */
    public static function destroyWhere(callable $matches): int
    {
        $killed = 0;
        foreach (self::entries() as $file => $entry) {
            if (!$matches($entry)) {
                continue;
            }
            self::revoke($entry);
            @unlink($file);
            $killed++;
        }
        return $killed;
    }

    /**
     * Take away whatever a record granted.
     *
     * Three different things, one intent: delete the PHP session file so the next
     * request lands on the login page, ask configd to drop the captive-portal session
     * (which also removes the client's address from the zone's pf table), or ask it to
     * kill the tunnels of that common name.
     */
    private static function revoke(array $entry): void
    {
        switch ((string)($entry['kind'] ?? self::WEBGUI)) {
            case self::PORTAL:
                $session = (string)($entry['cp_session'] ?? '');
                if ($session !== '') {
                    (new Backend())->configdpRun('captiveportal disconnect', [$session, 'os-sso revocation']);
                }
                break;
            case self::VPN:
                $commonName = (string)($entry['vpn_cn'] ?? '');
                if ($commonName !== '') {
                    (new Backend())->configdpRun('sso vpn_kill', [$commonName]);
                }
                break;
            default:
                $target = (string)($entry['file'] ?? '');
                // Only ever unlink inside the session directory we recorded from.
                if ($target !== '' && str_contains(basename($target), 'sess_') && is_file($target)) {
                    @unlink($target);
                }
        }
    }

    /**
     * End sessions that reached their absolute lifetime, and forget records whose
     * PHP session is already gone (idle timeout, logout, session GC).
     *
     * @return int sessions ended
     */
    public static function sweep(): int
    {
        $now = time();
        $accounts = new LocalAccountWriter();
        return self::destroyWhere(function (array $entry) use ($now, $accounts) {
            $expires = (int)($entry['expires_at'] ?? 0);
            if ($expires > 0 && $expires <= $now) {
                return true;
            }
            // An account disabled or expired since the login keeps whatever it was
            // granted until it makes a request -- and a captive-portal client or a
            // tunnel never makes one to us at all. The operator's own checkbox, an
            // <expires> date and anything that disabled the account outside the two
            // paths that end sessions themselves all land here.
            $username = (string)($entry['username'] ?? '');
            if ($username !== '') {
                $node = $accounts->findByName($username);
                if ($node !== null && !LocalAccount::isUsable($node)) {
                    return true;
                }
            }
            // A portal or VPN grant has no PHP session behind it; its own deadline is
            // the only thing that retires it (see GRANT_TTL).
            return (string)($entry['kind'] ?? self::WEBGUI) === self::WEBGUI
                && !is_file((string)($entry['file'] ?? ''));
        });
    }

    /**
     * End the sessions of one IdP subject -- what a back-channel logout asks for.
     * Matching on the IdP session id when the logout token carries one, otherwise on
     * the subject, always scoped to the issuer that vouched for it.
     */
    public static function destroyForSubject(string $issuer, string $sub, string $sid): int
    {
        if ($issuer === '' || ($sub === '' && $sid === '')) {
            return 0;
        }
        return self::destroyWhere(function (array $entry) use ($issuer, $sub, $sid) {
            if ((string)($entry['issuer'] ?? '') !== $issuer) {
                return false;
            }
            if ($sid !== '' && (string)($entry['sid'] ?? '') !== '') {
                return hash_equals((string)$entry['sid'], $sid);
            }
            return $sub !== '' && hash_equals((string)($entry['sub'] ?? ''), $sub);
        });
    }

    /**
     * Every recorded session still backed by a live PHP session, newest first.
     * Read-only view for the diagnostics page.
     *
     * @return array<int,array>
     */
    public static function listActive(): array
    {
        $out = [];
        foreach (self::entries() as $entry) {
            $isWebgui = (string)($entry['kind'] ?? self::WEBGUI) === self::WEBGUI;
            if ($isWebgui && !is_file((string)($entry['file'] ?? ''))) {
                continue;
            }
            unset($entry['file']); // a filesystem path is not diagnostics material
            $entry['kind'] = (string)($entry['kind'] ?? self::WEBGUI);
            $out[] = $entry;
        }
        usort($out, fn($a, $b) => (int)($b['started'] ?? 0) <=> (int)($a['started'] ?? 0));
        return $out;
    }

    /**
     * End one recorded session, named by the handle listActive() reports.
     *
     * The handle is the digest of the session id, never the id itself: it is enough to
     * say which row an administrator clicked, and it cannot be turned back into a
     * cookie by anyone who reads it off the diagnostics page.
     *
     * @return int 1 when a session was ended, 0 when the handle matched nothing
     */
    public static function destroyById(string $id): int
    {
        if (!preg_match('/^[a-f0-9]{64}$/', $id)) {
            return 0;
        }
        return self::destroyWhere(fn(array $entry) => hash_equals((string)($entry['id'] ?? ''), $id));
    }

    /** End every session os-sso opened, whoever they belong to. */
    public static function destroyAll(): int
    {
        return self::destroyWhere(fn(array $entry) => true);
    }

    /** @return array<string,array> record path => entry (each carrying its handle) */
    private static function entries(): array
    {
        try {
            $dir = StateDir::path('sessions');
        } catch (\RuntimeException $e) {
            // Say so: everything here degrades to "no sessions known", which reads
            // exactly like "nothing to expire" in the sweeper's output.
            syslog(LOG_WARNING, 'os-sso: the session registry is unreachable: ' . $e->getMessage());
            return [];
        }
        $out = [];
        foreach (glob($dir . '/*.json') ?: [] as $file) {
            $entry = json_decode((string)@file_get_contents($file), true);
            if (is_array($entry)) {
                // The record's own name is the digest of the session id, which is what
                // the diagnostics page hands back to end one.
                $entry['id'] = basename($file, '.json');
                $out[$file] = $entry;
            } else {
                @unlink($file); // unreadable leftover
            }
        }
        return $out;
    }

    private static function recordFile(string $sessionId): string
    {
        return StateDir::path('sessions') . '/' . hash('sha256', $sessionId) . '.json';
    }

    private static function sessionFile(string $sessionId): string
    {
        $path = (string)session_save_path();
        // save_path may carry "N;/path" or "N;MODE;/path" prefixes.
        if (str_contains($path, ';')) {
            $parts = explode(';', $path);
            $path = (string)end($parts);
        }
        return ($path !== '' ? $path : sys_get_temp_dir()) . '/sess_' . $sessionId;
    }
}
