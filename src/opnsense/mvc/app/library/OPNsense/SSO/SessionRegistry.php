<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * A record of the WebGUI sessions os-sso opened, so they can be ended from outside
 * the browser that owns them.
 *
 * Everything else in this plugin happens during a login. Once the session exists the
 * IdP is out of the loop: disable the account there, revoke its groups, and the
 * already-open firewall session carries on until it idles out. That is the gap this
 * closes -- it is what a back-channel logout needs to find (which PHP session belongs
 * to that IdP subject), and what an absolute session lifetime needs to enforce.
 *
 * Killing a session means deleting its PHP session file: the next request from that
 * browser finds no session and lands on the login page. The file path is recorded at
 * login rather than recomputed later, because the sweeper runs as root from configd
 * and its own session.save_path is not necessarily php-fpm's.
 */
final class SessionRegistry
{
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
        $entry = [
            'file' => self::sessionFile($sessionId),
            'username' => (string)($meta['username'] ?? ''),
            'provider' => (string)($meta['provider'] ?? ''),
            'issuer' => (string)($meta['issuer'] ?? ''),
            'sub' => (string)($meta['sub'] ?? ''),
            'sid' => (string)($meta['sid'] ?? ''),
            'started' => time(),
            'expires_at' => $lifetime > 0 ? time() + $lifetime : 0,
        ];
        try {
            @file_put_contents(self::recordFile($sessionId), json_encode($entry), LOCK_EX);
            @chmod(self::recordFile($sessionId), 0600);
        } catch (\RuntimeException $e) {
            syslog(LOG_WARNING, 'os-sso: cannot record the session: ' . $e->getMessage());
        }
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
            $target = (string)($entry['file'] ?? '');
            // Only ever unlink inside the session directory we recorded from.
            if ($target !== '' && str_contains(basename($target), 'sess_') && is_file($target)) {
                @unlink($target);
            }
            @unlink($file);
            $killed++;
        }
        return $killed;
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
        return self::destroyWhere(function (array $entry) use ($now) {
            $expires = (int)($entry['expires_at'] ?? 0);
            if ($expires > 0 && $expires <= $now) {
                return true;
            }
            return !is_file((string)($entry['file'] ?? ''));
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
            if (!is_file((string)($entry['file'] ?? ''))) {
                continue;
            }
            unset($entry['file']); // a filesystem path is not diagnostics material
            $out[] = $entry;
        }
        usort($out, fn($a, $b) => (int)($b['started'] ?? 0) <=> (int)($a['started'] ?? 0));
        return $out;
    }

    /** @return array<string,array> record path => entry */
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
