<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * A per-source-IP cap on how often the pre-auth SSO endpoints may be hit.
 *
 * These endpoints are reachable without a session, and each one costs real work:
 * signature verification, an outbound call to the IdP, a config.xml write. Core's
 * login lockout does not cover them -- it guards the password form, and nothing here
 * goes through it. This is not an anti-brute-force measure (there is no secret to
 * guess: a forged assertion fails on its signature) but a floor under how much a
 * stranger can make the firewall do.
 *
 * Deliberately blunt and dependency-free: a bucket per (action, IP) holding recent
 * timestamps in a small JSON file. The read-modify-write is not atomic, so a burst of
 * simultaneous requests can slip a couple over the limit -- which is fine for a
 * throttle and much cheaper than serialising every login on a lock.
 */
final class RateLimiter
{
    /** Buckets untouched for this long are swept away. */
    private const IDLE_TTL = 3600;

    /**
     * Count one request, and refuse it when the window is already full.
     *
     * @param string $action bucket name, e.g. "oidc-login"
     * @param string $clientIp source address (REMOTE_ADDR)
     * @param int $limit requests allowed per window
     * @param int $window window length in seconds
     * @throws \RuntimeException when the caller is over the limit
     */
    public static function hit(string $action, string $clientIp, int $limit, int $window = 60): void
    {
        if ($limit <= 0 || $clientIp === '') {
            return;
        }
        try {
            $file = self::bucketFile($action, $clientIp);
        } catch (\RuntimeException $e) {
            return; // no state directory: never let the throttle break logins
        }
        self::sweep();

        $now = time();
        $hits = json_decode((string)@file_get_contents($file), true);
        $hits = is_array($hits) ? array_values(array_filter(
            array_map('intval', $hits),
            fn($ts) => $ts > $now - $window
        )) : [];

        if (count($hits) >= $limit) {
            syslog(LOG_WARNING, sprintf(
                'os-sso: rate limit reached for %s from %s (%d requests in %ds)',
                $action,
                preg_replace('/[^0-9a-fA-F.:]/', '', $clientIp),
                count($hits),
                $window
            ));
            throw new \RuntimeException('too many requests, try again shortly');
        }

        $hits[] = $now;
        @file_put_contents($file, json_encode($hits), LOCK_EX);
        @chmod($file, 0600);
    }

    /** Drop buckets nobody has touched in a while. */
    private static function sweep(): void
    {
        // Cheap enough to do inline: the directory only ever holds one small file per
        // active source address.
        try {
            $dir = StateDir::path('ratelimit');
        } catch (\RuntimeException $e) {
            return;
        }
        foreach (glob($dir . '/*.json') ?: [] as $file) {
            if ((time() - (int)@filemtime($file)) > self::IDLE_TTL) {
                @unlink($file);
            }
        }
    }

    private static function bucketFile(string $action, string $clientIp): string
    {
        return StateDir::path('ratelimit') . '/' . hash('sha256', $action . '|' . $clientIp) . '.json';
    }
}
