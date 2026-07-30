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
 * timestamps in a small JSON file, counted under a per-bucket exclusive lock so a burst
 * of simultaneous requests cannot each read the same count and each conclude it is
 * under the limit. The lock is per (action, IP), so it never serialises unrelated
 * logins -- only the requests actually competing for one bucket.
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
            // No usable state directory. Staying open is deliberate -- there is no secret
            // to guess here, and the paths that matter already fail closed without us
            // (ConfigLock and the SAML request store both need the same directory) -- but
            // going quiet is not: this is a security control switching itself off, and it
            // was the one StateDir consumer that said nothing while every other one warns.
            self::warnDisabled($action, 'the state directory is unusable: ' . $e->getMessage());
            return;
        }
        self::sweep();

        // Count under one exclusive lock held across BOTH the read and the write. With
        // the lock on the write alone, the read sat outside it: parallel requests all
        // loaded the same bucket, all found room, and all proceeded -- the burst a
        // throttle exists to stop was the one case it did not catch.
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            // Cannot account for this hit; not a reason to break the login, but the
            // operator still needs to know the ceiling is not being applied.
            self::warnDisabled($action, 'the bucket file cannot be opened');
            return;
        }
        try {
            if (!flock($fp, LOCK_EX)) {
                self::warnDisabled($action, 'the bucket lock cannot be taken');
                return;
            }
            @chmod($file, 0600);

            $now = time();
            $hits = json_decode((string)stream_get_contents($fp), true);
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
            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, (string)json_encode($hits));
            fflush($fp);
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Say once, per process, that the throttle is not being applied.
     *
     * Once, because this sits on endpoints that are hit in bursts and a line per request
     * would bury the thing it is reporting -- and a php-fpm worker handling one request
     * is exactly the granularity that makes "it happened" visible without the noise.
     */
    private static function warnDisabled(string $action, string $why): void
    {
        static $warned = false;
        if ($warned) {
            return;
        }
        $warned = true;
        syslog(LOG_WARNING, sprintf(
            'os-sso: the rate limit on %s is NOT being applied -- %s',
            $action,
            $why
        ));
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
        return StateDir::path('ratelimit') . '/' . hash('sha256', $action . '|' . self::bucket($clientIp)) . '.json';
    }

    /**
     * The source a request is counted against.
     *
     * IPv4 counts per address, IPv6 per /64. Counting a v6 client per address is not a
     * limit at all: the smallest prefix anyone is handed is a /64, so a single machine
     * picks a fresh source address for every request and every one of them starts with
     * an empty bucket. The /64 is the smallest unit that actually belongs to one
     * customer, and it is what other throttles on this box work in too.
     */
    public static function bucket(string $clientIp): string
    {
        $binary = @inet_pton($clientIp);
        if ($binary === false || strlen($binary) !== 16) {
            return $clientIp;
        }
        $network = @inet_ntop(substr($binary, 0, 8) . str_repeat("\0", 8));
        return $network === false ? $clientIp : $network . '/64';
    }
}
