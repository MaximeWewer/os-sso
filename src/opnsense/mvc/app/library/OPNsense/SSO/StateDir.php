<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Owner of every on-disk location the WebGUI side of os-sso writes: the JWKS /
 * discovery caches, the SAML in-flight request state, the config lock. (The OpenVPN
 * session map is root-only and lives in its own /var/db/os-sso-vpn, written by the
 * auth-user-pass-verify and verdict scripts -- www never touches it.)
 *
 * These used to live directly under /var/tmp, which is world-writable and sticky:
 * any local account could pre-create os-sso's directory and own it before we did.
 * A JWKS cache an attacker can write is a signature-verification bypass -- the
 * cached "public key" is simply theirs. /var/db is root-owned 0755, so a subdirectory
 * created there cannot be squatted in the first place.
 *
 * Belt and braces on top of the location: every use re-checks the directory is a real
 * directory (not a symlink), belongs to us or to root, and is not group/other
 * accessible -- and FAILS the operation rather than writing into something suspect.
 * Silently degrading is exactly how a cache-poisoning bug survives a review.
 */
final class StateDir
{
    public const ROOT = '/var/db/os-sso';

    /**
     * Absolute path of a vetted os-sso state directory, created on first use.
     *
     * @param string $name subdirectory name ('oidc', 'jwt', 'saml', 'vpn', 'run')
     * @throws \RuntimeException when the directory cannot be created or is not safe
     */
    public static function path(string $name): string
    {
        if (!preg_match('/^[a-z0-9-]+$/', $name)) {
            throw new \RuntimeException('SSO: invalid state directory name');
        }
        self::ensure(self::ROOT);
        $dir = self::ROOT . '/' . $name;
        self::ensure($dir);
        return $dir;
    }

    /** Create $dir 0700 if missing, then assert it is safe to write into. */
    private static function ensure(string $dir): void
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException(sprintf('SSO: cannot create the state directory %s', $dir));
        }
        self::adopt($dir);
        self::assertSafe($dir);
    }

    /**
     * Hand a root-created directory over to the WebGUI user, where there is one.
     *
     * The case this exists for: two processes sharing the tree under different accounts
     * -- a web tier writing during a login, and the session sweeper running as root out
     * of configd -- where whichever ran first would own it at 0700 and lock the other
     * out. Root first means every SSO login fails on the config lock; www first means the
     * sweeper silently finds nothing and the maximum session lifetime is never enforced.
     *
     * On OPNsense itself this never fires, and is not what makes the tree work. Both ends
     * already run as root -- the /api/sso endpoints included, so the tree is created
     * root-owned on the first request -- and posix is not compiled into its php83, so
     * webUid() returns null and this returns immediately. Kept as belt and braces for a
     * platform where neither of those holds; if OPNsense ever moves the API off root,
     * this has to start working (webUid() would need to read /etc/passwd rather than ask
     * posix) or every login fails closed on an unusable state directory.
     */
    private static function adopt(string $dir): void
    {
        $web = self::webUid();
        if ($web === null || self::uid() !== 0) {
            return;
        }
        clearstatcache(true, $dir);
        if (@fileowner($dir) === 0) {
            @chown($dir, $web['uid']);
            @chgrp($dir, $web['gid']);
            clearstatcache(true, $dir);
        }
    }

    /**
     * uid/gid of the WebGUI user, null when there is none to ask about.
     *
     * Null on OPNsense, always: its php83 ships without ext-posix. That is survivable
     * only because nothing there needs the answer (see adopt()).
     *
     * @return array{uid:int,gid:int}|null
     */
    private static function webUid(): ?array
    {
        if (!function_exists('posix_getpwnam')) {
            return null;
        }
        $pw = @posix_getpwnam('www');
        return is_array($pw) ? ['uid' => (int)$pw['uid'], 'gid' => (int)$pw['gid']] : null;
    }

    /**
     * A directory is safe when it is not a symlink, is owned by one of the users that
     * legitimately share it -- this process, root, or the WebGUI user -- and grants
     * nothing to group or other.
     *
     * On OPNsense that list collapses to root alone, since uid() answers 0 and webUid()
     * answers nothing; a root-owned 0700 tree is exactly what runs there, so the check
     * is real rather than vacuous.
     */
    private static function assertSafe(string $dir): void
    {
        clearstatcache(true, $dir);
        if (is_link($dir) || !is_dir($dir)) {
            throw new \RuntimeException(sprintf('SSO: %s is not a directory', $dir));
        }
        $trusted = [0, self::uid()];
        $web = self::webUid();
        if ($web !== null) {
            $trusted[] = $web['uid'];
        }
        $owner = @fileowner($dir);
        if ($owner === false || !in_array($owner, $trusted, true)) {
            throw new \RuntimeException(sprintf('SSO: %s is owned by another user', $dir));
        }
        $perms = @fileperms($dir);
        if ($perms !== false && ($perms & 0077) !== 0) {
            // Try to fix a mode we own, otherwise refuse to use the directory.
            @chmod($dir, 0700);
            clearstatcache(true, $dir);
            if ((@fileperms($dir) & 0077) !== 0) {
                throw new \RuntimeException(sprintf('SSO: %s is group/world accessible', $dir));
            }
        }
    }

    /**
     * The uid this process counts as, for the ownership check above.
     *
     * Mind the fallback: getmyuid() is NOT the process uid, it is the owner of the
     * running script -- and with no ext-posix on OPNsense that fallback is the only path
     * taken. The plugin's files are deployed root-owned, so this answers 0 whoever is
     * executing, and assertSafe() ends up trusting a root-owned directory and nothing
     * else. That is the correct answer there by accident rather than by measurement, and
     * it fails closed rather than open the day it stops being: a directory owned by the
     * account actually running would be refused, loudly, instead of quietly accepted.
     */
    private static function uid(): int
    {
        return function_exists('posix_geteuid') ? (int)posix_geteuid() : (int)getmyuid();
    }
}
