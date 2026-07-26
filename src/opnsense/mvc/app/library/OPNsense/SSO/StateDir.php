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
        self::assertSafe($dir);
    }

    /**
     * A directory is safe when it is not a symlink, is owned by this process or by
     * root, and grants nothing to group or other.
     */
    private static function assertSafe(string $dir): void
    {
        clearstatcache(true, $dir);
        if (is_link($dir) || !is_dir($dir)) {
            throw new \RuntimeException(sprintf('SSO: %s is not a directory', $dir));
        }
        $owner = @fileowner($dir);
        if ($owner === false || ($owner !== 0 && $owner !== self::uid())) {
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

    private static function uid(): int
    {
        return function_exists('posix_geteuid') ? (int)posix_geteuid() : (int)getmyuid();
    }
}
