<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The state directory is shared by two users -- php-fpm (www) writes it during a login,
 * the scheduled sweeper reads it as root -- and it holds a JWKS cache, i.e. the keys
 * signature verification trusts. So it has to be usable by both and writable by nobody
 * else, and the failure mode of getting that wrong is silent on both sides.
 */

use OPNsense\SSO\StateDir;

T::group('StateDir: naming');

foreach (['../etc', 'oidc/../..', 'OIDC', 'a b', ''] as $bad) {
    throws(fn() => StateDir::path($bad), 'invalid state directory name', 'refuses ' . json_encode($bad));
}

if (!stateDirUsable()) {
    T::group('StateDir: layout');
    T::skip('the whole group', 'needs a writable ' . StateDir::ROOT);
    return;
}

T::group('StateDir: layout');

$dir = nothrow(fn() => StateDir::path('unit-test'), 'a fresh bucket is created');
eq(StateDir::ROOT . '/unit-test', $dir, 'under the plugin root');
eq(0, fileperms($dir) & 0077, 'and grants nothing to group or other');
eq($dir, StateDir::path('unit-test'), 'a second call is idempotent');

// Belt and braces: a bucket someone else owns is refused rather than written into --
// a JWKS cache an attacker can write is a signature-verification bypass.
if (function_exists('posix_geteuid') && posix_geteuid() === 0 && function_exists('posix_getpwnam')) {
    $nobody = @posix_getpwnam('nobody');
    if (is_array($nobody)) {
        chown($dir, (int)$nobody['uid']);
        throws(fn() => StateDir::path('unit-test'), 'owned by another user', 'a bucket owned by a third user is refused');
        chown($dir, 0);
    }
}

rmdir($dir);
