<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\NavigationGuard;

T::group('NavigationGuard: a login is a navigation, not a subresource');

/** Run the guard with one Sec-Fetch-Dest value in place. */
function withDest(?string $dest, callable $fn)
{
    $previous = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    if ($dest === null) {
        unset($_SERVER['HTTP_SEC_FETCH_DEST']);
    } else {
        $_SERVER['HTTP_SEC_FETCH_DEST'] = $dest;
    }
    try {
        return $fn();
    } finally {
        if ($previous === null) {
            unset($_SERVER['HTTP_SEC_FETCH_DEST']);
        } else {
            $_SERVER['HTTP_SEC_FETCH_DEST'] = $previous;
        }
    }
}

withDest('document', fn() => nothrow(
    fn() => NavigationGuard::assertNavigation(),
    'a top-level navigation is what a login looks like'
));
withDest('Document', fn() => nothrow(
    fn() => NavigationGuard::assertNavigation(),
    'the value is compared case-insensitively'
));
// No header at all: an old browser, or something that is not one. This closes a hole,
// it does not become the authentication.
withDest(null, fn() => nothrow(
    fn() => NavigationGuard::assertNavigation(),
    'a request without the header is left alone'
));
withDest('', fn() => nothrow(fn() => NavigationGuard::assertNavigation(), 'an empty header too'));

foreach (['image', 'iframe', 'script', 'empty', 'object', 'style'] as $dest) {
    withDest($dest, fn() => throws(
        fn() => NavigationGuard::assertNavigation(),
        'not a top-level navigation',
        "refuses a request made for a {$dest}"
    ));
}

// The message goes to syslog, so the attacker-supplied value must not carry a line with
// it.
withDest("image\ninjected: line", fn() => throws(
    function () {
        try {
            NavigationGuard::assertNavigation();
        } catch (\RuntimeException $e) {
            falsy(str_contains($e->getMessage(), "\n"), 'the reported value carries no newline');
            throw $e;
        }
    },
    'not a top-level navigation',
    'a crafted header value is still refused'
));
