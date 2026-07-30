<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The pre-auth endpoints are reachable without a session and each one costs real work,
 * so there is a floor under how much a stranger can make the firewall do. What matters
 * here is what counts as "a stranger": per address in IPv4, per /64 in IPv6, where a
 * single machine is handed more addresses than a counter can outlast.
 */

use OPNsense\SSO\RateLimiter;

T::group('RateLimiter: what a request is counted against');

eq('192.0.2.7', RateLimiter::bucket('192.0.2.7'), 'IPv4 counts per address');
eq('2001:db8::/64', RateLimiter::bucket('2001:db8::1'), 'IPv6 counts per /64');
eq(
    RateLimiter::bucket('2001:db8::1'),
    RateLimiter::bucket('2001:db8:0:0:ffff:ffff:ffff:ffff'),
    'two addresses in one /64 share a bucket'
);
truthy(
    RateLimiter::bucket('2001:db8::1') !== RateLimiter::bucket('2001:db8:0:1::1'),
    'a neighbouring /64 does not'
);
eq('not-an-ip', RateLimiter::bucket('not-an-ip'), 'anything unparsable is used as-is');

if (!stateDirUsable()) {
    T::group('RateLimiter: counting');
    T::skip('the whole group', 'needs a writable /var/db/os-sso');
    return;
}

T::group('RateLimiter: counting');

$action = 'unit-' . bin2hex(random_bytes(4));
nothrow(fn() => RateLimiter::hit($action, '198.51.100.9', 2), 'the first request goes through');
nothrow(fn() => RateLimiter::hit($action, '198.51.100.9', 2), 'so does the second');
throws(fn() => RateLimiter::hit($action, '198.51.100.9', 2), 'too many requests', 'the third is refused');
nothrow(fn() => RateLimiter::hit($action, '198.51.100.10', 2), 'another source has its own bucket');

// The bypass this closed: one machine, a routed prefix, a new source address per request.
$action = 'unit-' . bin2hex(random_bytes(4));
nothrow(fn() => RateLimiter::hit($action, '2001:db8:1::1', 2), 'a v6 client gets its two');
nothrow(fn() => RateLimiter::hit($action, '2001:db8:1::2', 2), 'from any address in its /64');
throws(fn() => RateLimiter::hit($action, '2001:db8:1::3', 2), 'too many requests', 'and rotating within it does not reset the count');
nothrow(fn() => RateLimiter::hit($action, '2001:db8:2::1', 2), 'while a different /64 is a different client');

nothrow(fn() => RateLimiter::hit($action, '2001:db8:1::9', 0), 'a limit of zero disables the throttle');
nothrow(fn() => RateLimiter::hit($action, '', 1), 'and a request with no source is not counted');
