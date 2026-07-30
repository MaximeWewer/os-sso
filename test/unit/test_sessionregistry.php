<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * How long what os-sso granted stays granted. A WebGUI session at least idles out on its
 * own; a captive-portal client and an OpenVPN tunnel have nothing here that reconsiders
 * them, so the deadline recorded at login is the only thing that ever will.
 */

use OPNsense\SSO\SessionRegistry;

if (!stateDirUsable()) {
    T::group('SessionRegistry');
    T::skip('the whole group', 'needs a writable /var/db/os-sso');
    return;
}

/** Drop every record, so each case below counts only its own. */
function clearRegistry(): void
{
    SessionRegistry::destroyAll();
}

/** The single recorded grant, or null. */
function onlyGrant(): ?array
{
    $rows = SessionRegistry::listActive();
    return count($rows) === 1 ? $rows[0] : null;
}

T::group('SessionRegistry: a grant carries the provider maximum session lifetime');

clearRegistry();
SessionRegistry::recordGrant([
    'kind' => SessionRegistry::PORTAL,
    'username' => 'guest',
    'provider' => 'kc',
    'cp_session' => 'cp-1',
    'zone' => '1',
    'lifetime' => 3600,
]);
$grant = onlyGrant();
truthy($grant !== null, 'the portal grant was recorded');
// Compared as a window rather than an instant: the record is written a moment after the
// clock is read here.
$ttl = (int)$grant['expires_at'] - time();
truthy($ttl > 3540 && $ttl <= 3600, "a 1h lifetime becomes a 1h deadline (got {$ttl}s)");

clearRegistry();
SessionRegistry::recordGrant([
    'kind' => SessionRegistry::VPN,
    'username' => 'kctest',
    'provider' => 'kc',
    'vpn_cn' => 'kctest',
    'lifetime' => 900,
]);
$ttl = (int)onlyGrant()['expires_at'] - time();
truthy($ttl > 840 && $ttl <= 900, "a VPN tunnel gets the same deadline (got {$ttl}s)");

T::group('SessionRegistry: without one, a grant still retires on its own');

clearRegistry();
SessionRegistry::recordGrant([
    'kind' => SessionRegistry::PORTAL,
    'username' => 'guest',
    'provider' => 'kc',
    'cp_session' => 'cp-2',
    'zone' => '1',
]);
$ttl = (int)onlyGrant()['expires_at'] - time();
truthy($ttl > 86340 && $ttl <= 86400, "no lifetime falls back to the 24h cap (got {$ttl}s)");

// A lifetime longer than the cap does not extend it: the record is only useful for
// revoking, and one that outlives the thing it describes is a row nobody will ever use.
clearRegistry();
SessionRegistry::recordGrant([
    'kind' => SessionRegistry::VPN,
    'username' => 'kctest',
    'provider' => 'kc',
    'vpn_cn' => 'kctest',
    'lifetime' => 7 * 86400,
]);
$ttl = (int)onlyGrant()['expires_at'] - time();
truthy($ttl > 86340 && $ttl <= 86400, "a week-long lifetime is capped at 24h (got {$ttl}s)");

clearRegistry();
