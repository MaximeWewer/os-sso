<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\SourceGate;

T::group('SourceGate: the allowlist that makes header-auth and SCIM safe');

// An empty list means nobody, never everybody. Both callers depend on this: it is what
// makes a JWT provider with no trusted proxy, or SCIM with no source list, fail closed.
falsy(SourceGate::allows('10.0.0.1', []), 'an empty allowlist matches nothing');
falsy(SourceGate::allows('10.0.0.1', ['']), 'a blank entry matches nothing');
falsy(SourceGate::allows('', ['10.0.0.0/8']), 'an empty peer matches nothing');
falsy(SourceGate::allows('not-an-ip', ['0.0.0.0/0']), 'a non-address peer matches nothing');

T::group('SourceGate: IPv4');

truthy(SourceGate::allows('10.1.2.3', ['10.1.2.3']), 'bare address, exact match');
falsy(SourceGate::allows('10.1.2.4', ['10.1.2.3']), 'bare address, no match');
truthy(SourceGate::allows('10.1.2.3', ['10.0.0.0/8']), 'inside /8');
falsy(SourceGate::allows('11.1.2.3', ['10.0.0.0/8']), 'outside /8');
truthy(SourceGate::allows('192.168.4.17', ['192.168.4.0/24']), 'inside /24');
falsy(SourceGate::allows('192.168.5.17', ['192.168.4.0/24']), 'outside /24');
truthy(SourceGate::allows('0.0.0.0', ['0.0.0.0/0']), '/0 matches everything v4');
truthy(SourceGate::allows('203.0.113.9', ['0.0.0.0/0']), '/0 matches any v4');
truthy(SourceGate::allows('10.0.0.5', ['10.0.0.4/31']), 'non-byte-aligned prefix, inside');
falsy(SourceGate::allows('10.0.0.6', ['10.0.0.4/31']), 'non-byte-aligned prefix, outside');
truthy(SourceGate::allows('10.0.0.130', ['10.0.0.128/25']), '/25 inside');
falsy(SourceGate::allows('10.0.0.127', ['10.0.0.128/25']), '/25 just outside');
truthy(SourceGate::allows('10.1.2.3', ['10.1.2.3/32']), '/32 exact');

T::group('SourceGate: IPv6 and cross-family');

truthy(SourceGate::allows('2001:db8::1', ['2001:db8::/32']), 'inside a v6 prefix');
falsy(SourceGate::allows('2001:db9::1', ['2001:db8::/32']), 'outside a v6 prefix');
truthy(SourceGate::allows('2001:db8::1', ['2001:db8::1']), 'bare v6 address');
truthy(SourceGate::allows('2001:db8::1', ['::/0']), '::/0 matches any v6');
// Families must not cross: a v4 peer inside "::/0" would be a silent allow-all.
falsy(SourceGate::allows('10.0.0.1', ['::/0']), 'a v4 peer is not inside ::/0');
falsy(SourceGate::allows('2001:db8::1', ['0.0.0.0/0']), 'a v6 peer is not inside 0.0.0.0/0');
truthy(SourceGate::allows('2001:db8::1', ['0.0.0.0/0', '::/0']), 'both families listed');

T::group('SourceGate: malformed entries are skipped, not fatal');

falsy(SourceGate::allows('10.0.0.1', ['garbage']), 'a junk entry matches nothing');
falsy(SourceGate::allows('10.0.0.1', ['10.0.0.0/999']), 'an out-of-range prefix is skipped');
falsy(SourceGate::allows('10.0.0.1', ['10.0.0.0/-1']), 'a negative prefix is skipped');
falsy(SourceGate::allows('10.0.0.1', ['not/8']), 'a junk network is skipped');
// A bad entry must not stop a good one later in the list from matching.
truthy(SourceGate::allows('10.0.0.1', ['garbage', '10.0.0.0/8']), 'a later valid entry still matches');
truthy(SourceGate::allows('10.0.0.1', [' 10.0.0.0/8 ']), 'surrounding whitespace is tolerated');
