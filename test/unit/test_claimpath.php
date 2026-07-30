<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\ClaimPath;

/**
 * Claims arrive in two shapes: an ID token decoded to nested stdClass, and a userinfo
 * document decoded to nested arrays. Both are tested, because a path that only walks
 * one of them silently returns nothing for the other -- which reads as "the IdP sends
 * no groups".
 */
$asObjects = (array)json_decode(json_encode([
    'sub' => 'u1',
    'groups' => ['a', 'b'],
    'realm_access' => ['roles' => ['admins', 'vpn']],
    'resource_access' => ['opnsense' => ['roles' => ['net-admin']]],
    'urn:oid:0.9.2342.19200300.100.1.1' => 'oid-name',
    'csv' => 'one, two three',
    'nested' => ['deep' => ['arr' => [['x' => 1]], 'num' => 7, 'nil' => null]],
]));
$asArrays = json_decode(json_encode($asObjects), true);

foreach (['stdClass tree' => $asObjects, 'array tree' => $asArrays] as $shape => $claims) {
    T::group("ClaimPath: {$shape}");

    eq(['a', 'b'], ClaimPath::groups($claims, 'groups'), 'a top-level array claim');
    eq(['admins', 'vpn'], ClaimPath::groups($claims, 'realm_access.roles'), 'Keycloak realm roles');
    eq(
        ['net-admin'],
        ClaimPath::groups($claims, 'resource_access.opnsense.roles'),
        'Keycloak client roles, three levels deep'
    );
    // A claim NAME containing dots must win over splitting it into a path.
    eq(
        ['oid-name'],
        ClaimPath::groups($claims, 'urn:oid:0.9.2342.19200300.100.1.1'),
        'an OID-style claim name is matched whole'
    );
    eq(['one', 'two', 'three'], ClaimPath::groups($claims, 'csv'), 'a string claim splits on commas and spaces');
    eq('u1', ClaimPath::get($claims, 'sub'), 'get returns a scalar claim');
    eq(7, ClaimPath::get($claims, 'nested.deep.num'), 'get walks to a nested scalar');

    // Nothing found is an empty list, never a fabricated one.
    eq([], ClaimPath::groups($claims, 'missing'), 'an absent claim yields no groups');
    eq([], ClaimPath::groups($claims, 'realm_access.nope'), 'an absent leaf yields no groups');
    eq([], ClaimPath::groups($claims, 'sub.deeper'), 'walking past a scalar yields no groups');
    eq([], ClaimPath::groups($claims, ''), 'an empty path yields no groups');
    eq(null, ClaimPath::get($claims, 'missing'), 'get returns null for an absent claim');
    eq(null, ClaimPath::get($claims, ''), 'get returns null for an empty path');

    // A non-scalar entry must be dropped, not stringified: "Array" would become a group
    // name and collide every such user onto it.
    eq([], ClaimPath::groups($claims, 'nested.deep.arr'), 'a list of objects yields no group names');
    eq([], ClaimPath::groups($claims, 'nested.deep.nil'), 'a null claim yields no groups');
    eq(['7'], ClaimPath::groups($claims, 'nested.deep.num'), 'a scalar claim becomes one group name');
}

T::group('ClaimPath: edge shapes');

eq([], ClaimPath::groups([], 'groups'), 'no claims at all');
eq(['x'], ClaimPath::groups(['groups' => 'x'], 'groups'), 'a single-name string claim');
eq([], ClaimPath::groups(['groups' => ''], 'groups'), 'an empty string claim');
eq([], ClaimPath::groups(['groups' => []], 'groups'), 'an empty array claim');
eq(['a', 'b'], ClaimPath::groups(['groups' => ['a', '', 'b']], 'groups'), 'empty entries are dropped');
eq(['a', 'b'], ClaimPath::groups(['groups' => "a\tb"], 'groups'), 'tab-separated names');
eq(['0'], ClaimPath::groups(['groups' => ['0']], 'groups'), 'a group literally named "0" survives');
