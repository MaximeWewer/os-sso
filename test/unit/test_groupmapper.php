<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Group mapping decides privileges: the ACL resolves them from membership on every
 * request, so what lands here is what the user can do.
 */

use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Test\Tree;

T::group('GroupMapper: parsing the operator map');

eq(['a' => 'b'], GroupMapper::parseMap('a:b'), 'a colon pair');
eq(['a' => 'b'], GroupMapper::parseMap('a=b'), 'an equals pair');
eq(['a' => 'b'], GroupMapper::parseMap('  a : b  '), 'whitespace around the separator');
eq(['a' => 'b', 'c' => 'd'], GroupMapper::parseMap('a:b,c:d'), 'comma separated');
eq(['a' => 'b', 'c' => 'd'], GroupMapper::parseMap("a:b\nc:d"), 'newline separated');
eq(['a' => 'b:c'], GroupMapper::parseMap('a:b:c'), 'only the first separator splits');
eq([], GroupMapper::parseMap(''), 'an empty spec');
eq([], GroupMapper::parseMap('nopair'), 'a value with no separator is ignored');
eq([], GroupMapper::parseMap(':b'), 'an empty left side is ignored');
eq([], GroupMapper::parseMap('a:'), 'an empty right side is ignored');
eq(['a' => 'b'], GroupMapper::parseMap('a:b,,junk,'), 'malformed entries are skipped');

/** Sync $groups for a fresh tree and return the resulting membership. */
function syncGroups(array $asserted, array $defaults, array $map = [], bool $reconcile = false, array $extra = []): array
{
    $root = Tree::build(
        [array_merge(['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1'], $extra)],
        [
            ['name' => 'admins', 'gid' => '1999'],
            ['name' => 'shellers', 'gid' => '2000', 'priv' => ['user-shell-access']],
            ['name' => 'staff', 'gid' => '2001'],
            ['name' => 'vpn', 'gid' => '2002'],
            ['name' => 'MixedCase', 'gid' => '2003'],
        ]
    );
    $identity = new NormalizedIdentity('kc');
    $identity->groups = $asserted;
    $changed = (new GroupMapper($map, $reconcile))->sync(Tree::user($root, 'alice'), $identity, $defaults);
    $out = [];
    foreach (['admins', 'shellers', 'staff', 'vpn', 'MixedCase'] as $name) {
        if (in_array('2100', Tree::members($root, $name), true)) {
            $out[] = $name;
        }
    }
    return ['groups' => $out, 'changed' => $changed, 'root' => $root];
}

T::group('GroupMapper: the 1:1 fallback never escalates');

eq(['staff'], syncGroups(['staff'], [])['groups'], 'an IdP group matching a plain group is granted');
eq(['MixedCase'], syncGroups(['mixedcase'], [])['groups'], 'matching is case-insensitive');
// The IdP group name is frequently self-service, so a bare name match must not reach a
// privileged group -- only an explicit operator decision can.
eq([], syncGroups(['admins'], [])['groups'], 'an unmapped IdP group named admins is refused');
eq([], syncGroups(['shellers'], [])['groups'], 'an unmapped IdP group with shell access is refused');
eq(['admins'], syncGroups([], ['admins'])['groups'], 'a default group may be privileged');
eq(
    ['admins'],
    syncGroups(['idp-admins'], [], ['idp-admins' => 'admins'])['groups'],
    'an explicitly mapped group may be privileged'
);
eq([], syncGroups(['unknown-group'], [])['groups'], 'an IdP group with no counterpart grants nothing');
eq([], syncGroups([], [])['groups'], 'nothing asserted grants nothing');
falsy(syncGroups([], [])['changed'], 'and reports no change');

T::group('GroupMapper: explicit map beats the 1:1 fallback');

$res = syncGroups(['staff'], [], ['staff' => 'vpn']);
eq(['vpn'], $res['groups'], 'the mapped target is used, not the same-name group');

T::group('GroupMapper: additive by default');

// Membership the operator assigned by hand must survive a login that does not assert it.
$root = Tree::build(
    [['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1']],
    [['name' => 'staff', 'gid' => '2001', 'member' => '2100'], ['name' => 'vpn', 'gid' => '2002']]
);
$identity = new NormalizedIdentity('kc');
$identity->groups = ['vpn'];
(new GroupMapper())->sync(Tree::user($root, 'alice'), $identity, []);
eq(['2100'], Tree::members($root, 'staff'), 'a group the IdP no longer asserts is kept');
eq(['2100'], Tree::members($root, 'vpn'), 'and the asserted one is added');

T::group('GroupMapper: strict sync revokes only what it granted');

// Provenance is what separates "os-sso granted this" from "the operator did".
$root = Tree::build(
    [['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_groups' => 'vpn']],
    [
        ['name' => 'staff', 'gid' => '2001', 'member' => '2100'],
        ['name' => 'vpn', 'gid' => '2002', 'member' => '2100'],
    ]
);
$identity = new NormalizedIdentity('kc');
$identity->groups = ['staff'];
(new GroupMapper([], true))->sync(Tree::user($root, 'alice'), $identity, []);
eq([], Tree::members($root, 'vpn'), 'a previously granted group the IdP dropped is revoked');
eq(['2100'], Tree::members($root, 'staff'), 'a hand-assigned group is not revoked');
eq('staff', (string)Tree::user($root, 'alice')->sso_groups, 'provenance is rewritten to what was granted');

T::group('GroupMapper: the last member of a privileged group is kept');

// Lockout backstop: reconciliation must never empty admins.
$root = Tree::build(
    [['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_groups' => 'admins']],
    [['name' => 'admins', 'gid' => '1999', 'member' => '2100']]
);
$identity = new NormalizedIdentity('kc');
$identity->groups = [];
(new GroupMapper([], true))->sync(Tree::user($root, 'alice'), $identity, []);
eq(['2100'], Tree::members($root, 'admins'), 'the sole member of admins is kept');

// With another enabled member present, revocation is safe and happens.
$root = Tree::build(
    [
        ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_groups' => 'admins'],
        ['name' => 'bob', 'uid' => '2101', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ],
    [['name' => 'admins', 'gid' => '1999', 'member' => '2100,2101']]
);
$identity = new NormalizedIdentity('kc');
$identity->groups = [];
(new GroupMapper([], true))->sync(Tree::user($root, 'alice'), $identity, []);
eq(['2101'], Tree::members($root, 'admins'), 'with another admin present, the grant is revoked');

// A disabled second member does not count as cover.
$root = Tree::build(
    [
        ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_groups' => 'admins'],
        ['name' => 'bob', 'uid' => '2101', 'disabled' => '1'],
    ],
    [['name' => 'admins', 'gid' => '1999', 'member' => '2100,2101']]
);
$identity = new NormalizedIdentity('kc');
$identity->groups = [];
(new GroupMapper([], true))->sync(Tree::user($root, 'alice'), $identity, []);
eq(['2100', '2101'], Tree::members($root, 'admins'), 'a disabled member is not a substitute');

T::group('GroupMapper: a user with no uid is left alone');

$root = Tree::build([['name' => 'nouid', 'scrambled_password' => '1']], [['name' => 'staff', 'gid' => '2001']]);
$identity = new NormalizedIdentity('kc');
$identity->groups = ['staff'];
falsy((new GroupMapper())->sync(Tree::user($root, 'nouid'), $identity, []), 'no uid means no membership change');
eq([], Tree::members($root, 'staff'), 'and the group is untouched');

T::group('GroupMapper: granting somebody a group must not evict root');

// The failure this guards: rewriting a group's member list through array_filter() drops
// the string "0", so adding any user to admins quietly removed root from it -- and the
// firewall's own administrator lost every privilege at the next login.
$root = Tree::build([
    ['name' => 'root', 'uid' => '0', 'scope' => 'system'],
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '0'],
    ['name' => 'staff', 'gid' => '2000', 'member' => '0,2200'],
]);

/** An identity asserting these IdP groups. */
function assertedGroups(array $groups): NormalizedIdentity
{
    $identity = new NormalizedIdentity('kc');
    $identity->groups = $groups;
    return $identity;
}

// Strict sync throughout, so the grant is recorded in the provenance stamp and the
// second pass has something to reconcile.
$strict = new GroupMapper(['idp-admins' => 'admins'], true);
truthy(
    $strict->sync(Tree::user($root, 'alice'), assertedGroups(['idp-admins']), []),
    'the mapped group is granted'
);
eq(['0', '2100'], Tree::members($root, 'admins'), 'root is still a member of admins');

// And on the way out: reconcile removes the user it granted, nobody else.
$strict->sync(Tree::user($root, 'alice'), assertedGroups([]), []);
eq(['0'], Tree::members($root, 'admins'), 'reconcile removed alice and left root');
eq(['0', '2200'], Tree::members($root, 'staff'), 'a group os-sso never granted is untouched');
