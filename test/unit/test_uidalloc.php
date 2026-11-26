<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * GHSA-wvvw-f723-h7ph: a new SSO account was given the uid of an existing local one,
 * and so its groups -- admins included -- and os-sso's own records about it.
 */

use OPNsense\SSO\AccountStamps;
use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Scim\ScimUsers;
use OPNsense\SSO\Test\Tree;

if (!stateDirUsable()) {
    T::group('uid allocation');
    T::skip('the whole group', 'needs a writable /var/db/os-sso for the config lock');
    return;
}

function uidIdentity(string $subject, string $username): NormalizedIdentity
{
    $id = new NormalizedIdentity('kc');
    $id->subject = $subject;
    $id->username = $username;
    return $id;
}

T::group('uid allocation: never a uid in use');

// What OPNsense 26.x leaves: users from core's UidField (lowest free from 2000) and no
// system/nextuid at all.
$root = Tree::build([
    ['name' => 'api1', 'uid' => '2000', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'api2', 'uid' => '2001', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'api3', 'uid' => '2002', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '0,2000'],
    // A member left behind by an account deleted since: its uid is not free either.
    ['name' => 'staff', 'gid' => '2000', 'member' => '2010'],
]);
unset($root->system->nextuid);
$writer = new LocalAccountWriter();
$node = $writer->create(['name' => 'sso.alice']);
eq('2011', (string)$node->uid, 'above every account and every group member, not 2000');
eq([], array_values(array_filter(
    iterator_to_array((function () use ($root) {
        foreach ($root->system->group as $g) {
            if (in_array('2011', OPNsense\SSO\GroupMembers::uids($g), true)) {
                yield (string)$g->name;
            }
        }
    })(), false)
)), 'and so in no group it was not given');
eq('2012', (string)$root->system->nextuid, 'system/nextuid moves past it, for a core that reads it');
eq('2012', (string)$writer->create(['name' => 'sso.bob'])->uid, 'the next account takes the next one');

// Records of a deleted account are keyed by its uid too.
$root = Tree::build([['name' => 'api1', 'uid' => '2000', 'password' => '$2y$10$abcdefghijklmnopqrstuv']]);
$ghost = $root->system->addChild('user');
$ghost->addChild('name', 'gone');
$ghost->addChild('uid', '2050');
AccountStamps::set($ghost, 'sso_subject', 'kc|someone');
unset($root->system->user[1]);
eq('2051', (string)(new LocalAccountWriter())->create(['name' => 'sso.carol'])->uid,
    'nor the uid of an os-sso record whose account is gone');

$root = Tree::build([['name' => 'api1', 'uid' => '2000']]);
$root->system->nextuid = '3000';
eq('3000', (string)(new LocalAccountWriter())->create(['name' => 'sso.dave'])->uid,
    'a higher system/nextuid is still honoured');

$root = Tree::build([['name' => 'top', 'uid' => '65533']]);
throws(fn() => (new LocalAccountWriter())->create(['name' => 'x']), 'no unused uid', 'and none past 65533');

T::group('uid allocation: an account sharing a uid is refused everywhere');

// The state an earlier version left behind: the SSO account on api2's uid, which
// therefore also reads as owned by os-sso and bound to the IdP subject.
$root = Tree::build([
    ['name' => 'api2', 'uid' => '2001', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'sso.erin', 'uid' => '2001', 'scrambled_password' => '1',
     'sso_owned' => '1', 'sso_subject' => 'kc|sub-erin', 'scim_ref' => 'kc|ext-erin', 'scim_provider' => 'kc'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2001'],
]);
$writer = new LocalAccountWriter();
truthy($writer->sharesUid(Tree::user($root, 'api2')), 'the pair is detected');
eq(['2001' => ['api2', 'sso.erin']], $writer->sharedUids(), 'and listed for the diagnostics page');
falsy($writer->isSsoManaged(Tree::user($root, 'api2')), 'the local account no longer reads as os-sso\'s');
eq(null, $writer->findBySubject('kc|sub-erin'), 'the IdP binding finds neither account');
eq(null, $writer->findByUid('2001'), 'nor does the uid');
throws(
    fn() => (new IdentityMapper(new GroupMapper()))->resolve(uidIdentity('sub-erin', 'sso.erin'), true, []),
    'shares uid 2001',
    'the SSO login is refused instead of landing on api2'
);
$base = 'https://fw.example/api/sso/scim';
eq(0, (new ScimUsers('kc', $base))->search('', 1, 100)['totalResults'], 'SCIM lists neither account');
throws(fn() => (new ScimUsers('kc', $base))->get('2001'), 'not found', 'nor reads one');
throws(fn() => (new ScimUsers('kc', $base))->create(['userName' => 'sso.erin']), 'shares uid',
    'nor adopts one by its userName');
