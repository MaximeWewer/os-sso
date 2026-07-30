<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SCIM is an unauthenticated-by-the-WebGUI, write-capable API into the firewall's
 * account database. What it refuses matters more than what it does.
 */

use OPNsense\Core\Backend;
use OPNsense\SSO\Scim\ScimGroups;
use OPNsense\SSO\Scim\ScimUsers;
use OPNsense\SSO\Test\Tree;

if (!stateDirUsable()) {
    T::group('SCIM');
    T::skip('the whole group', 'needs a writable /var/db/os-sso for the config lock');
    return;
}

$base = 'https://fw.example/api/sso/scim';
$users = fn(string $provider = 'kc') => new ScimUsers($provider, $base);
$groups = fn() => new ScimGroups($base);

T::group('ScimUsers: only accounts os-sso owns are visible');

// uids run sequentially from nextuid, so an unfiltered lookup by id is an enumeration of
// every local account on the box -- root included.
$root = Tree::build([
    ['name' => 'root', 'uid' => '0', 'scope' => 'system'],
    ['name' => 'human', 'uid' => '2100', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'ldapish', 'uid' => '2101', 'scrambled_password' => '1'],
    ['name' => 'ours', 'uid' => '2102', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-1'],
]);

throws(fn() => $users()->get('0'), 'not found', 'root is not readable');
throws(fn() => $users()->get('2100'), 'not found', 'a password account is not readable');
throws(fn() => $users()->get('2101'), 'not found', 'a merely passwordless account is not readable');
throws(fn() => $users()->get('9999'), 'not found', 'an unknown id is not found');
$res = nothrow(fn() => $users()->get('2102'), 'our own account is readable');
eq('ours', $res['userName'] ?? null, 'and carries the userName');
eq('ext-1', $res['externalId'] ?? null, 'and the externalId, stripped of the provider prefix');
eq($base . '/Users/2102', $res['meta']['location'] ?? null, 'and a usable location');
eq(true, $res['active'] ?? null, 'and its active state');

$list = $users()->search('', 1, 100);
eq(1, $list['totalResults'], 'search only lists accounts we own');

T::group('ScimUsers: filters');

eq(1, $users()->search('userName eq "ours"', 1, 100)['totalResults'], 'filter on userName');
eq(0, $users()->search('userName eq "human"', 1, 100)['totalResults'], 'a filter cannot reach an unowned account');
eq(1, $users()->search('externalId eq "ext-1"', 1, 100)['totalResults'], 'filter on externalId');
eq(1, $users()->search('id eq "2102"', 1, 100)['totalResults'], 'filter on id');
eq(1, $users()->search('userName eq "ours" and active eq "true"', 1, 100)['totalResults'],
    'two terms joined by and');
eq(1, $users()->search('userName eq "nobody" or externalId eq "ext-1"', 1, 100)['totalResults'],
    'two terms joined by or');
throws(fn() => $users()->search('userName co "ou"', 1, 100), 'only the "eq" operator', 'a co filter is refused');
throws(fn() => $users()->search('userType eq "x"', 1, 100), 'not supported', 'an unindexed attribute is refused');

// count=0 is how a client sizes a sync before walking it.
$probe = $users()->search('', 1, 0);
eq(0, $probe['itemsPerPage'], 'count=0 returns no resources');
eq(1, $probe['totalResults'], 'count=0 still reports the total');

T::group('ScimUsers: what a directory may not write');

$root = Tree::build([
    ['name' => 'boss', 'uid' => '2100', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-boss'],
    ['name' => 'human', 'uid' => '2101', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'theirs', 'uid' => '2102', 'scrambled_password' => '1', 'scim_ref' => 'other|ext-x'],
    ['name' => 'loggedin', 'uid' => '2103', 'scrambled_password' => '1', 'sso_subject' => 'other|sub-y'],
    // Privileges granted on the account rather than through admins: deactivating this
    // one over SCIM would lock the firewall's administrator out.
    ['name' => 'directadmin', 'uid' => '2104', 'scrambled_password' => '1',
     'scim_ref' => 'kc|ext-direct', 'priv' => ['page-all']],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2100'],
]);

throws(fn() => $users()->deactivate('2100'), 'privileged', 'a privileged account is never deactivated');
throws(fn() => $users()->replace('2100', ['userName' => 'boss']), 'privileged', 'nor replaced');
throws(fn() => $users()->deactivate('2104'), 'privileged', 'an account carrying page-all of its own either');
throws(fn() => $users()->get('2101'), 'not found', 'a password account is not even addressable');

// Cross-provider: enabling SCIM on one authentication server must not hand it another's
// accounts. Both bindings answer the question, scim_ref and sso_subject alike.
throws(fn() => $users()->deactivate('2102'), 'belongs to another provider', 'another SCIM provider\'s account');
throws(fn() => $users()->deactivate('2103'), 'belongs to another provider', 'another provider\'s login account');
nothrow(fn() => $users('other')->deactivate('2102'), 'its own provider may deactivate it');
eq('1', (string)Tree::user($root, 'theirs')->disabled, 'and it is disabled, not removed');

T::group('ScimUsers: create adopts or creates');

$root = Tree::build([
    ['name' => 'preexisting', 'uid' => '2100', 'scrambled_password' => '1'],
    ['name' => 'human', 'uid' => '2101', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
]);

// createdNew() reports on the last create() of THIS instance, which is how the
// controller uses it -- so hold one, the way it does.
$writer = $users();
$made = $writer->create(['userName' => 'fresh', 'externalId' => 'ext-fresh', 'active' => true]);
truthy($writer->createdNew(), 'a genuinely new account reports created');
eq('fresh', $made['userName'], 'the resource comes back');
truthy(Tree::user($root, 'fresh') !== null, 'and the account is in config.xml');

$writer->create(['userName' => 'preexisting', 'externalId' => 'ext-pre']);
falsy($writer->createdNew(), 'adopting an existing account does not report created');
eq('kc|ext-pre', (string)Tree::user($root, 'preexisting')->scim_ref, 'the adopted account is stamped');

throws(
    fn() => $users()->create(['userName' => 'another', 'externalId' => 'ext-fresh']),
    'already exists',
    'a repeated externalId is a conflict'
);
throws(fn() => $users()->create(['userName' => 'human']), 'own password', 'a password account is not adopted');
throws(fn() => $users()->create(['userName' => '']), 'userName is required', 'userName is required');
throws(fn() => $users()->create(['userName' => 'bad/name']), 'not a valid local', 'the username is validated');

// Re-creating a user is how several directories reactivate one they deactivated, so a
// POST that adopts an account has to apply "active" like any other statement of the
// resource -- otherwise the client gets a 200 for an account that stays disabled.
$root = Tree::build([
    ['name' => 'back', 'uid' => '2100', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-back', 'disabled' => '1'],
    ['name' => 'gone', 'uid' => '2101', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-gone'],
]);
$resource = $users()->create(['userName' => 'back', 'active' => true]);
eq('0', (string)Tree::user($root, 'back')->disabled, 'adopting with active=true re-enables the account');
truthy($resource['active'], 'and the resource says so');
$users()->create(['userName' => 'gone', 'active' => false]);
eq('1', (string)Tree::user($root, 'gone')->disabled, 'adopting with active=false disables it');

T::group('ScimUsers: patch');

$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-a'],
    ['name' => 'taken', 'uid' => '2101', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-t'],
]);

$users()->patch('2100', [['op' => 'replace', 'path' => 'active', 'value' => false]]);
eq('1', (string)Tree::user($root, 'alice')->disabled, 'active=false disables the account');
$users()->patch('2100', [['op' => 'replace', 'path' => 'active', 'value' => true]]);
eq('0', (string)Tree::user($root, 'alice')->disabled, 'active=true enables it again');
$users()->patch('2100', [['op' => 'remove', 'path' => 'active']]);
eq('1', (string)Tree::user($root, 'alice')->disabled, 'removing active disables it');

$users()->patch('2100', [['op' => 'replace', 'path' => 'displayName', 'value' => 'Alice A']]);
eq('Alice A', (string)Tree::user($root, 'alice')->descr, 'displayName lands on descr');
$users()->patch('2100', [['op' => 'replace', 'path' => 'emails', 'value' => 'a@example.com']]);
eq('a@example.com', (string)Tree::user($root, 'alice')->email, 'emails lands on email');
$users()->patch('2100', [['op' => 'replace', 'path' => 'userName', 'value' => 'alice.renamed']]);
eq('alice.renamed', (string)Tree::user($root, 'alice.renamed')->name, 'userName renames the account');
// A rename has to be reconciled, not just announced: core's sync is what drops the local
// entry the old name left behind. An ordinary edit stays on the cheaper notification.
eq(
    ['auth sync user', ['alice.renamed']],
    Backend::$calls[count(Backend::$calls) - 1],
    'and the rename is synced rather than merely announced'
);
$users()->patch('2100', [['op' => 'replace', 'path' => 'displayName', 'value' => 'Alice B']]);
eq(
    ['auth user changed', ['alice.renamed']],
    Backend::$calls[count(Backend::$calls) - 1],
    'while an ordinary edit only announces the change'
);
throws(
    fn() => $users()->patch('2101', [['op' => 'replace', 'path' => 'userName', 'value' => 'alice.renamed']]),
    'already exists',
    'a rename onto an existing name is a conflict'
);
// A no-op patch must not churn config.xml.
$before = \OPNsense\Core\Config::$saves;
$users()->patch('2100', [['op' => 'replace', 'path' => 'displayName', 'value' => 'Alice B']]);
eq($before, \OPNsense\Core\Config::$saves, 'an unchanged patch does not save config.xml');

T::group('ScimUsers: replace');

$root = Tree::build([
    ['name' => 'bob', 'uid' => '2100', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-b'],
    ['name' => 'occupied', 'uid' => '2101', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext-o'],
]);

// PUT states the whole resource. A userName it no longer agrees with is a rename, not a
// field to drop on the floor -- the login path falls back to the username when the
// subject does not match, so the two sides disagreeing about it is not cosmetic.
$put = $users()->replace('2100', ['userName' => 'bob.renamed', 'displayName' => 'Bob B', 'active' => true]);
eq('bob.renamed', $put['userName'], 'a PUT with a new userName renames the account');
eq('bob.renamed', (string)Tree::user($root, 'bob.renamed')->name, 'and config.xml follows');
eq('Bob B', (string)Tree::user($root, 'bob.renamed')->descr, 'the other attributes land too');
eq(
    ['auth sync user', ['bob.renamed']],
    Backend::$calls[count(Backend::$calls) - 1],
    'and it is synced like any rename'
);
throws(
    fn() => $users()->replace('2100', ['userName' => 'occupied']),
    'already exists',
    'a PUT cannot rename onto an existing account either'
);

T::group('ScimGroups: membership only, and only ours');

$root = Tree::build([
    ['name' => 'ours', 'uid' => '2100', 'scrambled_password' => '1', 'scim_ref' => 'kc|e1'],
    ['name' => 'alsoours', 'uid' => '2101', 'scrambled_password' => '1', 'scim_ref' => 'kc|e2'],
    ['name' => 'handmade', 'uid' => '2102', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2102'],
    ['name' => 'shellers', 'gid' => '2001', 'priv' => ['user-shell-access']],
    ['name' => 'staff', 'gid' => '2002', 'member' => '2102'],
]);

throws(fn() => $groups()->patch('1999', []), 'administrative privileges', 'admins takes no membership');
throws(fn() => $groups()->patch('2001', []), 'administrative privileges', 'nor does a shell-access group');
throws(fn() => $groups()->get('9999'), 'not found', 'an unknown group is not found');

// A directory may only move the accounts it provisioned. Adding an arbitrary local
// account would hand it whatever the group grants; removing one would strip the
// operator's own hand-assigned member.
$groups()->patch('2002', [['op' => 'add', 'path' => 'members', 'value' => [['value' => '2100']]]]);
eq(['2102', '2100'], Tree::members($root, 'staff'), 'our account is added, the hand-assigned one kept');
$groups()->patch('2002', [['op' => 'add', 'path' => 'members', 'value' => [['value' => '9999']]]]);
eq(['2102', '2100'], Tree::members($root, 'staff'), 'an unknown uid is not added');
$groups()->patch('2002', [['op' => 'remove', 'path' => 'members[value eq "2102"]']]);
eq(['2102', '2100'], Tree::members($root, 'staff'), 'a hand-assigned member cannot be removed');
$groups()->patch('2002', [['op' => 'remove', 'path' => 'members[value eq "2100"]']]);
eq(['2102'], Tree::members($root, 'staff'), 'our own member can be removed');

// replace means "replace my members", not "replace the members".
$groups()->patch('2002', [['op' => 'replace', 'path' => 'members',
                           'value' => [['value' => '2101'], ['value' => '2102']]]]);
eq(['2102', '2101'], Tree::members($root, 'staff'), 'replace keeps unowned members and sets ours');

$resource = $groups()->get('2002');
eq('staff', $resource['displayName'], 'the group resource names the group');
eq(['2101'], array_column($resource['members'], 'value'), 'and lists only the members we own');

T::group('ScimFilter: what a directory may ask for');

use OPNsense\SSO\Scim\ScimFilter;

/** Compile against a fixed resource. */
function filterOn(array $resource, string $filter): bool
{
    $predicate = ScimFilter::compile($filter, fn(string $attr) => $resource[$attr] ?? null);
    return $predicate();
}

$row = ['username' => 'alice', 'externalid' => 'ext-1', 'active' => 'true', 'displayname' => 'Alice A'];

truthy(filterOn($row, 'userName eq "alice"'), 'a single eq still works');
falsy(filterOn($row, 'userName eq "bob"'), 'and still says no when it should');
truthy(filterOn($row, 'userName eq "ALICE"'), 'string comparison is case-insensitive per the spec');
// The reconciliation shapes that used to be refused outright, sending the client back to
// walking every page.
truthy(filterOn($row, 'userName eq "alice" and active eq "true"'), 'two terms joined by and');
falsy(filterOn($row, 'userName eq "alice" and active eq "false"'), 'and is not or');
truthy(filterOn($row, 'userName eq "bob" or externalId eq "ext-1"'), 'two terms joined by or');
truthy(filterOn($row, '(userName eq "bob" or externalId eq "ext-1") and active eq "true"'), 'parentheses group');
falsy(filterOn($row, 'userName eq "bob" or externalId eq "ext-2"'), 'or with neither side true');

// Everything else is refused rather than approximated: a client that believes it
// filtered, and did not, acts on every row that came back.
throws(fn() => filterOn($row, 'userName co "ali"'), 'only the "eq" operator', 'co is refused');
throws(fn() => filterOn($row, 'userType eq "x"'), 'not supported', 'an attribute we cannot index is refused');
throws(fn() => filterOn($row, 'userName eq'), 'incomplete filter', 'a truncated expression is refused');
throws(fn() => filterOn($row, '(userName eq "alice"'), 'unbalanced parentheses', 'an unclosed group is refused');
throws(fn() => filterOn($row, 'userName eq "alice" bogus'), 'unsupported filter', 'trailing junk is refused');
