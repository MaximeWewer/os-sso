<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The binding policy: which local account an asserted identity is allowed to become.
 * This is where a mistake is an account takeover rather than a bug, and it is the part
 * an end-to-end suite never reaches -- e2e drives the happy path, and every case below
 * is a refusal.
 */

use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Test\Tree;

if (!stateDirUsable()) {
    T::group('IdentityMapper');
    T::skip('the whole group', 'needs a writable /var/db/os-sso for the config lock');
    return;
}

/** An identity as a protocol would hand it over. */
function identity(array $fields): NormalizedIdentity
{
    $id = new NormalizedIdentity((string)($fields['authServer'] ?? 'kc'));
    foreach (['subject', 'username', 'email', 'displayName'] as $key) {
        $id->{$key} = (string)($fields[$key] ?? '');
    }
    $id->emailVerified = (bool)($fields['emailVerified'] ?? false);
    $id->groups = (array)($fields['groups'] ?? []);
    return $id;
}

function mapper(array $map = [], bool $reconcile = false): IdentityMapper
{
    return new IdentityMapper(new GroupMapper($map, $reconcile));
}

T::group('IdentityMapper: the durable stamp wins');

$root = Tree::build([
    ['name' => 'renamed.alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-alice'],
]);
eq(
    'renamed.alice',
    mapper()->resolve(identity(['subject' => 'sub-alice', 'username' => 'alice.new']), false, []),
    'an account is found by its subject stamp even after the username changed at the IdP'
);

T::group('IdentityMapper: first-time linking by username');

$root = Tree::build([['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1']]);
eq(
    'alice',
    mapper()->resolve(identity(['subject' => 'sub-alice', 'username' => 'alice']), false, []),
    'a passwordless account is bound by username'
);
eq('kc|sub-alice', (string)Tree::user($root, 'alice')->sso_subject, 'and gets stamped for next time');

T::group('IdentityMapper: an account bound to another subject is refused');

// The takeover the audit found: subject B presents the username of the account already
// stamped for subject A -- an IdP rename, an account deleted and recreated there with a
// fresh sub, or simply a mutable claim such as email.
$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-alice'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 'sub-mallory', 'username' => 'alice']), false, []),
    'already bound to another IdP subject',
    'a different subject cannot take over the account by username'
);
eq('kc|sub-alice', (string)Tree::user($root, 'alice')->sso_subject, 'the original binding is untouched');

// No subject asserted at all is the same problem: nothing proves it is the same person.
throws(
    fn() => mapper()->resolve(identity(['subject' => '', 'username' => 'alice']), false, []),
    'already bound to another IdP subject',
    'an identity with no subject cannot claim a stamped account'
);

// A second provider is not a loophole either.
throws(
    fn() => mapper()->resolve(
        identity(['authServer' => 'other', 'subject' => 'sub-alice', 'username' => 'alice']),
        false,
        []
    ),
    'already bound to another IdP subject',
    'the same subject id from a different provider is refused'
);

T::group('IdentityMapper: human-owned and privileged accounts');

$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => 'alice']), false, []),
    'collides with an existing local account that has its own password',
    'an account with a real password is never taken over'
);

// The escalation the ownership fix closed: an admins member with a scrambled password --
// the standard LDAP-backed administrator -- used to read as os-sso-managed.
$root = Tree::build([
    ['name' => 'ldapadmin', 'uid' => '2101', 'password' => '*', 'scrambled_password' => '1'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2101'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => 'ldapadmin']), false, []),
    'refusing to bind to privileged local account',
    'a privileged passwordless account is refused'
);

// An account os-sso itself created may be privileged and still bind: the operator put it
// in admins on purpose, and the stamp proves whose it is.
$root = Tree::build([
    ['name' => 'ssoadmin', 'uid' => '2102', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-adm'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2102'],
]);
eq(
    'ssoadmin',
    mapper()->resolve(identity(['subject' => 'sub-adm', 'username' => 'ssoadmin']), false, []),
    'an os-sso-owned privileged account still binds to its own subject'
);

T::group('IdentityMapper: email matching');

$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'email' => 'a@example.com',
     'scrambled_password' => '1', 'sso_subject' => 'kc|sub-alice'],
]);
// The email path only relocates an account we own, and only for its own subject.
eq(
    'alice',
    mapper()->resolve(
        identity(['subject' => 'sub-alice', 'username' => '', 'email' => 'a@example.com', 'emailVerified' => true]),
        false,
        []
    ),
    'a verified email relocates our own account'
);
throws(
    fn() => mapper()->resolve(
        identity(['subject' => 'other', 'username' => '', 'email' => 'a@example.com', 'emailVerified' => true]),
        false,
        []
    ),
    'already bound to another IdP subject',
    'a verified email cannot cross subjects'
);
// Isolate the email path: a subject the stamp does not answer to, so the durable match
// above cannot resolve it first.
throws(
    fn() => mapper()->resolve(
        identity(['subject' => 'sub-bob', 'username' => '', 'email' => 'a@example.com', 'emailVerified' => false]),
        false,
        []
    ),
    'no local account matches',
    'an unverified email matches nothing'
);

// An unowned account is invisible to the email path whatever it says.
$root = Tree::build([['name' => 'human', 'uid' => '2100', 'email' => 'h@example.com',
                      'password' => '$2y$10$abcdefghijklmnopqrstuv']]);
throws(
    fn() => mapper()->resolve(
        identity(['subject' => 's', 'username' => '', 'email' => 'h@example.com', 'emailVerified' => true]),
        false,
        []
    ),
    'no local account matches',
    'a password account is not reachable by email'
);

T::group('IdentityMapper: disabled and expired accounts');

$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1',
     'sso_subject' => 'kc|sub-alice', 'disabled' => '1'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 'sub-alice', 'username' => 'alice']), false, []),
    'disabled or expired',
    'a disabled account is refused before anything is written'
);
eq(0, \OPNsense\Core\Config::$saves, 'and config.xml was never saved');

T::group('IdentityMapper: provisioning');

$root = Tree::build();
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => 'newbie']), false, []),
    'auto-creation is disabled',
    'no match and no auto-creation is a refusal'
);

$root = Tree::build([], [['name' => 'staff', 'gid' => '2000']]);
eq(
    'newbie',
    mapper()->resolve(
        identity(['subject' => 'sub-new', 'username' => 'newbie', 'displayName' => 'New Bie',
                  'email' => 'n@example.com', 'groups' => ['staff']]),
        true,
        []
    ),
    'auto-creation provisions the account'
);
$new = Tree::user($root, 'newbie');
truthy($new !== null, 'the account exists in config.xml');
eq('kc|sub-new', (string)$new->sso_subject, 'it carries the subject stamp');
eq('1', (string)$new->sso_owned, 'and the ownership marker');
eq(['2000'], Tree::members($root, 'staff'), 'the asserted group was granted');

// A username the local account rules reject must never be provisioned.
$root = Tree::build();
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => 'bad/name']), true, []),
    'not a valid local',
    'an invalid username is refused rather than created'
);
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => '']), true, []),
    'without a username claim',
    'an identity with no username cannot be provisioned'
);
