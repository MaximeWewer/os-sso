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

/** The same mapper with strict account binding on (the per-provider checkbox). */
function strictMapper(): IdentityMapper
{
    return new IdentityMapper(new GroupMapper(), strictBinding: true);
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
    "already bound to another subject of provider 'kc'",
    'a different subject of the same provider cannot take over the account'
);
eq('kc|sub-alice', (string)Tree::user($root, 'alice')->sso_subject, 'the original binding is untouched');

// No subject asserted at all cannot be pinned, so it may not claim a bound account.
throws(
    fn() => mapper()->resolve(identity(['subject' => '', 'username' => 'alice']), false, []),
    'asserts none',
    'an identity with no subject cannot claim a bound account'
);

T::group('IdentityMapper: one account, several providers');

// The shape the lab exposed: one directory fronted by OIDC and by SAML, the same person,
// two subjects. Each provider vouches for its own users -- the operator registered them
// separately -- so a second provider binds alongside the first rather than being refused.
$root = Tree::build([
    ['name' => 'kctest', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-oidc'],
]);
eq(
    'kctest',
    mapper()->resolve(
        identity(['authServer' => 'kc-saml', 'subject' => 'nameid-saml', 'username' => 'kctest']),
        false,
        []
    ),
    'a second provider binds to the same account'
);
$bindings = [];
foreach (Tree::user($root, 'kctest')->sso_subject as $b) {
    $bindings[] = (string)$b;
}
eq(['kc|sub-oidc', 'kc-saml|nameid-saml'], $bindings, 'both bindings are recorded, one per provider');

// And each is then durable in its own right.
eq(
    'kctest',
    mapper()->resolve(identity(['subject' => 'sub-oidc', 'username' => 'renamed']), false, []),
    'the first provider still resolves by its own binding'
);
eq(
    'kctest',
    mapper()->resolve(
        identity(['authServer' => 'kc-saml', 'subject' => 'nameid-saml', 'username' => 'renamed']),
        false,
        []
    ),
    'and so does the second'
);
// The takeover is still closed WITHIN each provider.
throws(
    fn() => mapper()->resolve(
        identity(['authServer' => 'kc-saml', 'subject' => 'nameid-other', 'username' => 'kctest']),
        false,
        []
    ),
    "another subject of provider 'kc-saml'",
    'a second subject of the second provider is still refused'
);

T::group('IdentityMapper: strict account binding');

// Binding alongside is right for one directory behind two servers, and wrong for two
// unrelated directories -- nothing in the configuration tells them apart, so the operator
// does, per provider. On, a provider may only join an account nobody else has claimed.
$root = Tree::build([
    ['name' => 'kctest', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-oidc'],
]);
throws(
    fn() => strictMapper()->resolve(
        identity(['authServer' => 'guest-idp', 'subject' => 'sub-mallory', 'username' => 'kctest']),
        false,
        []
    ),
    "claimed by provider 'kc'",
    'a second provider cannot join an account another one holds'
);
$bindings = [];
foreach (Tree::user($root, 'kctest')->sso_subject as $b) {
    $bindings[] = (string)$b;
}
eq(['kc|sub-oidc'], $bindings, 'and nothing was stamped on the way to the refusal');

// The hole this closes: an account a directory pre-provisioned over SCIM and nobody has
// logged into carries a scim_ref and no sso_subject at all, so reading <sso_subject>
// alone reported it as claimed by nobody and any provider could take it by username.
$root = Tree::build([
    ['name' => 'bob', 'uid' => '2101', 'scrambled_password' => '1', 'sso_owned' => '1', 'scim_ref' => 'kc|ext-bob'],
]);
throws(
    fn() => strictMapper()->resolve(
        identity(['authServer' => 'guest-idp', 'subject' => 'sub-bob', 'username' => 'bob']),
        false,
        []
    ),
    "claimed by provider 'kc'",
    'a SCIM-provisioned account is claimed even before its first login'
);

// ... and the provider that owns it still gets in.
eq(
    'bob',
    strictMapper()->resolve(identity(['subject' => 'sub-bob', 'username' => 'bob']), false, []),
    'the claiming provider binds to its own SCIM-provisioned account'
);

// An unclaimed account is free to take: strict binding narrows who may JOIN an account,
// not who may have one.
$root = Tree::build([['name' => 'carol', 'uid' => '2102', 'scrambled_password' => '1']]);
eq(
    'carol',
    strictMapper()->resolve(identity(['subject' => 'sub-carol', 'username' => 'carol']), false, []),
    'an account nobody has claimed still binds'
);

// The durable stamp is not weakened by it either -- strict binding only gates weak matches.
$root = Tree::build([
    ['name' => 'renamed.dave', 'uid' => '2103', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-dave'],
]);
eq(
    'renamed.dave',
    strictMapper()->resolve(identity(['subject' => 'sub-dave', 'username' => 'dave.new']), false, []),
    'a match on the subject stamp is unaffected'
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

// Same escalation without the group: OPNsense also grants privileges on the account
// itself, and an administrator configured that way is just as often the one wearing the
// "prevent local database logins" checkbox.
$root = Tree::build([
    ['name' => 'directadmin', 'uid' => '2103', 'password' => '*', 'scrambled_password' => '1',
     'priv' => ['page-all']],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 's', 'username' => 'directadmin']), false, []),
    'refusing to bind to privileged local account',
    'an account carrying page-all of its own is refused'
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
    "already bound to another subject of provider 'kc'",
    'a verified email cannot cross subjects of one provider'
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

T::group('IdentityMapper: undoing a deprovisioning');

// The account os-sso disabled on an earlier refused login. Getting here at all means the
// provider's required-groups gate has just passed, so the revocation is over -- and
// without this the login that proves it is the one refused by the flag it set.
$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_owned' => '1',
     'sso_subject' => 'kc|sub-alice', 'disabled' => '1', 'sso_deprovisioned' => '1'],
]);
eq(
    'alice',
    mapper()->resolve(identity(['subject' => 'sub-alice', 'username' => 'alice']), false, []),
    'an account os-sso deprovisioned is re-enabled and logs in'
);
eq('0', (string)Tree::user($root, 'alice')->disabled, 'the disabled flag is cleared');
eq('', (string)Tree::user($root, 'alice')->sso_deprovisioned, 'and so is the stamp');

// The operator's own lever is NOT ours to undo: no stamp, no revival.
$root = Tree::build([
    ['name' => 'bob', 'uid' => '2101', 'scrambled_password' => '1', 'sso_owned' => '1',
     'sso_subject' => 'kc|sub-bob', 'disabled' => '1'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 'sub-bob', 'username' => 'bob']), false, []),
    'disabled or expired',
    'an account the operator disabled stays disabled'
);
eq('1', (string)Tree::user($root, 'bob')->disabled, 'and its flag is untouched');

// A stamp left on an ENABLED account is dropped rather than trusted: somebody re-enabled
// the account by hand, so a later disable of theirs must not read as one of ours.
$root = Tree::build([
    ['name' => 'carol', 'uid' => '2102', 'scrambled_password' => '1', 'sso_owned' => '1',
     'sso_subject' => 'kc|sub-carol', 'sso_deprovisioned' => '1'],
]);
eq(
    'carol',
    mapper()->resolve(identity(['subject' => 'sub-carol', 'username' => 'carol']), false, []),
    'an enabled account with a stale stamp logs in'
);
eq('', (string)Tree::user($root, 'carol')->sso_deprovisioned, 'and the stale stamp is dropped');

// <expires> is a date the operator set, not a refusal os-sso issued -- reviving the
// disabled flag must not smuggle an expired account back in.
$root = Tree::build([
    ['name' => 'dave', 'uid' => '2103', 'scrambled_password' => '1', 'sso_owned' => '1',
     'sso_subject' => 'kc|sub-dave', 'disabled' => '1', 'sso_deprovisioned' => '1',
     'expires' => '01/01/2020'],
]);
throws(
    fn() => mapper()->resolve(identity(['subject' => 'sub-dave', 'username' => 'dave']), false, []),
    'disabled or expired',
    'an expired account is still refused after the revival'
);

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

T::group('IdentityMapper: the account follows the directory');

// Written once at creation and never again meant a display name or an address that
// changed at the IdP stayed wrong on the firewall for the life of the account.
$root = Tree::build([
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1', 'sso_subject' => 'kc|sub-alice',
     'descr' => 'Alice Old', 'email' => 'old@example.com'],
]);
mapper()->resolve(identity([
    'subject' => 'sub-alice',
    'username' => 'alice',
    'displayName' => 'Alice New',
    'email' => 'new@example.com',
    'emailVerified' => true,
]), false, []);
eq('Alice New', (string)Tree::user($root, 'alice')->descr, 'the display name is refreshed on login');
eq('new@example.com', (string)Tree::user($root, 'alice')->email, 'so is a verified address');

// An unverified address is not allowed to find an account, and is not allowed to
// overwrite one either.
mapper()->resolve(identity([
    'subject' => 'sub-alice',
    'username' => 'alice',
    'email' => 'unverified@example.com',
]), false, []);
eq('new@example.com', (string)Tree::user($root, 'alice')->email, 'an unverified address does not overwrite it');

// An identity that asserts nothing leaves what is there alone.
mapper()->resolve(identity(['subject' => 'sub-alice', 'username' => 'alice']), false, []);
eq('Alice New', (string)Tree::user($root, 'alice')->descr, 'an assertion with no name changes nothing');

// A pre-existing local account os-sso merely bound to is not ours to rewrite.
$root = Tree::build([
    ['name' => 'theirs', 'uid' => '2101', 'password' => '*', 'descr' => 'Hand written'],
]);
mapper()->resolve(identity([
    'subject' => 'sub-t', 'username' => 'theirs', 'displayName' => 'From the IdP',
]), false, []);
eq('From the IdP', (string)Tree::user($root, 'theirs')->descr, 'an account we just claimed is ours from then on');
