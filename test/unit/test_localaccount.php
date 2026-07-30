<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\LocalAccount;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\Test\Tree;

$writer = new LocalAccountWriter();

T::group('LocalAccountWriter: username validation');

foreach (['alice', 'a.b_c-d', 'A1', 'first last', str_repeat('x', 64)] as $ok) {
    nothrow(fn() => $writer->assertValidUsername($ok), 'accepts ' . json_encode($ok));
}
foreach ([
    '' => 'empty',
    ' alice' => 'leading space',
    'alice ' => 'trailing space',
    'a  b' => 'double interior space',
    'al/ice' => 'slash',
    'al:ice' => 'colon',
    'al<ice' => 'angle bracket',
    "al\nice" => 'newline',
    "al\0ice" => 'NUL',
    'root@example' => 'at sign',
    'utilisateur' . chr(233) => 'non-ASCII byte',
    str_repeat('x', 65) => 'too long',
] as $bad => $why) {
    throws(fn() => $writer->assertValidUsername($bad), 'not a valid local', "refuses {$why}");
}

T::group('LocalAccountWriter: who owns an account');

// The distinction the audit turned on: "no local password" is NOT "os-sso owns this".
// A scrambled password is the WebGUI's own checkbox, used for LDAP-backed accounts --
// administrators included -- and reading it as ownership let those be bound to.
$root = Tree::build([
    ['name' => 'ldapadmin', 'uid' => '2100', 'password' => '*', 'scrambled_password' => '1'],
    ['name' => 'ssologin', 'uid' => '2101', 'scrambled_password' => '1', 'sso_subject' => 'kc|abc'],
    ['name' => 'scimmade', 'uid' => '2102', 'scrambled_password' => '1', 'scim_ref' => 'kc|ext1'],
    ['name' => 'ssomade', 'uid' => '2103', 'scrambled_password' => '1', 'sso_owned' => '1'],
    ['name' => 'human', 'uid' => '2104', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'locked', 'uid' => '2105', 'password' => '*'],
    ['name' => 'banged', 'uid' => '2106', 'password' => '!locked'],
    ['name' => 'nopass', 'uid' => '2107'],
]);

falsy($writer->isSsoManaged(Tree::user($root, 'ldapadmin')), 'a scrambled password alone is not ownership');
truthy($writer->isSsoManaged(Tree::user($root, 'ssologin')), 'an sso_subject stamp is ownership');
truthy($writer->isSsoManaged(Tree::user($root, 'scimmade')), 'a scim_ref stamp is ownership');
truthy($writer->isSsoManaged(Tree::user($root, 'ssomade')), 'the sso_owned marker is ownership');
falsy($writer->isSsoManaged(Tree::user($root, 'human')), 'a password account is not ours');

T::group('LocalAccountWriter: which accounts can be bound at all');

falsy($writer->hasUsableLocalPassword(Tree::user($root, 'ldapadmin')), 'scrambled means no usable password');
truthy($writer->hasUsableLocalPassword(Tree::user($root, 'human')), 'a hash means a usable password');
falsy($writer->hasUsableLocalPassword(Tree::user($root, 'locked')), '"*" is not a usable password');
falsy($writer->hasUsableLocalPassword(Tree::user($root, 'banged')), 'a "!" prefix is not usable');
falsy($writer->hasUsableLocalPassword(Tree::user($root, 'nopass')), 'no password element is not usable');

T::group('LocalAccountWriter: create() shapes an IdP-only account');

$root = Tree::build();
$node = $writer->create([
    'name' => 'newbie',
    'descr' => 'New Bie',
    'email' => 'n@example.com',
    'comment' => 'made by a test',
    'sso_subject' => 'kc|sub-1',
]);
eq('newbie', (string)$node->name, 'the name is set');
eq('New Bie', (string)$node->descr, 'the description is set');
eq('*', (string)$node->password, 'the password is locked out');
eq('1', (string)$node->scrambled_password, 'local database login is prevented');
eq('1', (string)$node->sso_owned, 'the ownership marker is written');
eq('0', (string)$node->disabled, 'the account is enabled');
eq('user', (string)$node->scope, 'the scope is user, never system');
eq('2000', (string)$node->uid, 'the uid comes from nextuid');
eq('2001', (string)$root->system->nextuid, 'nextuid is advanced');
truthy($writer->isSsoManaged($node), 'a freshly created account is ours');

// Even with no stamp to record -- an identity carrying no subject, or SCIM with no
// externalId -- the account must still come out owned, or it drops off /Users entirely.
$bare = $writer->create(['name' => 'stampless']);
eq('1', (string)$bare->sso_owned, 'an account with no stamp is still marked owned');
truthy($writer->isSsoManaged($bare), 'and still reads as ours');
eq('stampless', (string)$bare->descr, 'the description falls back to the username');

$disabled = $writer->create(['name' => 'inactive', 'disabled' => true]);
eq('1', (string)$disabled->disabled, 'create() can make a disabled account');

throws(fn() => $writer->create(['name' => 'bad name!']), 'not a valid local', 'create() validates the name');

T::group('LocalAccountWriter: field writes');

$root = Tree::build([['name' => 'alice', 'uid' => '2100', 'email' => 'old@example.com']]);
$alice = Tree::user($root, 'alice');

truthy($writer->setField($alice, 'email', 'new@example.com'), 'changing a field reports a change');
eq('new@example.com', (string)$alice->email, 'the new value is stored');
falsy($writer->setField($alice, 'email', 'new@example.com'), 'rewriting the same value reports no change');
truthy($writer->setField($alice, 'email', ''), 'clearing a field reports a change');
eq('', (string)($alice->email ?? ''), 'the field is gone');

// stampOnce is what makes a binding permanent: it must never overwrite.
truthy($writer->stampOnce($alice, 'sso_subject', 'kc|first'), 'the first stamp is written');
eq('kc|first', (string)$alice->sso_subject, 'and holds the value');
falsy($writer->stampOnce($alice, 'sso_subject', 'kc|second'), 'a second stamp is refused');
eq('kc|first', (string)$alice->sso_subject, 'the original stamp survives');
falsy($writer->stampOnce($alice, 'scim_ref', ''), 'an empty stamp is a no-op');

truthy($writer->setDisabled($alice, true), 'disabling reports a change');
eq('1', (string)$alice->disabled, 'the account is disabled');
falsy($writer->setDisabled($alice, true), 'disabling twice reports no change');
truthy($writer->setDisabled($alice, false), 'enabling reports a change');

// XML-special characters have to survive a round trip through addChild.
$writer->setField($alice, 'descr', 'Smith & Sons <ops> "x"');
eq('Smith & Sons <ops> "x"', (string)$alice->descr, 'XML metacharacters round-trip intact');

T::group('LocalAccount: disabled and expired accounts are refused');

$root = Tree::build([
    ['name' => 'fine', 'uid' => '2100'],
    ['name' => 'off', 'uid' => '2101', 'disabled' => '1'],
    ['name' => 'stale', 'uid' => '2102', 'expires' => date('m/d/Y', strtotime('-10 days'))],
    ['name' => 'future', 'uid' => '2103', 'expires' => date('m/d/Y', strtotime('+10 days'))],
]);

truthy(LocalAccount::isUsable(Tree::user($root, 'fine')), 'an ordinary account is usable');
falsy(LocalAccount::isUsable(Tree::user($root, 'off')), 'a disabled account is not');
falsy(LocalAccount::isUsable(Tree::user($root, 'stale')), 'an expired account is not');
truthy(LocalAccount::isUsable(Tree::user($root, 'future')), 'a future expiry is still usable');
throws(
    fn() => LocalAccount::assertUsable(Tree::user($root, 'off')),
    'disabled or expired',
    'assertUsable explains itself'
);
