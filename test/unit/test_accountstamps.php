<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\AccountStamps;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\Test\Tree;

/** What core's user model does on save: keep only the fields it knows (issue #13). */
function coreRewritesUsers(SimpleXMLElement $root): void
{
    foreach ($root->system->user as $user) {
        foreach (AccountStamps::FIELDS as $field) {
            unset($user->{$field});
        }
    }
}

T::group('AccountStamps: what os-sso knows about an account survives core rewriting it');

$writer = new LocalAccountWriter();
$root = Tree::build();
$alice = $writer->create(['name' => 'alice', 'sso_subject' => 'entra|sub-a']);
$writer->setField($alice, 'sso_groups', 'admins');
eq(0, count($alice->sso_owned) + count($alice->sso_subject) + count($alice->sso_groups), 'nothing is written on <user> itself');
eq('2000', (string)$root->OPNsense->SSO->accounts->account[0]['uid'], 'it is kept against the uid, under OPNsense/SSO');

coreRewritesUsers($root);
$alice = Tree::user($root, 'alice');
truthy($writer->isSsoManaged($alice), 'the account is still ours after core rewrote the users');
eq('entra|sub-a', $writer->bindingFor($alice, 'entra'), 'its binding is still there');
eq('alice', (string)($writer->findBySubject('entra|sub-a')->name ?? ''), 'and a login still finds it by subject');
eq('admins', $writer->stamp($alice, 'sso_groups'), 'and so is the group provenance');

T::group('AccountStamps: configurations written the old way');

$root = Tree::build([['name' => 'bob', 'uid' => '2001', 'sso_owned' => '1', 'sso_subject' => 'kc|sub-b']]);
$bob = Tree::user($root, 'bob');
truthy($writer->isSsoManaged($bob), 'stamps still on <user> are read');
truthy(AccountStamps::adopt($bob), 'adopt() moves them');
eq(0, count($bob->sso_owned) + count($bob->sso_subject), 'off the <user>');
eq('kc|sub-b', AccountStamps::value($bob, 'sso_subject'), 'and into the record');
falsy(AccountStamps::adopt($bob), 'a second adopt() has nothing to move');

// A write must clear the old copy, or the read merge would bring a stale value back.
$root = Tree::build([['name' => 'carol', 'uid' => '2002', 'sso_deprovisioned' => '1']]);
$carol = Tree::user($root, 'carol');
truthy(AccountStamps::set($carol, 'sso_deprovisioned', ''), 'clearing a stamp held the old way');
eq('', AccountStamps::value($carol, 'sso_deprovisioned'), 'leaves nothing to read back');

T::group('AccountStamps: records of deleted accounts are dropped');

$root = Tree::build([['name' => 'dave', 'uid' => '2003']]);
AccountStamps::set(Tree::user($root, 'dave'), 'sso_owned', '1');
$gone = $root->OPNsense->SSO->accounts->addChild('account');
$gone->addAttribute('uid', '1999');
eq(1, AccountStamps::prune(), 'one orphan is pruned');
eq(['2003'], array_map(fn($a) => (string)$a['uid'], iterator_to_array($root->OPNsense->SSO->accounts->account, false)), 'the live one stays');

T::group('AccountStamps: bindings core already erased come back from a backup');

$dir = sys_get_temp_dir() . '/os-sso-backups-' . getmypid();
@mkdir($dir);
// The revision before core's rewrite: stamps still on <user>, the old way.
file_put_contents("$dir/config-100.xml", '<opnsense><system>'
    . '<user><name>erin</name><uid>2010</uid><password>*</password><scrambled_password>1</scrambled_password>'
    . '<sso_owned>1</sso_owned><sso_subject>entra|sub-e</sso_subject><sso_groups>admins</sso_groups><sso_deprovisioned>1</sso_deprovisioned></user>'
    . '<user><name>frank</name><uid>2011</uid><password>*</password><sso_owned>1</sso_owned><sso_subject>entra|sub-f</sso_subject></user>'
    . '<user><name>gina</name><uid>2012</uid><password>*</password><sso_owned>1</sso_owned><sso_subject>entra|sub-g</sso_subject></user>'
    . '</system></opnsense>');
// Today: core has rewritten them all. frank has since been given a real password,
// and uid 2012 now belongs to someone else by name.
$root = Tree::build([
    ['name' => 'erin', 'uid' => '2010', 'password' => '*', 'scrambled_password' => '1'],
    ['name' => 'frank', 'uid' => '2011', 'password' => '$2y$10$abcdefghijklmnopqrstuv'],
    ['name' => 'gino', 'uid' => '2012', 'password' => '*'],
]);
eq(['erin'], AccountStamps::recover(["$dir/config-100.xml"]), 'only the account that is still the same IdP-only one is recovered');
$erin = Tree::user($root, 'erin');
truthy($writer->isSsoManaged($erin), 'it is ours again');
eq('entra|sub-e', $writer->bindingFor($erin, 'entra'), 'with its binding');
eq('', $writer->stamp($erin, 'sso_groups'), 'but not its past group provenance');
eq('', $writer->stamp($erin, 'sso_deprovisioned'), 'nor a past deprovisioning');
falsy($writer->isSsoManaged(Tree::user($root, 'frank')), 'an account given a local password since is left alone');
falsy($writer->isSsoManaged(Tree::user($root, 'gino')), 'a uid now carrying another name is left alone');
eq([], AccountStamps::recover(["$dir/config-100.xml"]), 'and nothing is recovered twice');
array_map('unlink', glob("$dir/*"));
rmdir($dir);
