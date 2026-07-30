<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\SSO\GroupMembers;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\Privilege;
use OPNsense\SSO\Test\Tree;

T::group('Privilege: which groups must stay an operator decision');

$root = Tree::build([], [
    ['name' => 'admins', 'gid' => '1999'],
    ['name' => 'ADMINS-upper', 'gid' => '1998'],
    ['name' => 'fullgui', 'gid' => '2001', 'priv' => ['page-all']],
    ['name' => 'shell', 'gid' => '2002', 'priv' => ['user-shell-access']],
    ['name' => 'usermgr', 'gid' => '2003', 'priv' => ['page-system-usermanager']],
    ['name' => 'combo', 'gid' => '2004', 'priv' => ['page-diagnostics-log,page-all']],
    ['name' => 'plain', 'gid' => '2005', 'priv' => ['page-dashboard-all']],
    ['name' => 'bare', 'gid' => '2006'],
]);

truthy(Privilege::isPrivilegedGroup(Tree::group($root, 'admins')), 'admins is privileged by name');
truthy(Privilege::isPrivilegedGroup(Tree::group($root, 'fullgui')), 'page-all is privileged');
truthy(Privilege::isPrivilegedGroup(Tree::group($root, 'shell')), 'user-shell-access is privileged');
truthy(Privilege::isPrivilegedGroup(Tree::group($root, 'usermgr')), 'page-system-usermanager is privileged');
// The priv element holds a comma-separated list; an escalation privilege anywhere in it
// counts, not only as the sole value.
truthy(Privilege::isPrivilegedGroup(Tree::group($root, 'combo')), 'page-all inside a csv priv list is found');
falsy(Privilege::isPrivilegedGroup(Tree::group($root, 'plain')), 'an ordinary page privilege is not escalation');
falsy(Privilege::isPrivilegedGroup(Tree::group($root, 'bare')), 'a group with no privileges is not privileged');

T::group('Privilege: which accounts must never be bound to');

$root = Tree::build([
    ['name' => 'root', 'uid' => '0', 'scope' => 'system'],
    ['name' => 'sysacct', 'uid' => '2100', 'scope' => 'system'],
    ['name' => 'boss', 'uid' => '2101', 'scope' => 'user'],
    ['name' => 'ordinary', 'uid' => '2102', 'scope' => 'user'],
    ['name' => 'nouid', 'scope' => 'user'],
    // Privileges granted on the account itself, no admins membership anywhere: the
    // "LDAP-backed administrator" shape.
    ['name' => 'directadmin', 'uid' => '2103', 'scope' => 'user', 'priv' => ['page-all']],
    ['name' => 'shelluser', 'uid' => '2104', 'scope' => 'user', 'priv' => ['user-shell-access']],
    ['name' => 'usermgr', 'uid' => '2105', 'scope' => 'user', 'priv' => ['page-dashboard-all,page-system-usermanager']],
    ['name' => 'reader', 'uid' => '2106', 'scope' => 'user', 'priv' => ['page-dashboard-all']],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '2101'],
    ['name' => 'staff', 'gid' => '2000', 'member' => '2102'],
]);

truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'root')), 'uid 0 is privileged');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'sysacct')), 'a system-scope account is privileged');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'boss')), 'a member of admins is privileged');
falsy(Privilege::isPrivilegedAccount(Tree::user($root, 'ordinary')), 'a member of an ordinary group is not');
falsy(Privilege::isPrivilegedAccount(Tree::user($root, 'nouid')), 'an account with no uid is not');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'directadmin')), 'page-all on the account itself is privileged');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'shelluser')), 'user-shell-access on the account is privileged');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'usermgr')), 'page-system-usermanager inside a csv priv list is found');
falsy(Privilege::isPrivilegedAccount(Tree::user($root, 'reader')), 'an ordinary page privilege on the account is not escalation');

// LocalAccountWriter delegates now; prove the public entry point still answers the same,
// since IdentityMapper and ScimUsers gate on it.
$writer = new LocalAccountWriter();
truthy($writer->isPrivileged(Tree::user($root, 'boss')), 'LocalAccountWriter::isPrivileged agrees for admins');
falsy($writer->isPrivileged(Tree::user($root, 'ordinary')), 'LocalAccountWriter::isPrivileged agrees for staff');

T::group('GroupMembers: uid 0 is root, not "nothing"');

// The bug this class exists for: array_filter() on an exploded member list drops the
// string "0", so every rewrite of a group's members silently dropped root -- and with it
// the admins membership the anti-lockout rules are meant to protect.
$root = Tree::build([
    ['name' => 'root', 'uid' => '0', 'scope' => 'system'],
    ['name' => 'alice', 'uid' => '2100', 'scrambled_password' => '1'],
], [
    ['name' => 'admins', 'gid' => '1999', 'member' => '0,2100'],
    ['name' => 'empty', 'gid' => '2000'],
    ['name' => 'spaced', 'gid' => '2001', 'member' => ' 0 , 2100 ,,'],
]);

eq(['0', '2100'], GroupMembers::uids(Tree::group($root, 'admins')), 'root is read back as a member');
eq([], GroupMembers::uids(Tree::group($root, 'empty')), 'a group with no members is empty');
eq(['0', '2100'], GroupMembers::uids(Tree::group($root, 'spaced')), 'whitespace and empty entries are dropped, uids are not');
truthy(GroupMembers::contains(Tree::group($root, 'admins'), '0'), 'contains() finds uid 0');
falsy(GroupMembers::contains(Tree::group($root, 'admins'), ''), 'and no uid at all is not a member');

GroupMembers::set(Tree::group($root, 'admins'), ['0', '2100', '2101']);
eq('0,2100,2101', (string)Tree::group($root, 'admins')->member, 'writing the list keeps root in it');

// The account check reads the same list: root has to look privileged through its
// membership, not only through its uid.
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'root')), 'root is privileged');
truthy(Privilege::isPrivilegedAccount(Tree::user($root, 'alice')), 'and so is the other admins member');
