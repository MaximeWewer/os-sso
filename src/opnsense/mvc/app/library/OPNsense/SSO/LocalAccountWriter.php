<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Every read and write os-sso performs on a config.xml user node.
 *
 * Two very different callers need the same primitives: IdentityMapper, which acts on
 * an identity asserted during a login, and the SCIM endpoint, which acts on a
 * directory push with no login and no assertion at all. The account rules -- what a
 * username may look like, which accounts are privileged, which ones os-sso is allowed
 * to touch -- must not be duplicated between them, because a rule enforced on only
 * one of the two paths is a rule that can be walked around by using the other.
 *
 * Nothing here decides policy. It finds, creates and edits nodes; the callers decide
 * whether they are allowed to.
 */
final class LocalAccountWriter
{
    /** @return \SimpleXMLElement[] */
    public function users(): array
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return [];
        }
        $out = [];
        foreach ($cnf->system->user as $user) {
            $out[] = $user;
        }
        return $out;
    }

    public function findByName(string $username): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ((string)$user->name === $username) {
                return $user;
            }
        }
        return null;
    }

    public function findByUid(string $uid): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ($uid !== '' && (string)($user->uid ?? '') === $uid) {
                return $user;
            }
        }
        return null;
    }

    public function findByEmail(string $email): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if (isset($user->email) && (string)$user->email === $email) {
                return $user;
            }
        }
        return null;
    }

    /** Account carrying this exact value in $field (a namespaced external id). */
    public function findByStamp(string $field, string $value): ?\SimpleXMLElement
    {
        if ($value === '') {
            return null;
        }
        foreach ($this->users() as $user) {
            $stamp = (string)($user->{$field} ?? '');
            if ($stamp !== '' && hash_equals($stamp, $value)) {
                return $user;
            }
        }
        return null;
    }

    /**
     * Enforce a strict local-username shape before the name is used to match an
     * account or written to config.xml. We bypass the core User model (to stay
     * dependency-light), so we must re-apply its constraint here: a username
     * carrying control characters or newlines would forge syslog/audit lines, and
     * leading/trailing whitespace or interior runs invite homoglyph collisions
     * with existing accounts. Allowed: letters, digits, '.', '-', '_', and single
     * interior spaces; 1-64 chars; no edge whitespace.
     */
    public function assertValidUsername(string $username): void
    {
        if (
            $username !== trim($username)
            || strlen($username) > 64
            || !preg_match('/^[A-Za-z0-9._-]+( [A-Za-z0-9._-]+)*$/', $username)
        ) {
            throw new \RuntimeException(
                "SSO: '" . preg_replace('/[^\x20-\x7e]/', '', $username) . "' is not a valid local " .
                "account name (allowed: letters, digits, '.', '-', '_', single interior spaces; 1-64 chars)"
            );
        }
    }

    /** Built-in/system account, or a member of the admins group. */
    public function isPrivileged(\SimpleXMLElement $node): bool
    {
        if ((string)($node->scope ?? '') === 'system' || (string)($node->uid ?? '') === '0') {
            return true;
        }
        $uid = (string)($node->uid ?? '');
        if ($uid === '') {
            return false;
        }
        foreach ((Config::getInstance()->object()->system->group ?? []) as $group) {
            if (strtolower((string)$group->name) !== 'admins') {
                continue;
            }
            foreach ($group->member as $member) {
                if (in_array($uid, array_filter(explode(',', (string)$member)), true)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** An account os-sso may (re)bind: it has no usable local password of its own. */
    public function isSsoManaged(\SimpleXMLElement $node): bool
    {
        return (string)($node->scrambled_password ?? '') === '1'
            || (string)($node->sso_subject ?? '') !== ''
            || (string)($node->scim_ref ?? '') !== '';
    }

    /**
     * True if the account logs in with a real local password -- i.e. a human-owned
     * account. A scrambled password (IdP-only), an empty one, or the classic unix
     * lock ("*" / "!...") is NOT usable, so such accounts are safe for SSO to bind.
     */
    public function hasUsableLocalPassword(\SimpleXMLElement $node): bool
    {
        if ((string)($node->scrambled_password ?? '') === '1') {
            return false;
        }
        $pw = (string)($node->password ?? '');
        return $pw !== '' && $pw !== '*' && ($pw[0] ?? '') !== '!';
    }

    /**
     * Create a local user node. No usable local password: the only way in is the IdP.
     *
     * @param array $attrs name (required), descr, email, comment, and any extra
     *                     scalar children to stamp (sso_subject, scim_ref, ...)
     */
    public function create(array $attrs): \SimpleXMLElement
    {
        $username = (string)($attrs['name'] ?? '');
        $this->assertValidUsername($username);

        $cnf = Config::getInstance()->object();
        $node = $cnf->system->addChild('user');
        $node->addChild('name', $this->xml($username));
        $node->addChild('descr', $this->xml((string)($attrs['descr'] ?? '') ?: $username));
        if (!empty($attrs['email'])) {
            $node->addChild('email', $this->xml((string)$attrs['email']));
        }
        $node->addChild('comment', $this->xml((string)($attrs['comment'] ?? 'Created by os-sso')));
        $node->addChild('scope', 'user');
        $node->addChild('disabled', empty($attrs['disabled']) ? '0' : '1');
        $node->addChild('password', '*');
        $node->addChild('scrambled_password', '1');
        $node->addChild('uid', (string)$this->nextUid($cnf));
        foreach (['sso_subject', 'scim_ref'] as $stamp) {
            if (!empty($attrs[$stamp])) {
                $node->addChild($stamp, $this->xml((string)$attrs[$stamp]));
            }
        }
        return $node;
    }

    /** Set a scalar child, adding it when absent. Returns whether anything changed. */
    public function setField(\SimpleXMLElement $node, string $field, string $value): bool
    {
        if ((string)($node->{$field} ?? '') === $value) {
            return false;
        }
        unset($node->{$field});
        if ($value !== '') {
            $node->addChild($field, $this->xml($value));
        }
        return true;
    }

    /** Stamp an external identifier once; never overwrite an existing one. */
    public function stampOnce(\SimpleXMLElement $node, string $field, string $value): bool
    {
        if ($value === '' || (string)($node->{$field} ?? '') !== '') {
            return false;
        }
        $node->addChild($field, $this->xml($value));
        return true;
    }

    /** @return bool whether the flag changed */
    public function setDisabled(\SimpleXMLElement $node, bool $disabled): bool
    {
        $current = !empty((string)($node->disabled ?? ''));
        if ($current === $disabled) {
            return false;
        }
        return $this->setField($node, 'disabled', $disabled ? '1' : '0');
    }

    /**
     * Persist config.xml and tell the rest of the system about it.
     *
     * @param bool $isNew a fresh account needs "auth sync user" (it creates the unix
     *                    side); an edit only needs "auth user changed"
     */
    public function persist(string $username, bool $isNew = false): void
    {
        Config::getInstance()->save();
        (new Backend())->configdpRun($isNew ? 'auth sync user' : 'auth user changed', [$username]);
        if ($isNew) {
            Config::getInstance()->forceReload();
        }
    }

    private function nextUid(\SimpleXMLElement $cnf): int
    {
        $next = (int)($cnf->system->nextuid ?? 2000);
        $cnf->system->nextuid = (string)($next + 1);
        return $next;
    }

    private function xml(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1);
    }
}
