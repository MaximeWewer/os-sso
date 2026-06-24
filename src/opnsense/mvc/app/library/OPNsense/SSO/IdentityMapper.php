<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;
use OPNsense\Core\Backend;

/**
 * Maps a NormalizedIdentity onto a LOCAL account name in config.xml.
 *
 * In pure-consumer mode the whole authorization decision lives here and in
 * GroupMapper: a wrong mapping = wrong privileges. The session
 * core trusts whatever username this returns, so this stays conservative:
 * exact matches only, no fuzzy/substring matching, creation off unless the
 * provider explicitly enabled it.
 */
final class IdentityMapper
{
    private GroupMapper $groupMapper;

    public function __construct(?GroupMapper $groupMapper = null)
    {
        $this->groupMapper = $groupMapper ?? new GroupMapper();
    }

    /**
     * Resolve the local username for an asserted identity, provisioning the
     * account if (and only if) the provider allows it.
     *
     * @param NormalizedIdentity $identity asserted by the protocol
     * @param bool   $allowCreate    provider opt-in for auto-provisioning
     * @param array  $defaultGroups  groups to grant a freshly created user
     * @return string local username
     * @throws \RuntimeException when no match exists and creation is disallowed
     */
    public function resolve(NormalizedIdentity $identity, bool $allowCreate, array $defaultGroups): string
    {
        // Serialize logins that may write config.xml across php-fpm workers, and
        // re-read under the lock, so concurrent provisioning can't clobber the file
        // or hand out duplicate UIDs.
        return $this->withConfigLock(
            fn() => $this->resolveLocked($identity, $allowCreate, $defaultGroups)
        );
    }

    private function withConfigLock(callable $fn): string
    {
        $fp = @fopen('/var/tmp/os-sso-config.lock', 'c');
        if ($fp === false) {
            return $fn(); // best-effort: proceed unlocked rather than fail login
        }
        @chmod('/var/tmp/os-sso-config.lock', 0600);
        try {
            flock($fp, LOCK_EX);
            Config::getInstance()->forceReload();
            return $fn();
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    private function resolveLocked(NormalizedIdentity $identity, bool $allowCreate, array $defaultGroups): string
    {
        $subjectKey = $this->subjectKey($identity);

        // 1. Durable match: an account already linked to this exact IdP subject.
        //    Immune to later username/email changes and to collisions.
        $node = $subjectKey !== '' ? $this->findBySubject($subjectKey) : null;

        // 2. First-time linking: by the configured username claim, then by a
        //    *verified* email -- and either may only (re)locate an SSO-managed
        //    account, never bind to a hand-created local user.
        $stamp = false;
        if ($node === null && $identity->username !== '') {
            $this->assertValidUsername($identity->username);
            $byName = $this->findByName($identity->username);
            if ($byName !== null) {
                // A username-claim collision with an account that has its own local
                // password would let anyone who can set their IdP username to an
                // existing local name take that account over (the username claim is
                // often a self-service IdP attribute). Bind by username only to an
                // SSO-managed account, exactly like the email path below; otherwise
                // refuse -- silently provisioning a duplicate name would be worse.
                if (!$this->isSsoManaged($byName)) {
                    throw new \RuntimeException(
                        "SSO: username '" . (string)$byName->name . "' collides with an existing " .
                        "local account; refusing to bind (use an immutable IdP username claim, or " .
                        "rename/remove the local account)"
                    );
                }
                $node = $byName;
            }
        }
        if ($node === null && $identity->emailVerified && $identity->email !== '') {
            $byEmail = $this->findByEmail($identity->email);
            if ($byEmail !== null && $this->isSsoManaged($byEmail)) {
                $node = $byEmail;
            }
        }

        if ($node !== null) {
            $this->guardBinding($node, $subjectKey);
            $stamp = $this->stampSubject($node, $subjectKey);
            $changed = $this->groupMapper->sync($node, $identity, $defaultGroups);
            if ($stamp || $changed) {
                Config::getInstance()->save();
                (new Backend())->configdpRun('auth user changed', [(string)$node->name]);
            }
            return (string)$node->name;
        }

        if (!$allowCreate) {
            throw new \RuntimeException(
                "SSO: no local account matches the asserted identity and auto-creation is disabled"
            );
        }

        $created = $this->provision($identity, $defaultGroups, $subjectKey);
        return (string)$created->name;
    }

    private function subjectKey(NormalizedIdentity $identity): string
    {
        return $identity->subject === '' ? '' : $identity->authServer . '|' . $identity->subject;
    }

    /**
     * Refuse binding SSO to a PRIVILEGED local account (the built-in system/root
     * accounts, or any member of the admins group) that was not provisioned by SSO
     * -- the classic "set my username/email to root and become admin" takeover.
     * SSO-managed accounts (scrambled password, IdP-only) are fine to re-bind, so
     * the same person logging in via a second IdP/protocol still works.
     *
     * Username-claim collisions on NON-privileged accounts remain the operator's
     * trust decision: the username claim MUST be an immutable, IdP-administered
     * attribute (documented).
     */
    private function guardBinding(\SimpleXMLElement $node, string $subjectKey): void
    {
        if ($this->isPrivileged($node) && !$this->isSsoManaged($node)) {
            throw new \RuntimeException(
                "SSO: refusing to bind to privileged local account '" . (string)$node->name .
                "' (provision a dedicated SSO account instead)"
            );
        }
    }

    private function isPrivileged(\SimpleXMLElement $node): bool
    {
        return $this->isSystemAccount($node) || $this->isInAdminsGroup((string)($node->uid ?? ''));
    }

    private function isInAdminsGroup(string $uid): bool
    {
        if ($uid === '') {
            return false;
        }
        $cnf = Config::getInstance()->object();
        foreach (($cnf->system->group ?? []) as $group) {
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

    private function stampSubject(\SimpleXMLElement $node, string $subjectKey): bool
    {
        if ($subjectKey === '' || (string)($node->sso_subject ?? '') !== '') {
            return false;
        }
        $node->addChild('sso_subject', htmlspecialchars($subjectKey, ENT_XML1));
        return true;
    }

    private function isSystemAccount(\SimpleXMLElement $node): bool
    {
        return (string)($node->scope ?? '') === 'system' || (string)($node->uid ?? '') === '0';
    }

    /** An account os-sso may (re)bind: it has no usable local password of its own. */
    private function isSsoManaged(\SimpleXMLElement $node): bool
    {
        return (string)($node->scrambled_password ?? '') === '1'
            || (string)($node->sso_subject ?? '') !== '';
    }

    private function findBySubject(string $subjectKey): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ((string)($user->sso_subject ?? '') !== '' && hash_equals((string)$user->sso_subject, $subjectKey)) {
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
    private function assertValidUsername(string $username): void
    {
        if (
            $username !== trim($username)
            || strlen($username) > 64
            || !preg_match('/^[A-Za-z0-9._-]+( [A-Za-z0-9._-]+)*$/', $username)
        ) {
            throw new \RuntimeException(
                "SSO: asserted username is not a valid local account name " .
                "(allowed: letters, digits, '.', '-', '_', single interior spaces; 1-64 chars)"
            );
        }
    }

    private function findByName(string $username): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if ((string)$user->name === $username) {
                return $user;
            }
        }
        return null;
    }

    private function findByEmail(string $email): ?\SimpleXMLElement
    {
        foreach ($this->users() as $user) {
            if (isset($user->email) && (string)$user->email === $email) {
                return $user;
            }
        }
        return null;
    }

    /** @return \SimpleXMLElement[] */
    private function users(): array
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

    /**
     * Create a local user persisted in config.xml so the ACL can see its groups.
     * The account carries no usable local password (scrambled) -- the only way in
     * is the IdP. Auto-created users MUST be persisted to config.xml.
     */
    private function provision(NormalizedIdentity $identity, array $defaultGroups, string $subjectKey): \SimpleXMLElement
    {
        $username = $identity->username;
        if ($username === '') {
            throw new \RuntimeException("SSO: cannot provision a user without a username claim");
        }
        $this->assertValidUsername($username);

        // Use the legacy config_* helpers to append a user node, mirroring how the
        // core User model serializes. We avoid the high-level Model here to keep
        // this dependency-light; the controller persists + reloads.
        $cnf = Config::getInstance()->object();
        $userNode = $cnf->system->addChild('user');
        $userNode->addChild('name', htmlspecialchars($username, ENT_XML1));
        $userNode->addChild('descr', htmlspecialchars($identity->displayName ?: $username, ENT_XML1));
        if ($identity->email !== '') {
            $userNode->addChild('email', htmlspecialchars($identity->email, ENT_XML1));
        }
        $userNode->addChild('comment', 'Created by os-sso (' . htmlspecialchars($identity->authServer, ENT_XML1) . ')');
        $userNode->addChild('scope', 'user');
        $userNode->addChild('disabled', '0');
        // No local login: scrambled, unusable password.
        $userNode->addChild('password', '*');
        $userNode->addChild('scrambled_password', '1');
        $userNode->addChild('uid', (string)$this->nextUid($cnf));
        // Durable link to the IdP subject so future logins match on this, not on
        // a mutable username/email.
        if ($subjectKey !== '') {
            $userNode->addChild('sso_subject', htmlspecialchars($subjectKey, ENT_XML1));
        }

        $this->groupMapper->sync($userNode, $identity, $defaultGroups);

        Config::getInstance()->save();
        (new Backend())->configdpRun('auth sync user', [$username]);
        Config::getInstance()->forceReload();

        return $userNode;
    }

    private function nextUid(\SimpleXMLElement $cnf): int
    {
        $next = (int)($cnf->system->nextuid ?? 2000);
        $cnf->system->nextuid = (string)($next + 1);
        return $next;
    }
}
