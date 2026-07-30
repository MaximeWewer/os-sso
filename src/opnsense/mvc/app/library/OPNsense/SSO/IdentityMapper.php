<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Maps a NormalizedIdentity onto a LOCAL account name in config.xml.
 *
 * In pure-consumer mode the whole authorization decision lives here and in
 * GroupMapper: a wrong mapping = wrong privileges. The session
 * core trusts whatever username this returns, so this stays conservative:
 * exact matches only, no fuzzy/substring matching, creation off unless the
 * provider explicitly enabled it.
 *
 * The mechanics of finding and writing a user node live in LocalAccountWriter,
 * shared with the SCIM endpoint. What stays here is the login policy: which
 * identity may bind to which account.
 */
final class IdentityMapper
{
    private GroupMapper $groupMapper;
    private LocalAccountWriter $accounts;

    public function __construct(?GroupMapper $groupMapper = null, ?LocalAccountWriter $accounts = null)
    {
        $this->groupMapper = $groupMapper ?? new GroupMapper();
        $this->accounts = $accounts ?? new LocalAccountWriter();
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
        return (string)ConfigLock::with(
            fn() => $this->resolveLocked($identity, $allowCreate, $defaultGroups)
        );
    }

    private function resolveLocked(NormalizedIdentity $identity, bool $allowCreate, array $defaultGroups): string
    {
        $subjectKey = $this->subjectKey($identity);

        // 1. Durable match: an account already linked to this exact IdP subject.
        //    Immune to later username/email changes and to collisions.
        $node = $this->accounts->findByStamp('sso_subject', $subjectKey);

        // 2. First-time linking: by the configured username claim -- which may land on
        //    any account with no usable local password of its own -- then by a
        //    *verified* email, which only ever (re)locates an account we already own.
        //    Neither may take over an account bound to a different subject.
        if ($node === null && $identity->username !== '') {
            $this->accounts->assertValidUsername($identity->username);
            $byName = $this->accounts->findByName($identity->username);
            if ($byName !== null) {
                // Refuse only when the match is a real human-owned account, i.e. one
                // with a USABLE local password: binding the (often self-service,
                // mutable) IdP username claim to it would be a takeover. SSO-managed
                // accounts and otherwise passwordless/locked ones (no local login of
                // their own) are safe to (re)bind -- and privileged accounts are
                // additionally gated by guardBinding() below.
                if (!$this->accounts->isSsoManaged($byName) && $this->accounts->hasUsableLocalPassword($byName)) {
                    throw new \RuntimeException(
                        "SSO: username '" . (string)$byName->name . "' collides with an existing " .
                        "local account that has its own password; refusing to bind (use an immutable " .
                        "IdP username claim, or rename/remove the local account)"
                    );
                }
                $this->assertNotBoundElsewhere($byName, $subjectKey);
                $node = $byName;
            }
        }
        if ($node === null && $identity->emailVerified && $identity->email !== '') {
            $byEmail = $this->accounts->findByEmail($identity->email);
            if ($byEmail !== null && $this->accounts->isSsoManaged($byEmail)) {
                $this->assertNotBoundElsewhere($byEmail, $subjectKey);
                $node = $byEmail;
            }
        }

        if ($node !== null) {
            // Ask before writing anything. A disabled or expired account is refused
            // downstream anyway, but until now it was refused AFTER group sync had
            // already saved config.xml -- and on the VPN path, where no WebGUI session
            // is opened, it was not refused at all.
            LocalAccount::assertUsable($node);
            $this->guardBinding($node);
            $stamped = $this->accounts->stampOnce($node, 'sso_subject', $subjectKey);
            $changed = $this->groupMapper->sync($node, $identity, $defaultGroups);
            if ($stamped || $changed) {
                $this->accounts->persist((string)$node->name);
            }
            return (string)$node->name;
        }

        if (!$allowCreate) {
            throw new \RuntimeException(
                "SSO: no local account matches the asserted identity and auto-creation is disabled"
            );
        }

        return $this->provision($identity, $defaultGroups, $subjectKey);
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
    /**
     * A weak match -- username claim or verified email -- may not land on an account
     * that is ALREADY bound to a different IdP subject.
     *
     * The stamp is the only durable link between an account and a person; the username
     * claim is not. Without this check, a second subject that manages to present the
     * first one's username inherits the account, its groups and its history: a rename
     * at the IdP, a directory account deleted and recreated there with a fresh `sub`,
     * or simply a mutable claim such as `email`. The stamped account is SSO-managed by
     * definition, so neither the password-collision guard above nor guardBinding()
     * below sees anything wrong with it.
     *
     * An empty $subjectKey (no `sub` asserted at all) is refused for the same reason:
     * we cannot show it is the same person, so we do not guess.
     */
    private function assertNotBoundElsewhere(\SimpleXMLElement $node, string $subjectKey): void
    {
        $stamp = (string)($node->sso_subject ?? '');
        if ($stamp === '' || hash_equals($stamp, $subjectKey)) {
            return;
        }
        throw new \RuntimeException(
            "SSO: local account '" . (string)$node->name . "' is already bound to another " .
            "IdP subject; refusing to bind (one local account belongs to one IdP subject -- " .
            "provision a separate account, or clear its binding in config.xml if the account " .
            "really did change hands)"
        );
    }

    private function guardBinding(\SimpleXMLElement $node): void
    {
        if ($this->accounts->isPrivileged($node) && !$this->accounts->isSsoManaged($node)) {
            throw new \RuntimeException(
                "SSO: refusing to bind to privileged local account '" . (string)$node->name .
                "' (provision a dedicated SSO account instead)"
            );
        }
    }

    /**
     * Create a local user persisted in config.xml so the ACL can see its groups.
     * The account carries no usable local password -- the only way in is the IdP.
     */
    private function provision(NormalizedIdentity $identity, array $defaultGroups, string $subjectKey): string
    {
        if ($identity->username === '') {
            throw new \RuntimeException("SSO: cannot provision a user without a username claim");
        }
        $node = $this->accounts->create([
            'name' => $identity->username,
            'descr' => $identity->displayName,
            'email' => $identity->email,
            'comment' => 'Created by os-sso (' . $identity->authServer . ')',
            'sso_subject' => $subjectKey,
        ]);
        $this->groupMapper->sync($node, $identity, $defaultGroups);
        $this->accounts->persist($identity->username, true);
        return $identity->username;
    }
}
