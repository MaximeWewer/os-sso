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

    /** refuse a weak match onto an account only other providers have claimed */
    private bool $strictBinding;

    public function __construct(
        ?GroupMapper $groupMapper = null,
        ?LocalAccountWriter $accounts = null,
        bool $strictBinding = false
    ) {
        $this->groupMapper = $groupMapper ?? new GroupMapper();
        $this->accounts = $accounts ?? new LocalAccountWriter();
        $this->strictBinding = $strictBinding;
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
        $node = $this->accounts->findBySubject($subjectKey);

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
            $stamped = $this->accounts->addBinding($node, $subjectKey);
            $refreshed = $this->refreshAttributes($node, $identity);
            $changed = $this->groupMapper->sync($node, $identity, $defaultGroups);
            if ($stamped || $refreshed || $changed) {
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

    /**
     * Bring the account's descriptive fields back in line with the assertion.
     *
     * They were written once, at creation, and never again: someone whose display name
     * or address changed at the directory kept the old one on the firewall for as long
     * as the account lived, which is the kind of drift nobody notices until an email
     * goes to an address that no longer exists.
     *
     * Only the two fields that describe a person, and only on accounts os-sso owns. The
     * ones an operator might expect to see here are deliberately absent: a `shell` is
     * how an account gets SSH, `expires` is the operator's own lever for ending access,
     * an OTP seed is a second factor for a password these accounts do not have, and API
     * keys are separate credentials. None of those is a directory's to set.
     *
     * @return bool whether anything changed (the caller persists config.xml if so)
     */
    private function refreshAttributes(\SimpleXMLElement $node, NormalizedIdentity $identity): bool
    {
        if (!$this->accounts->isSsoManaged($node)) {
            return false; // bound, but not ours to rewrite
        }
        $changed = false;
        if ($identity->displayName !== '') {
            $changed = $this->accounts->setField($node, 'descr', $identity->displayName) || $changed;
        }
        // An address only follows the account when the IdP vouches for it, the same
        // condition under which it is allowed to FIND an account in the first place.
        if ($identity->email !== '' && $identity->emailVerified) {
            $changed = $this->accounts->setField($node, 'email', $identity->email) || $changed;
        }
        return $changed;
    }

    private function subjectKey(NormalizedIdentity $identity): string
    {
        return $identity->subject === '' ? '' : $identity->authServer . '|' . $identity->subject;
    }

    /**
     * A weak match -- username claim or verified email -- may not land on an account this
     * provider has already bound to a DIFFERENT subject.
     *
     * The binding is the only durable link between an account and a person; the username
     * claim is not. Without this check, a second subject that manages to present the
     * first one's username inherits the account, its groups and its history: a rename at
     * the IdP, a directory account deleted and recreated there with a fresh `sub`, or
     * simply a mutable claim such as `email`. A bound account is os-sso-owned by
     * definition, so neither the password-collision guard above nor guardBinding() below
     * sees anything wrong with it.
     *
     * Scoped to THIS provider. Another provider's binding is not a conflict: the operator
     * registered each authentication server separately and each vouches for its own
     * users, which is what makes one account reachable through a directory's OIDC and
     * SAML front doors at once. What must never happen is two subjects of the SAME
     * provider sharing an account -- there, the claim is the only thing distinguishing
     * them, and it is exactly the thing that can be made to collide.
     *
     * An identity asserting no subject at all cannot be pinned, so it may not take over
     * an account that anyone is bound to.
     *
     * Whether a SECOND provider may bind alongside at all is the operator's call, because
     * nothing in the configuration distinguishes the two shapes: one directory behind two
     * authentication servers (the same person, and binding alongside is the point), and
     * two unrelated directories where a user of one presenting a username from the other
     * inherits their account. Strict binding, per provider, answers it -- and it reads
     * both kinds of stamp, so an account a directory pre-provisioned over SCIM and nobody
     * has logged into yet is claimed just as much as one somebody has.
     */
    private function assertNotBoundElsewhere(\SimpleXMLElement $node, string $subjectKey): void
    {
        if ($subjectKey === '') {
            if ($this->accounts->subjectBindings($node) !== []) {
                throw new \RuntimeException(
                    "SSO: local account '" . (string)$node->name . "' is bound to an IdP subject " .
                    "and this identity asserts none; refusing to bind"
                );
            }
            $this->assertNotClaimedElsewhere($node, '');
            return;
        }
        $provider = explode('|', $subjectKey, 2)[0];
        $existing = $this->accounts->bindingFor($node, $provider);
        if ($existing !== '' && !hash_equals($existing, $subjectKey)) {
            throw new \RuntimeException(
                "SSO: local account '" . (string)$node->name . "' is already bound to another " .
                "subject of provider '" . $provider . "'; refusing to bind (one account belongs to " .
                "one subject per provider -- provision a separate account, or clear its binding in " .
                "config.xml if the account really did change hands)"
            );
        }
        if ($existing === '') {
            $this->assertNotClaimedElsewhere($node, $provider);
        }
    }

    /**
     * With strict binding on, refuse an account every existing claim on which belongs to
     * a different provider.
     *
     * Only reached on a weak match -- the username claim or a verified email -- so the
     * durable subject stamp still binds whatever this says. An account nobody has claimed
     * is free to take, which is what makes strict binding safe to turn on: it narrows who
     * may join an account that is already somebody's, not who may have one.
     */
    private function assertNotClaimedElsewhere(\SimpleXMLElement $node, string $provider): void
    {
        if (!$this->strictBinding) {
            return;
        }
        $claimed = $this->accounts->claimingProviders($node);
        if ($claimed === [] || ($provider !== '' && in_array($provider, $claimed, true))) {
            return;
        }
        throw new \RuntimeException(
            "SSO: local account '" . (string)$node->name . "' is claimed by provider '" .
            implode("', '", $claimed) . "' and strict account binding is on for " .
            ($provider !== '' ? "'" . $provider . "'" : 'this provider') .
            "; refusing to bind (turn strict binding off if both servers front the same " .
            "directory, or provision a separate account)"
        );
    }

    /**
     * Refuse binding SSO to a PRIVILEGED local account -- the built-in system/root
     * accounts, a member of the admins group, or one carrying an escalation privilege of
     * its own -- that was not provisioned by SSO. The classic "set my username or email
     * to root and become admin" takeover. SSO-managed accounts (scrambled password,
     * IdP-only) are fine to re-bind, so the same person logging in through a second
     * IdP or protocol still works.
     *
     * Username-claim collisions on NON-privileged accounts remain the operator's trust
     * decision: the username claim MUST be an immutable, IdP-administered attribute
     * (documented).
     */
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
