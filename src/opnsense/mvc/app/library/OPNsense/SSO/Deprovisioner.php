<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Turns "the IdP no longer lets this person in" into a local account that is disabled
 * and sessions that are ended.
 *
 * A login-driven plugin only ever learns about a revocation when the person tries to
 * log in and is refused -- there is no directory to poll. That refusal is the signal
 * used here: an account that fails the provider's required-groups gate is deactivated
 * rather than left sitting there enabled, with whatever group membership it had.
 *
 * Deliberately narrow, because getting this wrong locks people out of a firewall:
 *   - only accounts os-sso itself manages (linked subject, no usable local password);
 *   - never a privileged one -- an admins-group account is reported, never disabled,
 *     since a bad IdP group edit must not be able to lock out the firewall;
 *   - disabled, never deleted: reversible, and it keeps the audit trail and the uid.
 */
final class Deprovisioner
{
    /**
     * Stamp recording that os-sso is what disabled this account -- and therefore that
     * os-sso may enable it again.
     *
     * Without it, deprovisioning is a one-way door: the account is disabled by a refused
     * login, and the login that should undo it (the person put back in the right IdP
     * group) is refused by the disabled flag before anything re-evaluates it. Somebody
     * has to go and tick the box back by hand, which is the opposite of what pushing
     * lifecycle to the directory is for.
     *
     * It cannot simply be "enable any disabled account whose login now passes", because
     * <disabled> is also the operator's own lever and SSO must not route around it. The
     * stamp is the difference: it is written only here, and dropped the moment the
     * account is seen enabled, so an operator who re-enables an account and later
     * disables it again is never overruled.
     */
    private const DEPROVISIONED_FIELD = 'sso_deprovisioned';

    /**
     * Deactivate the local account behind a refused identity, if os-sso owns it.
     *
     * @return bool whether an account was disabled
     */
    public static function disableFor(NormalizedIdentity $identity): bool
    {
        $subjectKey = $identity->subject === ''
            ? ''
            : $identity->authServer . '|' . $identity->subject;
        if ($subjectKey === '') {
            return false; // nothing durable to match on
        }

        try {
            return (bool)ConfigLock::with(function () use ($subjectKey, $identity) {
                $node = self::findManaged($subjectKey);
                if ($node === null) {
                    return false;
                }
                $username = (string)$node->name;
                if (Privilege::isPrivilegedAccount($node)) {
                    syslog(LOG_WARNING, sprintf(
                        "os-sso: NOT deprovisioning privileged account '%s' refused by %s -- " .
                        "disable it by hand if that is what you want",
                        $username,
                        $identity->authServer
                    ));
                    return false;
                }
                if (!empty((string)($node->disabled ?? ''))) {
                    return false; // already disabled
                }
                unset($node->disabled);
                $node->addChild('disabled', '1');
                // Ours, so a later successful login may undo it (see reviveNode()).
                unset($node->{self::DEPROVISIONED_FIELD});
                $node->addChild(self::DEPROVISIONED_FIELD, '1');
                Config::getInstance()->save();
                (new Backend())->configdpRun('auth user changed', [$username]);

                $ended = SessionRegistry::destroyWhere(
                    fn(array $entry) => (string)($entry['username'] ?? '') === $username
                );
                syslog(LOG_WARNING, sprintf(
                    "os-sso: disabled local account '%s' (refused by %s), ended %d session(s)",
                    $username,
                    $identity->authServer,
                    $ended
                ));
                return true;
            });
        } catch (\Throwable $e) {
            // Never let deprovisioning turn a clean refusal into a 500: the login is
            // being denied either way.
            syslog(LOG_ERR, 'os-sso: deprovisioning failed: ' . $e->getMessage());
            return false;
        }
    }

    /** Does this account carry the "os-sso disabled it" stamp? */
    public static function isDeprovisioned(\SimpleXMLElement $node): bool
    {
        return (string)($node->{self::DEPROVISIONED_FIELD} ?? '') === '1';
    }

    /**
     * Undo a deprovisioning, on an account os-sso owns and itself disabled.
     *
     * Called once the provider's required-groups gate has already passed, so the IdP has
     * just said this person is allowed again -- which is exactly the event deprovisioning
     * was waiting for and could not hear.
     *
     * Mutates the node only; the caller persists, because every caller is already in the
     * middle of a config.xml write it can fold this into. <expires> is deliberately left
     * alone: it is a date the operator set, not a refusal os-sso issued, and the usability
     * check the caller runs next still enforces it.
     *
     * @return bool whether anything changed
     */
    public static function reviveNode(\SimpleXMLElement $node, LocalAccountWriter $accounts): bool
    {
        if (!self::isDeprovisioned($node)) {
            return false;
        }
        // Stamped but enabled: somebody put it back by hand. Drop the stamp, so that if
        // they disable the account again later we do not read their decision as ours.
        if (empty((string)($node->disabled ?? ''))) {
            return $accounts->setField($node, self::DEPROVISIONED_FIELD, '');
        }
        if (!$accounts->isSsoManaged($node)) {
            return false; // not ours to enable, whatever the stamp says
        }
        $accounts->setDisabled($node, false);
        $accounts->setField($node, self::DEPROVISIONED_FIELD, '');
        syslog(LOG_NOTICE, sprintf(
            "os-sso: re-enabled local account '%s' (deprovisioned earlier, the IdP allows it again)",
            (string)$node->name
        ));
        return true;
    }

    /** The SSO-managed account carrying this subject stamp, or null. */
    private static function findManaged(string $subjectKey): ?\SimpleXMLElement
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return null;
        }
        foreach ($cnf->system->user as $user) {
            foreach ($user->sso_subject as $binding) {
                if (hash_equals(trim((string)$binding), $subjectKey)) {
                    return $user;
                }
            }
        }
        return null;
    }

}
