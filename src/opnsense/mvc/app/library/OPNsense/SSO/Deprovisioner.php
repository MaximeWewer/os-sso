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

    /** The SSO-managed account carrying this subject stamp, or null. */
    private static function findManaged(string $subjectKey): ?\SimpleXMLElement
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return null;
        }
        foreach ($cnf->system->user as $user) {
            $stamp = (string)($user->sso_subject ?? '');
            if ($stamp !== '' && hash_equals($stamp, $subjectKey)) {
                return $user;
            }
        }
        return null;
    }

}
