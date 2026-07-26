<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * The provider-level authorization gate: WHO, of everyone the IdP is willing to
 * authenticate, may use this firewall at all.
 *
 * Authentication is not authorization. Without this, any account in the IdP that
 * completes the ceremony gets in as soon as a local account matches (or, with
 * auto-creation on, gets one made for it) -- the whole directory, not the operators.
 * Group *mapping* is a privilege question and runs later; this runs first and is a
 * yes/no on the door.
 *
 * Empty required-groups means "no restriction" -- the pre-existing behaviour, kept so
 * an upgrade does not lock anyone out. Every provider type exposes the field.
 */
final class AccessPolicy
{
    /**
     * @param string[] $requiredGroups IdP group names, any one of which grants access
     * @param NormalizedIdentity $identity the verified identity
     * @param bool $deprovision also deactivate the local account behind a refusal --
     *             the only moment a login-driven plugin learns of a revocation
     * @throws \RuntimeException when the identity holds none of the required groups
     */
    public static function assert(
        array $requiredGroups,
        NormalizedIdentity $identity,
        bool $deprovision = false
    ): void {
        $required = [];
        foreach ($requiredGroups as $group) {
            $group = strtolower(trim((string)$group));
            if ($group !== '') {
                $required[$group] = true;
            }
        }
        if (empty($required)) {
            return; // no restriction configured
        }

        foreach ($identity->groups as $asserted) {
            if (isset($required[strtolower(trim((string)$asserted))])) {
                return;
            }
        }

        if ($deprovision) {
            Deprovisioner::disableFor($identity);
        }

        // The identity is authentic; it is simply not allowed here. Name the subject
        // (not the groups) so the log is useful without echoing the IdP's directory.
        throw new \RuntimeException(sprintf(
            "SSO: '%s' is in none of the groups required by this provider",
            preg_replace('/[^\x20-\x7e]/', '', $identity->username ?: $identity->subject)
        ));
    }
}
