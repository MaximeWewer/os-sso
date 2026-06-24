<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Resolves IdP-asserted groups/roles into OPNsense group membership and writes
 * it into config.xml. Privileges themselves are NEVER touched here -- the ACL
 * derives them from group membership at request time.
 *
 * Mapping strategy (additive, conservative):
 *   - defaultGroups are always granted.
 *   - each asserted IdP group is run through an explicit name->name map if the
 *     provider supplied one, otherwise matched 1:1 by (case-insensitive) name.
 *   - only OPNsense groups that actually exist are touched; unknown names are
 *     ignored (a typo in the IdP must never silently grant nothing-or-everything).
 *
 * Membership is additive on purpose for now: we add the user to resolved groups
 * but do not strip memberships we did not assert. Strict reconciliation
 * (deprovisioning on login) is a Phase 5 hardening item -- done wrong it can lock
 * the only admin out of the box.
 */
final class GroupMapper
{
    /** @var array<string,string> lower(idpGroup) => opnsenseGroupName */
    private array $explicitMap;

    /**
     * @param array<string,string> $explicitMap optional idp->opnsense name map
     */
    public function __construct(array $explicitMap = [])
    {
        $this->explicitMap = array_change_key_case($explicitMap, CASE_LOWER);
    }

    /**
     * Ensure $userNode is a member of every resolved OPNsense group.
     *
     * @param \SimpleXMLElement $userNode config.xml system/user node (has <uid>)
     * @param NormalizedIdentity $identity asserted identity (groups[])
     * @param string[] $defaultGroups group names always granted
     * @return bool whether any membership changed (caller must persist if true)
     */
    public function sync(\SimpleXMLElement $userNode, NormalizedIdentity $identity, array $defaultGroups): bool
    {
        $uid = (string)$userNode->uid;
        if ($uid === '') {
            return false;
        }

        $targets = $this->resolveTargetGroups($identity, $defaultGroups);
        if (empty($targets)) {
            return false;
        }

        $cnf = $userNode->xpath('/opnsense/system')[0] ?? null;
        if ($cnf === null) {
            return false;
        }

        $changed = false;
        foreach ($cnf->group as $group) {
            $groupName = strtolower((string)$group->name);
            if (!isset($targets[$groupName])) {
                continue;
            }
            // Refuse to auto-escalate into a privileged group via an unmapped IdP
            // group name matched 1:1 -- the IdP group name is attacker-influenced
            // (often self-service). defaultGroups and explicit operator maps are
            // trusted and may target privileged groups on purpose.
            if ($targets[$groupName] === 'idp' && $this->isPrivilegedGroup($group)) {
                syslog(LOG_WARNING, sprintf(
                    "os-sso: ignoring unmapped IdP group '%s' -> privileged OPNsense group '%s' " .
                    "(configure an explicit mapping or default group to allow)",
                    $groupName,
                    (string)$group->name
                ));
                continue;
            }
            $changed = $this->addMember($group, $uid) || $changed;
        }
        return $changed;
    }

    /**
     * @return array<string,string> lower-cased OPNsense group name => provenance
     *         ('default'|'explicit'|'idp'); only 'idp' (unmapped 1:1) is gated
     *         against privileged groups at grant time.
     */
    private function resolveTargetGroups(NormalizedIdentity $identity, array $defaultGroups): array
    {
        $targets = [];
        foreach ($defaultGroups as $g) {
            $g = strtolower(trim($g));
            if ($g !== '') {
                $targets[$g] = 'default';
            }
        }
        foreach ($identity->groups as $idpGroup) {
            $key = strtolower(trim((string)$idpGroup));
            if ($key === '') {
                continue;
            }
            if (isset($this->explicitMap[$key])) {
                // Operator-defined mapping is trusted, even into privileged groups.
                $targets[strtolower($this->explicitMap[$key])] = 'explicit';
                continue;
            }
            // 1:1 fallback by name -- gated against privileged groups in sync().
            // Never downgrade a trusted (default/explicit) target to 'idp'.
            if (!isset($targets[$key])) {
                $targets[$key] = 'idp';
            }
        }
        return $targets;
    }

    /**
     * A group is privileged if it grants full GUI access, shell access, or the
     * ability to edit users/groups (self-escalation) -- or is the built-in admins
     * group. Checked against the group's actual ACL privileges, not just its name,
     * so a custom admin-equivalent group is covered too.
     */
    private function isPrivilegedGroup(\SimpleXMLElement $group): bool
    {
        if (strtolower((string)$group->name) === 'admins') {
            return true;
        }
        foreach ($group->priv as $priv) {
            foreach (array_filter(array_map('trim', explode(',', (string)$priv))) as $p) {
                if (in_array($p, self::ESCALATION_PRIVS, true)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** ACL privileges that make a group admin-equivalent for 1:1-fallback gating. */
    private const ESCALATION_PRIVS = [
        'page-all',                 // unrestricted WebGUI access
        'user-shell-access',        // shell login
        'page-system-usermanager',  // edit users/groups -> grant self anything
    ];

    private function addMember(\SimpleXMLElement $group, string $uid): bool
    {
        $members = [];
        foreach ($group->member as $member) {
            $members = array_merge($members, array_filter(explode(',', (string)$member)));
        }
        if (in_array($uid, $members, true)) {
            return false; // already a member
        }
        $members[] = $uid;
        // SimpleXML cannot rewrite a scalar child cleanly with multiple <member>;
        // collapse to a single comma-separated <member> node, matching core format.
        unset($group->member);
        $group->addChild('member', implode(',', $members));

        syslog(LOG_NOTICE, sprintf(
            "os-sso: linked uid %s to group %s",
            $uid,
            (string)$group->name
        ));
        return true;
    }
}
