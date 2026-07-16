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
 * Membership is additive by default: we add the user to resolved groups but do
 * not strip memberships we did not assert. Optional strict reconciliation
 * (deprovision-on-login) removes memberships the IdP no longer asserts -- but only
 * ones os-sso itself granted (tracked in a per-user provenance stamp), never a
 * hand-assigned local group, and never the last member of a privileged group.
 */
final class GroupMapper
{
    /** @var array<string,string> lower(idpGroup) => opnsenseGroupName */
    private array $explicitMap;

    /** when true, strip previously-granted memberships the IdP no longer asserts */
    private bool $reconcile;

    /** config.xml child on the user node recording the groups os-sso last granted */
    private const PROVENANCE_FIELD = 'sso_groups';

    /**
     * @param array<string,string> $explicitMap optional idp->opnsense name map
     * @param bool $reconcile opt-in strict group sync (deprovision on login)
     */
    public function __construct(array $explicitMap = [], bool $reconcile = false)
    {
        $this->explicitMap = array_change_key_case($explicitMap, CASE_LOWER);
        $this->reconcile = $reconcile;
    }

    /**
     * Parse an operator group-map text field into an idp => opnsense name map.
     * Accepts "idpGroup:opnsenseGroup" (or "=") pairs, comma- or newline-
     * separated; blank or malformed entries are ignored.
     *
     * @return array<string,string>
     */
    public static function parseMap(string $spec): array
    {
        $map = [];
        foreach (preg_split('/[,\r\n]+/', $spec) as $pair) {
            $parts = preg_split('/\s*[:=]\s*/', trim($pair), 2);
            if (count($parts) !== 2) {
                continue;
            }
            $idp = trim($parts[0]);
            $opn = trim($parts[1]);
            if ($idp !== '' && $opn !== '') {
                $map[$idp] = $opn;
            }
        }
        return $map;
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
        // Additive mode with nothing to grant is a no-op; reconcile mode still has to
        // run (to strip memberships the IdP no longer asserts).
        if (empty($targets) && !$this->reconcile) {
            return false;
        }

        $system = $userNode->xpath('/opnsense/system')[0] ?? null;
        if ($system === null) {
            return false;
        }

        $changed = false;
        $granted = []; // lower-cased group names os-sso holds this user in after this login

        foreach ($system->group as $group) {
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
            $granted[$groupName] = true;
        }

        if ($this->reconcile) {
            $changed = $this->reconcileMemberships($system, $userNode, $uid, $granted) || $changed;
        }

        return $changed;
    }

    /**
     * Strip memberships os-sso previously granted but this login no longer asserts.
     * Only groups recorded in the per-user provenance stamp are touched -- a group
     * the operator assigned by hand is never in it, so it is never removed. The last
     * enabled member of a privileged group is kept as a lockout backstop. Rewrites
     * the provenance stamp to the currently-granted set.
     *
     * @param array<string,bool> $granted lower-cased names granted this login
     */
    private function reconcileMemberships(
        \SimpleXMLElement $system,
        \SimpleXMLElement $userNode,
        string $uid,
        array $granted
    ): bool {
        $previous = $this->readProvenance($userNode);
        $changed = false;
        foreach ($system->group as $group) {
            $groupName = strtolower((string)$group->name);
            // Only revoke what os-sso itself previously granted and no longer asserts.
            if (!isset($previous[$groupName]) || isset($granted[$groupName])) {
                continue;
            }
            if ($this->isPrivilegedGroup($group) && $this->isLastEnabledMember($group, $uid)) {
                syslog(LOG_WARNING, sprintf(
                    "os-sso: keeping uid %s in privileged group '%s' (would remove its last member)",
                    $uid,
                    (string)$group->name
                ));
                continue;
            }
            $changed = $this->removeMember($group, $uid) || $changed;
        }
        return $this->writeProvenance($userNode, array_keys($granted)) || $changed;
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

    /** Remove $uid from a group's comma-separated <member> list, collapsing to one
     *  node (core format); drops the node entirely when no member remains. */
    private function removeMember(\SimpleXMLElement $group, string $uid): bool
    {
        $members = [];
        foreach ($group->member as $member) {
            $members = array_merge($members, array_filter(explode(',', (string)$member)));
        }
        if (!in_array($uid, $members, true)) {
            return false; // not a member
        }
        $members = array_values(array_diff($members, [$uid]));
        unset($group->member);
        if (!empty($members)) {
            $group->addChild('member', implode(',', $members));
        }
        syslog(LOG_NOTICE, sprintf(
            "os-sso: removed uid %s from group %s (reconcile)",
            $uid,
            (string)$group->name
        ));
        return true;
    }

    /**
     * True if $uid is the only ENABLED member of $group -- i.e. removing it would
     * leave the group with no enabled member. Used as a lockout backstop before
     * revoking a privileged group.
     */
    private function isLastEnabledMember(\SimpleXMLElement $group, string $uid): bool
    {
        $others = [];
        foreach ($group->member as $member) {
            foreach (array_filter(explode(',', (string)$member)) as $m) {
                if ($m !== $uid) {
                    $others[$m] = true;
                }
            }
        }
        if (empty($others)) {
            return true; // uid is the sole member
        }
        $system = $group->xpath('/opnsense/system')[0] ?? null;
        if ($system === null) {
            return false;
        }
        foreach ($system->user as $u) {
            if (isset($others[(string)$u->uid]) && empty((string)$u->disabled)) {
                return false; // another enabled member remains
            }
        }
        return true;
    }

    /**
     * Groups os-sso last granted this user (lower-cased set), from the provenance
     * stamp on the user node. Empty when the stamp is absent (e.g. first reconcile
     * login, or a user only ever touched in additive mode -- conservatively, nothing
     * pre-existing is stripped until os-sso has recorded a grant).
     *
     * @return array<string,bool>
     */
    private function readProvenance(\SimpleXMLElement $userNode): array
    {
        $raw = (string)($userNode->{self::PROVENANCE_FIELD} ?? '');
        $out = [];
        foreach (array_filter(array_map('trim', explode(',', $raw))) as $name) {
            $out[strtolower($name)] = true;
        }
        return $out;
    }

    /** Persist the currently-granted set as the provenance stamp; returns whether it
     *  changed (so the caller knows to save config.xml). */
    private function writeProvenance(\SimpleXMLElement $userNode, array $grantedNames): bool
    {
        $names = array_values(array_unique(array_map('strtolower', $grantedNames)));
        sort($names);
        $new = implode(',', $names);
        if ((string)($userNode->{self::PROVENANCE_FIELD} ?? '') === $new) {
            return false;
        }
        unset($userNode->{self::PROVENANCE_FIELD});
        $userNode->addChild(self::PROVENANCE_FIELD, htmlspecialchars($new, ENT_XML1));
        return true;
    }
}
