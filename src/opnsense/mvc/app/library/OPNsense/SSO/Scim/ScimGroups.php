<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

use OPNsense\Core\Config;
use OPNsense\SSO\ConfigLock;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\Privilege;

/**
 * The /Groups half: membership, and only membership.
 *
 * Two deliberate refusals, both about who decides privileges on a firewall:
 *
 *   - groups are never created or deleted over SCIM. An OPNsense group carries ACL
 *     privileges; letting a directory mint one moves that decision off the firewall.
 *     The client sees the groups that exist and may fill them.
 *   - a PRIVILEGED group (admins, or any group holding full-GUI / shell /
 *     user-manager privileges) never takes a membership change from SCIM. Granting
 *     administration of the firewall stays an operator action -- either by hand, or
 *     through the provider's explicit group map, which is operator-written config
 *     rather than a directory assertion.
 */
final class ScimGroups
{
    private LocalAccountWriter $accounts;
    private string $base;

    public function __construct(string $base, ?LocalAccountWriter $accounts = null)
    {
        $this->base = $base;
        $this->accounts = $accounts ?? new LocalAccountWriter();
    }

    public function get(string $id): array
    {
        return $this->toResource($this->requireGroup($id));
    }

    public function search(string $filter, int $startIndex, int $count): array
    {
        $matches = [];
        foreach ($this->groups() as $group) {
            if ($filter === '' || $this->matches($group, $filter)) {
                $matches[] = $group;
            }
        }
        $total = count($matches);
        // count=0 asks for the total only -- see the same case in ScimUsers::search().
        $page = $count <= 0
            ? []
            : array_slice($matches, max(0, $startIndex - 1), min($count, ScimUsers::MAX_RESULTS));
        return ScimSchema::listResponse(array_map([$this, 'toResource'], $page), $total, $startIndex);
    }

    /**
     * PATCH on "members": add, remove, or replace the whole set.
     *
     * Members are the SCIM user ids, which are our uids -- so a member the firewall
     * does not know is simply skipped rather than failing the operation: a directory
     * group routinely holds people who were never provisioned here.
     */
    public function patch(string $id, array $operations): array
    {
        return ConfigLock::with(function () use ($id, $operations) {
            $group = $this->requireGroup($id);
            $this->assertMayTouch($group);
            $changed = false;

            foreach ($operations as $operation) {
                $op = strtolower((string)($operation['op'] ?? ''));
                $path = strtolower(trim((string)($operation['path'] ?? '')));
                $value = $operation['value'] ?? null;

                // "members[value eq \"42\"]" with op remove: the uid is in the path.
                if ($op === 'remove' && preg_match('/^members\[\s*value\s+eq\s+"([^"]*)"\s*\]$/i', $path, $m)) {
                    $changed = $this->removeMember($group, $m[1]) || $changed;
                    continue;
                }
                if ($path !== '' && $path !== 'members') {
                    continue; // nothing else about a group is ours to change
                }
                $uids = $this->uidsFrom($value);
                switch ($op) {
                    case 'add':
                        foreach ($uids as $uid) {
                            $changed = $this->addMember($group, $uid) || $changed;
                        }
                        break;
                    case 'remove':
                        foreach ($uids as $uid) {
                            $changed = $this->removeMember($group, $uid) || $changed;
                        }
                        break;
                    case 'replace':
                        $changed = $this->replaceMembers($group, $uids) || $changed;
                        break;
                }
            }

            if ($changed) {
                $this->persist((string)$group->name);
            }
            return $this->toResource($group);
        });
    }

    /* ---- mapping ----------------------------------------------------- */

    public function toResource(\SimpleXMLElement $group): array
    {
        $members = [];
        foreach ($this->membersOf($group) as $uid) {
            $user = $this->accounts->findByUid($uid);
            // Only accounts os-sso manages are reported: the directory has no business
            // learning the firewall's own local accounts from a group listing.
            if ($user !== null && $this->accounts->isSsoManaged($user)) {
                $members[] = ['value' => $uid, 'display' => (string)$user->name];
            }
        }
        $id = (string)($group->gid ?? '');
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'id' => $id,
            'displayName' => (string)$group->name,
            'members' => $members,
            'meta' => [
                'resourceType' => 'Group',
                'location' => $this->base . '/Groups/' . rawurlencode($id),
            ],
        ];
    }

    /* ---- helpers ----------------------------------------------------- */

    /** @return \SimpleXMLElement[] */
    private function groups(): array
    {
        $out = [];
        foreach ((Config::getInstance()->object()->system->group ?? []) as $group) {
            $out[] = $group;
        }
        return $out;
    }

    private function requireGroup(string $id): \SimpleXMLElement
    {
        foreach ($this->groups() as $group) {
            if ((string)($group->gid ?? '') === $id) {
                return $group;
            }
        }
        throw ScimError::notFound('group');
    }

    private function assertMayTouch(\SimpleXMLElement $group): void
    {
        if (Privilege::isPrivilegedGroup($group)) {
            throw new ScimError(403, sprintf(
                "'%s' grants administrative privileges; its membership is not managed over SCIM",
                (string)$group->name
            ));
        }
    }


    /** @return string[] */
    private function membersOf(\SimpleXMLElement $group): array
    {
        $members = [];
        foreach ($group->member as $member) {
            $members = array_merge($members, array_filter(explode(',', (string)$member)));
        }
        return array_values(array_unique($members));
    }

    private function setMembers(\SimpleXMLElement $group, array $members): void
    {
        // SimpleXML cannot rewrite a scalar child cleanly with multiple <member>;
        // collapse to a single comma-separated node, matching the core format.
        unset($group->member);
        if (!empty($members)) {
            $group->addChild('member', implode(',', $members));
        }
    }

    /**
     * A uid a directory may add to, or remove from, a group: one os-sso owns.
     *
     * Not merely "an account that exists". A group that gets past assertMayTouch() can
     * still carry real privileges -- firewall rules, the diagnostics pages -- and
     * without this a directory could hand those to any pre-existing local account it
     * never provisioned. The reverse matters just as much: it must not strip the
     * operator's hand-assigned member out of a group it happens to sync. Membership
     * os-sso did not grant is not membership it manages.
     */
    private function isManageable(string $uid): bool
    {
        if ($uid === '') {
            return false;
        }
        $user = $this->accounts->findByUid($uid);
        return $user !== null && $this->accounts->isSsoManaged($user);
    }

    private function addMember(\SimpleXMLElement $group, string $uid): bool
    {
        if (!$this->isManageable($uid)) {
            return false; // not ours to grant
        }
        $members = $this->membersOf($group);
        if (in_array($uid, $members, true)) {
            return false;
        }
        $members[] = $uid;
        $this->setMembers($group, $members);
        syslog(LOG_NOTICE, sprintf('os-sso scim: added uid %s to group %s', $uid, (string)$group->name));
        return true;
    }

    private function removeMember(\SimpleXMLElement $group, string $uid): bool
    {
        if (!$this->isManageable($uid)) {
            return false; // not ours to revoke
        }
        $members = $this->membersOf($group);
        if (!in_array($uid, $members, true)) {
            return false;
        }
        $this->setMembers($group, array_values(array_diff($members, [$uid])));
        syslog(LOG_NOTICE, sprintf('os-sso scim: removed uid %s from group %s', $uid, (string)$group->name));
        return true;
    }

    /**
     * Replace the membership, but only the part os-sso owns: members that are not
     * SSO-managed accounts stay, because a directory replacing "the members" means
     * its own members, not the operator's hand-assigned ones.
     */
    private function replaceMembers(\SimpleXMLElement $group, array $uids): bool
    {
        $kept = [];
        foreach ($this->membersOf($group) as $uid) {
            if (!$this->isManageable($uid)) {
                $kept[] = $uid;
            }
        }
        foreach ($uids as $uid) {
            if ($this->isManageable($uid) && !in_array($uid, $kept, true)) {
                $kept[] = $uid;
            }
        }
        if ($kept === $this->membersOf($group)) {
            return false;
        }
        $this->setMembers($group, $kept);
        return true;
    }

    /** @return string[] uids out of a SCIM members value (list, single, or scalar) */
    private function uidsFrom($value): array
    {
        if (is_string($value)) {
            return [$value];
        }
        if (!is_array($value)) {
            return [];
        }
        if (isset($value['value'])) {
            return [(string)$value['value']];
        }
        $out = [];
        foreach ($value as $entry) {
            if (is_array($entry) && isset($entry['value'])) {
                $out[] = (string)$entry['value'];
            } elseif (is_string($entry)) {
                $out[] = $entry;
            }
        }
        return $out;
    }

    private function matches(\SimpleXMLElement $group, string $filter): bool
    {
        if (!preg_match('/^\s*(\w+)\s+eq\s+"([^"]*)"\s*$/i', $filter, $m)) {
            throw ScimError::badRequest('unsupported filter: ' . $filter, 'invalidFilter');
        }
        [, $attribute, $value] = $m;
        switch (strtolower($attribute)) {
            case 'displayname':
                return strcasecmp((string)$group->name, $value) === 0;
            case 'id':
                return (string)($group->gid ?? '') === $value;
            default:
                throw ScimError::badRequest('filtering on ' . $attribute . ' is not supported', 'invalidFilter');
        }
    }

    private function persist(string $groupName): void
    {
        Config::getInstance()->save();
        (new \OPNsense\Core\Backend())->configdpRun('auth group changed', [$groupName]);
    }
}
