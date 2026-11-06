<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO\Scim;

use OPNsense\Core\Config;
use OPNsense\SSO\ConfigLock;
use OPNsense\SSO\GroupMembers;
use OPNsense\SSO\LocalAccountWriter;
use OPNsense\SSO\Privilege;

/**
 * The /Groups half: membership, and only membership.
 *
 * Two deliberate refusals, both about who decides privileges on a firewall:
 *
 *   - by default, groups are never created or deleted over SCIM. An OPNsense group
 *     carries ACL privileges; letting a directory mint one moves that decision off the
 *     firewall. The client sees the groups that exist and may fill them.
 *     A provider may be allowed to create groups (Entra's group provisioning, Okta's
 *     Push Groups), and then only on these terms: a group it creates starts with no
 *     privilege at all, so what it may do stays the operator's call; the directory may
 *     rename, replace or delete only the groups it created itself, and only while they
 *     still carry no privilege -- one the operator has granted something is no longer
 *     the directory's to manage.
 *   - a PRIVILEGED group (admins, or any group holding full-GUI / shell /
 *     user-manager privileges) never takes a membership change from SCIM. Granting
 *     administration of the firewall stays an operator action -- either by hand, or
 *     through the provider's explicit group map, which is operator-written config
 *     rather than a directory assertion.
 */
final class ScimGroups
{
    /** What core's group model accepts as a name. */
    private const NAME = '/^[a-zA-Z0-9.\-_]{1,32}$/';

    private LocalAccountWriter $accounts;
    private string $provider;
    private string $base;
    private bool $mayCreate;

    public function __construct(
        string $provider,
        string $base,
        ?LocalAccountWriter $accounts = null,
        bool $mayCreate = false
    ) {
        $this->provider = $provider;
        $this->base = $base;
        $this->accounts = $accounts ?? new LocalAccountWriter();
        $this->mayCreate = $mayCreate;
    }

    /**
     * POST: a new group, with no privilege, owned by this provider.
     *
     * Directory names are free text ("VPN Users"); core's are not. The firewall group
     * gets a name core accepts -- anything else becomes "_", cut to 32 characters --
     * and the directory's name is kept next to it, so the client finds the group again
     * under the name it knows. Taken either way is a 409: the client then looks it up.
     */
    public function create(array $body): array
    {
        $this->assertMayManage();
        return ConfigLock::with(function () use ($body) {
            $display = trim((string)($body['displayName'] ?? ''));
            if ($display === '') {
                throw ScimError::badRequest('displayName is required');
            }
            $name = self::firewallName($display);
            foreach ($this->groups() as $group) {
                if (strcasecmp((string)$group->name, $name) === 0 || $this->displayName($group) === $display) {
                    throw ScimError::conflict(sprintf("a group named '%s' already exists", $name));
                }
            }
            $cnf = Config::getInstance()->object();
            $group = $cnf->system->addChild('group');
            LocalAccountWriter::ensureUuid($group);
            $group->addChild('name', $name);
            $group->addChild('description', htmlspecialchars(
                LocalAccountWriter::xmlText(sprintf('Created over SCIM by %s: %s', $this->provider, $display)),
                ENT_XML1
            ));
            $group->addChild('scope', 'user');
            $group->addChild('gid', (string)$this->nextGid($cnf));
            $this->own($group, $display);
            $this->replaceMembers($group, $this->uidsFrom($body['members'] ?? []));
            syslog(LOG_NOTICE, sprintf('os-sso scim: %s created group %s', $this->provider, $name));
            $this->persist($name);
            return $this->toResource($group);
        });
    }

    /** PUT: the whole group -- its members, and its name when it is one this provider created. */
    public function replace(string $id, array $body): array
    {
        $this->assertMayManage();
        return ConfigLock::with(function () use ($id, $body) {
            $group = $this->requireGroup($id);
            $this->assertMayTouch($group);
            $changed = $this->rename($group, trim((string)($body['displayName'] ?? '')));
            $changed = $this->replaceMembers($group, $this->uidsFrom($body['members'] ?? [])) || $changed;
            if ($changed) {
                $this->persist((string)$group->name);
            }
            return $this->toResource($group);
        });
    }

    /** DELETE: only a group this provider created, and only while it carries no privilege. */
    public function delete(string $id): void
    {
        $this->assertMayManage();
        ConfigLock::with(function () use ($id) {
            $group = $this->requireGroup($id);
            $this->assertMayTouch($group);
            if (!$this->owns($group)) {
                throw new ScimError(403, sprintf(
                    "'%s' was not created over SCIM by this provider; it is not deleted from here",
                    (string)$group->name
                ));
            }
            $name = (string)$group->name;
            $this->disown($group);
            $dom = dom_import_simplexml($group);
            $dom->parentNode->removeChild($dom);
            syslog(LOG_NOTICE, sprintf('os-sso scim: %s deleted group %s', $this->provider, $name));
            $this->persist($name);
        });
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
                if ($path === 'displayname' && $op === 'replace') {
                    $changed = $this->rename($group, trim((string)(is_array($value) ? '' : $value))) || $changed;
                    continue;
                }
                if ($path === '' && is_array($value) && !array_is_list($value)) {
                    // No path: the value is a partial group, {"displayName": ..., "members": [...]}.
                    if (isset($value['displayName']) && $op === 'replace') {
                        $changed = $this->rename($group, trim((string)$value['displayName'])) || $changed;
                    }
                    if (!array_key_exists('members', $value)) {
                        continue;
                    }
                    $value = $value['members'];
                } elseif ($path !== '' && $path !== 'members') {
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
            if ($user !== null && $this->isManageable($uid)) {
                $members[] = ['value' => $uid, 'display' => (string)$user->name];
            }
        }
        $id = (string)($group->gid ?? '');
        return [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'id' => $id,
            'displayName' => $this->displayName($group),
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
        if (!Privilege::acceptsImplicitDirectoryMembership($group)) {
            throw new ScimError(403, sprintf(
                "'%s' carries firewall ACL privileges; its membership is not managed over SCIM",
                (string)$group->name
            ));
        }
    }


    /** @return string[] */
    private function membersOf(\SimpleXMLElement $group): array
    {
        return GroupMembers::uids($group);
    }

    private function setMembers(\SimpleXMLElement $group, array $members): void
    {
        GroupMembers::set($group, $members);
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
        return $user !== null
            && $this->accounts->isSsoManaged($user)
            && $this->accounts->isClaimedBy($user, $this->provider);
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
        $predicate = ScimFilter::compile($filter, function (string $attribute) use ($group) {
            switch ($attribute) {
                case 'displayname':
                    return $this->displayName($group);
                case 'id':
                    return (string)($group->gid ?? '');
                default:
                    return null;
            }
        });
        return $predicate();
    }

    private function assertMayManage(): void
    {
        if (!$this->mayCreate) {
            throw new ScimError(
                403,
                'groups are not created, replaced or deleted over SCIM by this provider; only their membership is'
            );
        }
    }

    /**
     * Rename a group this provider created; a name it already has is no change. Any other
     * group keeps the name the operator gave it -- a directory renaming its own group is
     * no reason to rename one it merely fills.
     */
    private function rename(\SimpleXMLElement $group, string $display): bool
    {
        if ($display === '' || $display === $this->displayName($group)) {
            return false;
        }
        if (!$this->mayCreate || !$this->owns($group)) {
            throw new ScimError(403, sprintf(
                "'%s' was not created over SCIM by this provider; it keeps its name",
                (string)$group->name
            ));
        }
        $name = self::firewallName($display);
        foreach ($this->groups() as $other) {
            if ((string)$other->gid !== (string)$group->gid && strcasecmp((string)$other->name, $name) === 0) {
                throw ScimError::conflict(sprintf("a group named '%s' already exists", $name));
            }
        }
        $group->name = $name;
        $this->own($group, $display);
        return true;
    }

    /** A name core's group model accepts. */
    private static function firewallName(string $display): string
    {
        $name = substr((string)preg_replace('/[^a-zA-Z0-9.\-_]/', '_', $display), 0, 32);
        if (preg_match(self::NAME, $name) !== 1) {
            throw ScimError::badRequest('displayName gives no usable group name');
        }
        return $name;
    }

    /** First free gid from 2000, as core's GidField picks it, and past a legacy nextgid. */
    private function nextGid(\SimpleXMLElement $cnf): int
    {
        $used = [];
        foreach ($this->groups() as $group) {
            $used[(int)$group->gid] = true;
        }
        $gid = 2000;
        while (isset($used[$gid])) {
            $gid++;
        }
        if (isset($cnf->system->nextgid) && (int)$cnf->system->nextgid <= $gid) {
            $cnf->system->nextgid = (string)($gid + 1);
        }
        return $gid;
    }

    /**
     * Groups created over SCIM, under //OPNsense/SSO/scimgroups/group, keyed by the
     * group's uuid (never reused, unlike a gid, which core hands out again once freed):
     * which provider created it, and the name it has in the directory.
     */
    private function record(\SimpleXMLElement $group, bool $create): ?\SimpleXMLElement
    {
        $uuid = (string)($group->attributes()['uuid'] ?? '');
        if ($uuid === '') {
            return null;
        }
        $cfg = Config::getInstance()->object();
        if (isset($cfg->OPNsense->SSO->scimgroups)) {
            foreach ($cfg->OPNsense->SSO->scimgroups->group as $record) {
                if ((string)$record['uuid'] === $uuid) {
                    return $record;
                }
            }
        }
        if (!$create) {
            return null;
        }
        $opnsense = isset($cfg->OPNsense) ? $cfg->OPNsense : $cfg->addChild('OPNsense');
        $sso = isset($opnsense->SSO) ? $opnsense->SSO : $opnsense->addChild('SSO');
        $records = isset($sso->scimgroups) ? $sso->scimgroups : $sso->addChild('scimgroups');
        $record = $records->addChild('group');
        $record->addAttribute('uuid', $uuid);
        return $record;
    }

    private function owns(\SimpleXMLElement $group): bool
    {
        $record = $this->record($group, false);
        return $record !== null && (string)$record['provider'] === $this->provider;
    }

    private function own(\SimpleXMLElement $group, string $display): void
    {
        $record = $this->record($group, true);
        $record['provider'] = $this->provider;
        $record['display'] = LocalAccountWriter::xmlText($display);
    }

    private function disown(\SimpleXMLElement $group): void
    {
        $record = $this->record($group, false);
        if ($record !== null) {
            $dom = dom_import_simplexml($record);
            $dom->parentNode->removeChild($dom);
        }
    }

    /** The name the directory knows the group by: its own for a group it created. */
    private function displayName(\SimpleXMLElement $group): string
    {
        $record = $this->record($group, false);
        $display = $record !== null ? (string)$record['display'] : '';
        return $display !== '' ? $display : (string)$group->name;
    }

    private function persist(string $groupName): void
    {
        Config::getInstance()->save();
        (new \OPNsense\Core\Backend())->configdpRun('auth sync group', [$groupName]);
    }
}
