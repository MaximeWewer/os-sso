<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;

/**
 * What counts as privileged on this firewall.
 *
 * Both answers below gate several unrelated decisions -- which account an asserted
 * identity may bind to, which one deprovisioning may disable, which group a 1:1 name
 * match may grant, which group takes membership from a directory. They were duplicated
 * across four classes, which is the wrong shape for a security definition: adding a
 * privilege to one copy and not the others silently opens the paths that kept the old
 * list.
 */
final class Privilege
{
    /**
     * Privileges that amount to owning the firewall.
     *
     * Not an exhaustive list of dangerous pages -- it is the set from which everything
     * else can be granted. page-all is unrestricted access, user-shell-access is a shell,
     * and page-system-usermanager lets its holder put themselves in any group, including
     * the ones this list protects.
     */
    public const ESCALATION_PRIVS = [
        'page-all',
        'user-shell-access',
        'page-system-usermanager',
    ];

    /**
     * A group whose membership must stay an operator decision: `admins`, or one carrying
     * any escalation privilege.
     */
    public static function isPrivilegedGroup(\SimpleXMLElement $group): bool
    {
        return strtolower((string)$group->name) === 'admins' || self::hasEscalationPriv($group);
    }

    /**
     * Does this node's own <priv> list carry a privilege that amounts to owning the
     * firewall? Shared by groups and accounts: a <priv> element is the same
     * comma-separated list on both, and an escalation privilege means the same thing
     * whichever one holds it.
     */
    private static function hasEscalationPriv(\SimpleXMLElement $node): bool
    {
        foreach ($node->priv as $priv) {
            foreach (array_filter(array_map('trim', explode(',', (string)$priv))) as $p) {
                if (in_array($p, self::ESCALATION_PRIVS, true)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * A built-in/system account, root, an account carrying an escalation privilege of
     * its own, or a member of the admins group.
     *
     * The direct privileges matter as much as the group ones: OPNsense lets an operator
     * grant page-all (or a shell, or the user manager) on the account itself, and an
     * administrator configured that way is frequently also the one wearing the WebGUI's
     * "prevent local database logins" checkbox -- so without this the account reads as
     * unprivileged AND as having no usable local password, which is precisely the
     * combination IdentityMapper and the SCIM writes are allowed to take over.
     *
     * Group membership is read from config.xml rather than taken from the node, because
     * the node knows its uid and nothing else -- the group holds the list.
     */
    public static function isPrivilegedAccount(\SimpleXMLElement $node): bool
    {
        if ((string)($node->scope ?? '') === 'system' || (string)($node->uid ?? '') === '0') {
            return true;
        }
        if (self::hasEscalationPriv($node)) {
            return true;
        }
        $uid = (string)($node->uid ?? '');
        if ($uid === '') {
            return false;
        }
        foreach ((Config::getInstance()->object()->system->group ?? []) as $group) {
            if (strtolower((string)$group->name) !== 'admins') {
                continue;
            }
            if (GroupMembers::contains($group, $uid)) {
                return true;
            }
        }
        return false;
    }
}
