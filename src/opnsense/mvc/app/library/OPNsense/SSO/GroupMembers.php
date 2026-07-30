<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Reading and writing the member list of a config.xml group.
 *
 * One line of it is the whole reason this class exists. A group's members are a
 * comma-separated list of uids in one (or several) <member> elements, and the obvious
 * way to split it --
 *
 *     array_filter(explode(',', $members))
 *
 * -- quietly drops "0", because PHP counts the string "0" as falsy. uid 0 is root. So
 * every time os-sso added or removed anybody in a group, it rewrote that group's member
 * list without root: the firewall's own administrator silently lost `admins`, and the
 * anti-lockout rules could not see it either, since to them the group no longer had a
 * privileged member to protect.
 *
 * Everything that touches a member list goes through here, so there is one place where
 * "empty" means empty and nothing else.
 */
final class GroupMembers
{
    /**
     * The uids in a group, in order, without duplicates.
     *
     * @return string[]
     */
    public static function uids(\SimpleXMLElement $group): array
    {
        $out = [];
        foreach ($group->member as $member) {
            foreach (explode(',', (string)$member) as $uid) {
                $uid = trim($uid);
                // Only an empty entry is dropped -- "0" is root, not nothing.
                if ($uid !== '' && !in_array($uid, $out, true)) {
                    $out[] = $uid;
                }
            }
        }
        return $out;
    }

    /** Is $uid a member of $group? */
    public static function contains(\SimpleXMLElement $group, string $uid): bool
    {
        return $uid !== '' && in_array($uid, self::uids($group), true);
    }

    /**
     * Replace the member list.
     *
     * SimpleXML cannot rewrite a scalar child cleanly when there are several <member>
     * elements, so they collapse into one comma-separated node -- the format core
     * writes itself.
     *
     * @param string[] $uids
     */
    public static function set(\SimpleXMLElement $group, array $uids): void
    {
        unset($group->member);
        $uids = array_values(array_filter($uids, fn($uid) => (string)$uid !== ''));
        if ($uids !== []) {
            $group->addChild('member', implode(',', $uids));
        }
    }
}
