<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Stand-ins for the OPNsense core services the SSO library calls, plus a builder for
 * the slice of config.xml it reads and writes. Only what the tested code actually
 * touches: an in-memory SimpleXML tree, a save counter, and a record of the configd
 * actions that would have run.
 */

namespace OPNsense\Core;

class Config
{
    private static ?Config $instance = null;
    private \SimpleXMLElement $root;

    /** How many times the code under test persisted config.xml. */
    public static int $saves = 0;
    /** How many times it asked for a reload. */
    public static int $reloads = 0;

    private function __construct(\SimpleXMLElement $root)
    {
        $this->root = $root;
    }

    public static function getInstance(): Config
    {
        if (self::$instance === null) {
            self::$instance = new self(new \SimpleXMLElement('<opnsense><system/></opnsense>'));
        }
        return self::$instance;
    }

    /** Test seam: install a fresh tree and reset the counters. */
    public static function useTree(\SimpleXMLElement $root): void
    {
        self::$instance = new self($root);
        self::$saves = 0;
        self::$reloads = 0;
        Backend::$calls = [];
    }

    public function object(): \SimpleXMLElement
    {
        return $this->root;
    }

    public function save()
    {
        self::$saves++;
        return true;
    }

    public function forceReload()
    {
        self::$reloads++;
    }
}

class Backend
{
    /** @var array<int,array{0:string,1:array}> every configd call the code made */
    public static array $calls = [];

    public function configdpRun($action, $params = [], $detach = false)
    {
        self::$calls[] = [(string)$action, (array)$params];
        // vpn_verdict is the only action whose output the caller inspects.
        return str_contains((string)$action, 'vpn_verdict') ? 'ok' : 'OK';
    }

    public function configdRun($command, $detach = false)
    {
        self::$calls[] = [(string)$command, []];
        return 'OK';
    }
}

namespace OPNsense\SSO\Test;

/**
 * Builds the config.xml slice the account and group code works on.
 *
 * Groups and users have to live in one document rooted at <opnsense>, because
 * GroupMapper reaches the group list from a user node with xpath('/opnsense/system').
 */
final class Tree
{
    /**
     * @param array<int,array<string,string>> $users  child name => value per user
     * @param array<int,array<string,mixed>>  $groups name, gid, priv (string), member (csv)
     */
    public static function build(array $users = [], array $groups = []): \SimpleXMLElement
    {
        $root = new \SimpleXMLElement('<opnsense><system><nextuid>2000</nextuid></system></opnsense>');
        foreach ($groups as $group) {
            $node = $root->system->addChild('group');
            $node->addChild('name', (string)($group['name'] ?? 'group'));
            $node->addChild('gid', (string)($group['gid'] ?? '2000'));
            foreach ((array)($group['priv'] ?? []) as $priv) {
                $node->addChild('priv', (string)$priv);
            }
            if (isset($group['member'])) {
                $node->addChild('member', (string)$group['member']);
            }
        }
        foreach ($users as $user) {
            $node = $root->system->addChild('user');
            foreach ($user as $key => $value) {
                // An array value becomes repeated children, the shape config.xml uses
                // for a user's own <priv> entries and for os-sso's <sso_subject>.
                foreach (is_array($value) ? $value : [$value] as $entry) {
                    $node->addChild((string)$key, htmlspecialchars((string)$entry, ENT_XML1));
                }
            }
        }
        \OPNsense\Core\Config::useTree($root);
        return $root;
    }

    /** The <user> node named $name, or null. */
    public static function user(\SimpleXMLElement $root, string $name): ?\SimpleXMLElement
    {
        foreach ($root->system->user as $user) {
            if ((string)$user->name === $name) {
                return $user;
            }
        }
        return null;
    }

    /** The <group> node named $name, or null. */
    public static function group(\SimpleXMLElement $root, string $name): ?\SimpleXMLElement
    {
        foreach ($root->system->group as $group) {
            if ((string)$group->name === $name) {
                return $group;
            }
        }
        return null;
    }

    /** Members of a group as a list of uids. */
    public static function members(\SimpleXMLElement $root, string $name): array
    {
        $group = self::group($root, $name);
        if ($group === null) {
            return [];
        }
        $out = [];
        foreach ($group->member as $member) {
            $out = array_merge($out, array_filter(explode(',', (string)$member)));
        }
        return array_values($out);
    }
}
