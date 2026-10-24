<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;

/**
 * What os-sso knows about a local account, kept out of the account itself.
 *
 * These used to be extra children of <system><user>: the ownership marker, the IdP
 * bindings, the SCIM references and timestamps, the deprovisioning flag and the
 * provenance of granted groups. But users are a core MVC model, and saving ANY user
 * through it -- creating an unrelated one in System > Access > Users is enough --
 * rewrites every <user> from the model's own fields and drops ours (issue #13). The
 * account then reads as a local one nobody owns, and an SSO login on an admin is
 * refused as a bind to a privileged account.
 *
 * So they live under //OPNsense/SSO/accounts/account[@uid], outside the mount of
 * os-sso's own Settings model (//OPNsense/SSO/settings), where no model rewrites them,
 * and within the section the HA sync carries. Keyed by uid: core never changes it and
 * never hands a deleted account's uid to a new one.
 *
 * Reads still merge what an account carries the old way, so a configuration nothing
 * has rewritten yet keeps working before migration 1.0.6 moves it; writes clear the
 * old copy, so a stale one can never come back through that merge.
 */
final class AccountStamps
{
    public const FIELDS = [
        'sso_owned',
        'sso_subject',
        'scim_ref',
        'scim_provider',
        'scim_created',
        'scim_modified',
        'sso_deprovisioned',
        'sso_groups',
    ];

    public static function isStamp(string $field): bool
    {
        return in_array($field, self::FIELDS, true);
    }

    /**
     * Every non-empty value of a stamp, in order, without duplicates.
     *
     * @return string[]
     */
    public static function values(\SimpleXMLElement $user, string $field): array
    {
        $out = [];
        $record = self::record($user, false);
        $sources = $record !== null ? [$record->{$field}, $user->{$field}] : [$user->{$field}];
        foreach ($sources as $nodes) {
            foreach ($nodes as $node) {
                $value = trim((string)$node);
                if ($value !== '' && !in_array($value, $out, true)) {
                    $out[] = $value;
                }
            }
        }
        return $out;
    }

    /** The first value of a stamp, '' when it has none. */
    public static function value(\SimpleXMLElement $user, string $field): string
    {
        return self::values($user, $field)[0] ?? '';
    }

    /** Append one value (repeatable stamps: sso_subject). */
    public static function add(\SimpleXMLElement $user, string $field, string $value): void
    {
        $value = trim(LocalAccountWriter::xmlText($value));
        if ($value === '' || in_array($value, self::values($user, $field), true)) {
            return;
        }
        $record = self::record($user, true);
        if ($record === null) {
            $user->addChild($field, self::xml($value)); // no uid: nowhere else to put it
            return;
        }
        self::moveLegacy($user, $record, $field);
        $record->addChild($field, self::xml($value));
    }

    /**
     * Replace a stamp with one value; '' removes it.
     *
     * @return bool whether anything changed
     */
    public static function set(\SimpleXMLElement $user, string $field, string $value): bool
    {
        $value = trim(LocalAccountWriter::xmlText($value));
        if (self::values($user, $field) === ($value === '' ? [] : [$value])) {
            return false;
        }
        unset($user->{$field});
        $record = self::record($user, $value !== '');
        if ($record === null) {
            if ($value !== '') {
                $user->addChild($field, self::xml($value));
            }
            return true;
        }
        unset($record->{$field});
        if ($value !== '') {
            $record->addChild($field, self::xml($value));
        }
        return true;
    }

    /**
     * Move whatever stamps an account still carries the old way into its record.
     *
     * @return bool whether anything moved
     */
    public static function adopt(\SimpleXMLElement $user): bool
    {
        $moved = false;
        foreach (self::FIELDS as $field) {
            if (count($user->{$field}) === 0) {
                continue;
            }
            $record = self::record($user, true);
            if ($record === null) {
                return $moved;
            }
            $moved = self::moveLegacy($user, $record, $field) || $moved;
        }
        return $moved;
    }

    /** The stamps that say who an account is; recover() brings back only these. */
    private const IDENTITY = ['sso_owned', 'sso_subject', 'scim_ref', 'scim_provider', 'scim_created'];

    /**
     * Bring back the identity stamps core already erased, from config.xml backups.
     *
     * Before AccountStamps, every save of the core user model dropped them, so an
     * account os-sso made can be sitting there unowned and unbound (issue #13). The
     * backups taken before that save still have them. An account is recovered only if
     * it is still the same account -- same uid AND same name in the backup -- carries
     * no identity stamp today, and still has no usable local password, i.e. is still
     * the IdP-only account os-sso made. Group provenance and the deprovisioning flag
     * are left out on purpose: they describe a past state, and bringing them back could
     * revoke or re-enable something on the strength of it.
     *
     * @param string[] $backups config.xml backup files, newest first
     * @return string[] names of the accounts recovered
     */
    public static function recover(array $backups): array
    {
        $accounts = new LocalAccountWriter();
        $wanted = [];
        foreach (Config::getInstance()->object()->system->user ?? [] as $user) {
            $uid = trim((string)$user->uid);
            if ($uid === '' || $accounts->hasUsableLocalPassword($user)) {
                continue;
            }
            foreach (self::IDENTITY as $field) {
                if (self::values($user, $field) !== []) {
                    continue 2;
                }
            }
            $wanted[$uid] = $user;
        }

        $recovered = [];
        foreach ($backups as $file) {
            if ($wanted === []) {
                break;
            }
            $backup = @simplexml_load_file($file); // @ - a damaged backup is just skipped
            if ($backup === false) {
                continue;
            }
            foreach ($backup->system->user ?? [] as $old) {
                $uid = trim((string)$old->uid);
                if (!isset($wanted[$uid]) || (string)$old->name !== (string)$wanted[$uid]->name) {
                    continue;
                }
                $record = null;
                if (isset($backup->OPNsense->SSO->accounts)) {
                    foreach ($backup->OPNsense->SSO->accounts->account as $account) {
                        if ((string)$account['uid'] === $uid) {
                            $record = $account;
                        }
                    }
                }
                $found = false;
                foreach (self::IDENTITY as $field) {
                    foreach ([$record?->{$field} ?? [], $old->{$field}] as $nodes) {
                        foreach ($nodes as $node) {
                            if (trim((string)$node) !== '') {
                                self::add($wanted[$uid], $field, trim((string)$node));
                                $found = true;
                            }
                        }
                    }
                }
                if ($found) {
                    $recovered[] = (string)$wanted[$uid]->name;
                    unset($wanted[$uid]);
                }
            }
        }
        return $recovered;
    }

    /**
     * Drop the records of accounts that no longer exist.
     *
     * @return int records removed
     */
    public static function prune(): int
    {
        $cfg = Config::getInstance()->object();
        $uids = [];
        foreach ($cfg->system->user ?? [] as $user) {
            $uids[(string)$user->uid] = true;
        }
        if (!isset($cfg->OPNsense->SSO->accounts)) {
            return 0;
        }
        $accounts = $cfg->OPNsense->SSO->accounts;
        $removed = 0;
        for ($i = count($accounts->account) - 1; $i >= 0; $i--) {
            if (!isset($uids[(string)$accounts->account[$i]['uid']])) {
                unset($accounts->account[$i]);
                $removed++;
            }
        }
        return $removed;
    }

    /** Copy the old children of one field into the record, then drop them. */
    private static function moveLegacy(\SimpleXMLElement $user, \SimpleXMLElement $record, string $field): bool
    {
        if (count($user->{$field}) === 0) {
            return false;
        }
        $present = [];
        foreach ($record->{$field} as $node) {
            $present[] = trim((string)$node);
        }
        foreach ($user->{$field} as $node) {
            $value = trim((string)$node);
            if ($value !== '' && !in_array($value, $present, true)) {
                $record->addChild($field, self::xml($value));
                $present[] = $value;
            }
        }
        unset($user->{$field});
        return true;
    }

    /** This account's record, created on demand; null when the account has no uid. */
    private static function record(\SimpleXMLElement $user, bool $create): ?\SimpleXMLElement
    {
        $uid = trim((string)($user->uid ?? ''));
        if ($uid === '' || !ctype_digit($uid)) {
            return null;
        }
        // isset(), not ??: SimpleXML hands back an empty element, never null, for a
        // child that does not exist.
        $cfg = Config::getInstance()->object();
        if (isset($cfg->OPNsense->SSO->accounts)) {
            foreach ($cfg->OPNsense->SSO->accounts->account as $account) {
                if ((string)$account['uid'] === $uid) {
                    return $account;
                }
            }
        }
        if (!$create) {
            return null;
        }
        $opnsense = isset($cfg->OPNsense) ? $cfg->OPNsense : $cfg->addChild('OPNsense');
        $sso = isset($opnsense->SSO) ? $opnsense->SSO : $opnsense->addChild('SSO');
        $accounts = isset($sso->accounts) ? $sso->accounts : $sso->addChild('accounts');
        $account = $accounts->addChild('account');
        $account->addAttribute('uid', $uid);
        return $account;
    }

    /** Escaped for addChild(), with what XML cannot hold already dropped. */
    private static function xml(string $value): string
    {
        return htmlspecialchars(LocalAccountWriter::xmlText($value), ENT_XML1);
    }
}
