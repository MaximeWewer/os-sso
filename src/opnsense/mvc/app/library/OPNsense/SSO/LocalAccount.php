<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * One answer to "may this local account be used at all", shared by everything that
 * acts on a config.xml user node.
 *
 * The operator's <disabled> flag and <expires> date are a local decision that SSO
 * must not route around: core's Local::_authenticate() refuses both on the password
 * path, so the IdP path refuses them too. It is asked EARLY -- before group sync
 * writes config.xml, before a VPN tunnel is approved, before a session is opened --
 * so a disabled account is never granted anything on the way to being refused.
 */
final class LocalAccount
{
    /** Enabled, and not past its expiry date. */
    public static function isUsable(\SimpleXMLElement $node): bool
    {
        if (!empty((string)($node->disabled ?? ''))) {
            return false;
        }
        // Same m/d/Y parse and one-day grace as core Local::_authenticate(); an
        // SSO-managed account normally carries no <expires> at all.
        if (
            !empty($node->expires)
            && strtotime('-1 day') > strtotime(date('m/d/Y', strtotime((string)$node->expires)))
        ) {
            return false;
        }
        return true;
    }

    /** @throws \RuntimeException when the account is disabled or expired */
    public static function assertUsable(\SimpleXMLElement $node): void
    {
        if (!self::isUsable($node)) {
            throw new \RuntimeException(sprintf(
                "SSO: local account '%s' is disabled or expired",
                (string)$node->name
            ));
        }
    }
}
