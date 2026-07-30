<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Where a provider may be used: the WebGUI, the captive portal, the VPN.
 *
 * Without this every configured OIDC or SAML server is all three at once. A provider
 * added for guest wifi puts a button on the firewall's own login page, and a provider
 * meant for the VPN does the same -- so an operator who left "Required groups" empty
 * because the captive portal zone does its own group enforcement has, without being
 * told, opened the WebGUI to every account the directory will authenticate.
 *
 * Empty means all three, which is what every provider configured before this existed
 * gets: an upgrade must not silently take a login away.
 */
final class ServiceScope
{
    public const WEBGUI = 'webgui';
    public const PORTAL = 'portal';
    public const VPN = 'vpn';

    public const SERVICES = [self::WEBGUI, self::PORTAL, self::VPN];

    /**
     * The services named in an operator's comma-separated list.
     *
     * @return string[] the recognised ones, or [] for "no restriction". A list that
     *         names nothing we know of also reads as [] rather than as "nowhere": a
     *         typo must not lock everybody out of a working provider silently -- the
     *         form validation is where a bad value is reported.
     */
    public static function parse(string $spec): array
    {
        $out = [];
        foreach (preg_split('/[\s,]+/', strtolower(trim($spec))) ?: [] as $service) {
            if (in_array($service, self::SERVICES, true) && !in_array($service, $out, true)) {
                $out[] = $service;
            }
        }
        return $out;
    }

    /**
     * The entries of a list that name no service we know of -- what the form reports
     * rather than silently ignoring, since parse() is deliberately forgiving.
     *
     * @return string[]
     */
    public static function unknown(string $spec): array
    {
        $out = [];
        foreach (preg_split('/[\s,]+/', strtolower(trim($spec))) ?: [] as $service) {
            if ($service !== '' && !in_array($service, self::SERVICES, true)) {
                $out[] = $service;
            }
        }
        return $out;
    }

    /** @param string[]|string $configured the provider's list, parsed or raw */
    public static function allows($configured, string $service): bool
    {
        $services = is_array($configured) ? $configured : self::parse((string)$configured);
        return $services === [] || in_array($service, $services, true);
    }

    /**
     * @param string[]|string $configured
     * @throws \RuntimeException when this provider is not offered for $service
     */
    public static function assert($configured, string $service, string $provider = ''): void
    {
        if (!self::allows($configured, $service)) {
            throw new \RuntimeException(sprintf(
                "SSO: provider '%s' is not enabled for %s logins",
                preg_replace('/[^\x20-\x7e]/', '', $provider),
                $service
            ));
        }
    }
}
