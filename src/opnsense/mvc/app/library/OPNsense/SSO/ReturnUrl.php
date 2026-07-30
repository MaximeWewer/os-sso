<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * The one place that decides where a login is allowed to land.
 *
 * Every SSO flow carries a "where was I going" value that ends up in a redirect, and it
 * all arrives from outside: a query parameter on the login link, the RelayState of a SAML
 * round-trip, a provider's configured landing path. That makes each of them an open
 * redirect (CWE-601) waiting to happen, which is why five copies of this rule existed --
 * and why they should not: a divergence between them is a hole in whichever flow got left
 * behind.
 */
final class ReturnUrl
{
    /**
     * A same-site relative path, or '/'.
     *
     * Refuses, in order:
     *   - anything not starting with '/', i.e. every absolute URL and every scheme;
     *   - '//host', which is protocol-relative and goes off-site;
     *   - '/\host', because browsers fold '\' to '/' and it resolves the same way;
     *   - CR, LF and TAB, which is header splitting once this reaches a Location.
     */
    public static function sanitize(string $url): string
    {
        if (
            $url === '' || $url[0] !== '/'
            || str_starts_with($url, '//') || str_starts_with($url, '/\\')
            || strpbrk($url, "\\\r\n\t") !== false
        ) {
            return '/';
        }
        return $url;
    }

    /**
     * Where a successful WebGUI login lands: the page originally requested if there was
     * one, otherwise the provider's configured default, otherwise the dashboard.
     */
    public static function landing(string $requested, string $configuredDefault): string
    {
        $requested = self::sanitize($requested);
        return $requested !== '/' ? $requested : self::sanitize(trim($configuredDefault));
    }
}
