<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * A login has to be something the user's browser is actually navigating to.
 *
 * The login endpoints are plain GET URLs by construction -- a button on the login page,
 * a redirect from a reverse proxy, the WEB_AUTH link an OpenVPN client opens -- so any
 * page a user visits can also fire them from an <img> tag or a fetch(). For JWT
 * forward-auth that is a login CSRF outright: the proxy adds the header to whatever
 * request goes through it, so a third-party page can silently open a firewall session
 * in the victim's browser. For OIDC and SAML it merely burns a ceremony, but neither is
 * something a login should tolerate.
 *
 * Sec-Fetch-Dest is set by the browser, not by the page, and says what the request is
 * for: "document" is a top-level navigation, anything else is a subresource. A request
 * that does not carry it at all (an old browser, a client that is not one) is left
 * alone -- this closes a hole, it does not become the authentication.
 */
final class NavigationGuard
{
    /**
     * @throws \RuntimeException when the browser says this is not a navigation
     */
    public static function assertNavigation(): void
    {
        $dest = strtolower(trim((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? '')));
        if ($dest === '' || $dest === 'document') {
            return;
        }
        throw new \RuntimeException(sprintf(
            'refusing a login that is not a top-level navigation (Sec-Fetch-Dest: %s)',
            preg_replace('/[^a-z-]/', '', $dest) ?: 'unreadable'
        ));
    }
}
