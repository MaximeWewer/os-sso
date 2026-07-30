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
 * page a user visits can also fire them from an <img> tag or a fetch(). For OIDC and SAML
 * that merely burns a ceremony. For JWT forward-auth it is a login CSRF: the proxy adds
 * the header to whatever request goes through it, so a third-party page can open a
 * firewall session in the victim's browser without them asking for one.
 *
 * Worth keeping in proportion, though, because it decides how hard to lean on this: the
 * proxy is what mints the token, so the session that appears is the victim's OWN. An
 * attacker cannot choose whose it is, which is the whole payoff of a classic login CSRF
 * (log the victim into the attacker's account and watch what they do there). What is
 * left is an unasked-for session that idles out.
 *
 * Sec-Fetch-Dest is set by the browser, not by the page, and says what the request is
 * for: "document" is a top-level navigation, anything else is a subresource. A request
 * that does not carry it at all is left alone -- this closes a hole, it does not become
 * the authentication.
 *
 * That last branch is load-bearing, and not (only) for old browsers: nothing that is not
 * a browser sends the header, which includes the end-to-end suite -- test/e2e drives
 * these endpoints with curl and python-requests throughout. Requiring the header would
 * take the whole suite down with it, and would break any reverse proxy that strips the
 * headers it does not recognise, for a threat bounded as above. Leave it.
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
