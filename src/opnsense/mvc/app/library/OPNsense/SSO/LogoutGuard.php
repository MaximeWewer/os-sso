<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

/**
 * Keeps a third-party page from logging our users out.
 *
 * The logout endpoints are plain GET links (the WebGUI Lobby menu item points at one,
 * and core's own logout works the same way), so any site the user visits could fire
 * them with an <img> tag. The damage is bounded -- it ends a session, it does not
 * steal one -- but for SAML it also bounces the browser to the IdP's logout, so it is
 * worth closing.
 *
 * Rather than break the menu link by demanding POST everywhere, a logout goes through
 * when the browser tells us the request is same-origin (Sec-Fetch-Site, which every
 * current browser sends, with Referer as the fallback). When it cannot be shown to be
 * same-origin, we do not refuse either: we render a one-click confirmation page whose
 * form POSTs back with a per-session token. Cross-site triggering then needs the
 * user's own click, which is no longer CSRF.
 */
final class LogoutGuard
{
    private const TOKEN_KEY = 'sso_logout_token';

    /**
     * May this request perform the logout, or should the caller render confirm()?
     * Call with the native session already started.
     */
    public static function allow(): bool
    {
        if (self::isConfirmedPost()) {
            return true;
        }
        // Sec-Fetch-Site is set by the browser, not by the page: "none" is a typed URL
        // or a bookmark, "same-origin" is our own UI. Anything else is another site.
        $site = strtolower((string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? ''));
        if ($site !== '') {
            return $site === 'same-origin' || $site === 'none';
        }
        // Older browser: fall back to the Referer host.
        $referer = (string)($_SERVER['HTTP_REFERER'] ?? '');
        if ($referer !== '') {
            $host = (string)(parse_url($referer, PHP_URL_HOST) ?? '');
            $self = explode(':', (string)($_SERVER['HTTP_HOST'] ?? ''))[0];
            return $host !== '' && $self !== '' && strcasecmp($host, $self) === 0;
        }
        return false; // cannot prove same-origin: ask the user
    }

    /** True when this is the POST from our own confirmation page. */
    private static function isConfirmedPost(): bool
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            return false;
        }
        $expected = (string)($_SESSION[self::TOKEN_KEY] ?? '');
        $given = (string)($_POST['logout_token'] ?? '');
        return $expected !== '' && hash_equals($expected, $given);
    }

    /**
     * One-click confirmation page posting back to $action with a session token.
     * Mints the token into the session, so the caller must not close it beforehand.
     */
    public static function confirm(string $action): string
    {
        $token = bin2hex(random_bytes(16));
        $_SESSION[self::TOKEN_KEY] = $token;
        $a = htmlspecialchars($action, ENT_QUOTES);
        $t = htmlspecialchars($token, ENT_QUOTES);
        return "<!doctype html><html><head><meta charset='utf-8'><title>Sign out</title>"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em}"
            . "button{font-size:15px;padding:8px 22px;cursor:pointer}</style>"
            . "</head><body><h2>Sign out?</h2>"
            . "<p>Confirm that you want to end your session.</p>"
            . "<form method='post' action='{$a}'>"
            . "<input type='hidden' name='logout_token' value='{$t}'>"
            . "<button type='submit'>Sign out</button></form>"
            . "</body></html>";
    }
}
